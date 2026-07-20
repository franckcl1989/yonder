#!/usr/bin/env bash
set -euo pipefail

yon="${1:?path to the yon executable is required}"
relay="${2:?path to the yon-relay executable is required}"

yon="$(realpath "$yon")"
relay="$(realpath "$relay")"
test -x "$yon"
test -x "$relay"
test "$(id -u)" -eq 0

for command in date ip iptables grep sed timeout; do
  command -v "$command" >/dev/null
done

readonly tag="ym${$}"
readonly root="$(mktemp -d /tmp/yonder-network-matrix.XXXXXX)"
declare -a namespaces=()
declare -a bridges=()
declare -a processes=()

cleanup_processes() {
  local pid
  for pid in "${processes[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${processes[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  processes=()
}

cleanup_topology() {
  local namespace bridge
  cleanup_processes
  for namespace in "${namespaces[@]}"; do
    ip netns delete "$namespace" 2>/dev/null || true
  done
  for bridge in "${bridges[@]}"; do
    ip link delete "$bridge" 2>/dev/null || true
  done
  namespaces=()
  bridges=()
}

cleanup() {
  cleanup_topology
  rm -rf -- "$root"
}
trap cleanup EXIT INT TERM

new_namespace() {
  local namespace="$1"
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
  namespaces+=("$namespace")
}

new_bridge() {
  local bridge="$1"
  ip link add "$bridge" type bridge
  ip link set "$bridge" up
  bridges+=("$bridge")
}

attach_ipv4() {
  local namespace="$1" bridge="$2" root_interface="$3" address="$4"
  local peer_interface="${root_interface}p"
  ip link add "$root_interface" type veth peer name "$peer_interface"
  ip link set "$peer_interface" netns "$namespace"
  ip -n "$namespace" link set "$peer_interface" name eth0
  ip link set "$root_interface" master "$bridge"
  ip link set "$root_interface" up
  ip -n "$namespace" addr add "$address" dev eth0
  ip -n "$namespace" link set eth0 up
}

attach_ipv6() {
  local namespace="$1" bridge="$2" root_interface="$3" address="$4"
  local peer_interface="${root_interface}p"
  ip link add "$root_interface" type veth peer name "$peer_interface"
  ip link set "$peer_interface" netns "$namespace"
  ip -n "$namespace" link set "$peer_interface" name eth0
  ip link set "$root_interface" master "$bridge"
  ip link set "$root_interface" up
  ip netns exec "$namespace" sysctl -q -w net.ipv6.conf.all.disable_ipv6=0
  ip netns exec "$namespace" sysctl -q -w net.ipv6.conf.default.disable_ipv6=0
  ip -n "$namespace" addr add "$address" dev eth0 nodad
  ip -n "$namespace" link set eth0 up
}

connect_private_ipv4() {
  local endpoint_namespace="$1" nat_namespace="$2" prefix="$3"
  local endpoint_address="$4" gateway_address="$5" gateway="$6"
  local endpoint_interface="${prefix}e" nat_interface="${prefix}n"
  ip link add "$endpoint_interface" type veth peer name "$nat_interface"
  ip link set "$endpoint_interface" netns "$endpoint_namespace"
  ip link set "$nat_interface" netns "$nat_namespace"
  ip -n "$endpoint_namespace" link set "$endpoint_interface" name eth0
  ip -n "$nat_namespace" link set "$nat_interface" name lan0
  ip -n "$endpoint_namespace" addr add "$endpoint_address" dev eth0
  ip -n "$nat_namespace" addr add "$gateway_address" dev lan0
  ip -n "$endpoint_namespace" link set eth0 up
  ip -n "$nat_namespace" link set lan0 up
  ip -n "$endpoint_namespace" route add default via "$gateway"
}

configure_nat() {
  local namespace="$1" private_cidr="$2"
  ip netns exec "$namespace" sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec "$namespace" iptables -w -F
  ip netns exec "$namespace" iptables -w -t nat -F
  ip netns exec "$namespace" iptables -w -P FORWARD DROP
  ip netns exec "$namespace" iptables -w -A FORWARD \
    -i lan0 -o wan0 -j ACCEPT
  ip netns exec "$namespace" iptables -w -A FORWARD \
    -i wan0 -o lan0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip netns exec "$namespace" iptables -w -t nat -A POSTROUTING \
    -s "$private_cidr" -o wan0 -j MASQUERADE --random-fully
}

rename_nat_wan() {
  local namespace="$1"
  ip -n "$namespace" link set eth0 down
  ip -n "$namespace" link set eth0 name wan0
  ip -n "$namespace" link set wan0 up
}

wait_for_code() {
  local output="$1" deadline=$((SECONDS + 90)) code
  while ((SECONDS < deadline)); do
    code="$(
      grep -a -m1 -E \
        '^Connection code: [0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$' \
        "$output" | sed 's/^Connection code: //' || true
    )"
    if [[ -n "$code" ]]; then
      printf '%s\n' "$code"
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_process() {
  local pid="$1" seconds="$2" deadline
  deadline=$((SECONDS + seconds))
  while kill -0 "$pid" 2>/dev/null; do
    if ((SECONDS >= deadline)); then
      return 1
    fi
    sleep 1
  done
}

run_session() {
  local case_name="$1" relay_namespace="$2" host_namespace="$3"
  local controller_namespace="$4" relay_ip="$5" family="$6" port="$7"
  local max_controller_ms="$8"
  local case_root="$root/$case_name" peer_output peer code host_pid controller_status
  local controller_started controller_elapsed
  mkdir -m 700 "$case_root" "$case_root/relay" "$case_root/endpoint"

  peer_output="$($relay identity init --output "$case_root/relay/relay.key")"
  peer="${peer_output#Relay PeerId: }"
  test -n "$peer"
  test "$peer" != "$peer_output"

  cat >"$case_root/relay/yon-relay.toml" <<EOF
identity = "relay.key"
listen = [
  "/${family}/0.0.0.0/tcp/${port}",
  "/${family}/0.0.0.0/udp/${port}/quic-v1",
]
external = [
  "/${family}/${relay_ip}/tcp/${port}",
  "/${family}/${relay_ip}/udp/${port}/quic-v1",
]
EOF
  if [[ "$family" == ip6 ]]; then
    sed -i 's#/ip6/0\.0\.0\.0/#/ip6/::/#g' "$case_root/relay/yon-relay.toml"
  fi

  cat >"$case_root/endpoint/yon.toml" <<EOF
relays = [
  "/${family}/${relay_ip}/tcp/${port}/p2p/${peer}",
  "/${family}/${relay_ip}/udp/${port}/quic-v1/p2p/${peer}",
]
EOF

  (
    cd "$case_root/relay"
    exec ip netns exec "$relay_namespace" "$relay" --log-level debug serve
  ) >"$case_root/relay.stdout" 2>"$case_root/relay.stderr" &
  processes+=("$!")

  local relay_deadline=$((SECONDS + 30))
  while ! grep -a -q "/p2p/${peer}" "$case_root/relay.stdout"; do
    if ((SECONDS >= relay_deadline)); then
      printf 'relay failed to publish its address in case %s\n' "$case_name" >&2
      tail -n 40 "$case_root/relay.stderr" >&2 || true
      return 1
    fi
    sleep 1
  done

  (
    cd "$case_root/endpoint"
    exec ip netns exec "$host_namespace" "$yon" --log-level debug host
  ) >"$case_root/host.stdout" 2>"$case_root/host.stderr" &
  host_pid="$!"
  processes+=("$host_pid")

  if ! code="$(wait_for_code "$case_root/host.stdout")"; then
    printf 'host failed to publish a connection code in case %s\n' "$case_name" >&2
    tail -n 60 "$case_root/host.stderr" >&2 || true
    return 1
  fi

  set +e
  controller_started="$(date +%s%3N)"
  {
    printf '%s\n' "$code"
    printf '\033[1;1R\r\necho YONDER_MATRIX_%s\r\nexit\r\n' "$case_name"
  } | (
    cd "$case_root/endpoint"
    exec timeout 180 ip netns exec "$controller_namespace" \
      "$yon" --log-level debug connect
  ) >"$case_root/controller.stdout" 2>"$case_root/controller.stderr"
  controller_status="$?"
  controller_elapsed="$(($(date +%s%3N) - controller_started))"
  set -e

  if [[ "$controller_status" -ne 0 ]]; then
    printf 'controller failed with %s in case %s\n' "$controller_status" "$case_name" >&2
    tail -n 80 "$case_root/controller.stderr" >&2 || true
    return 1
  fi
  if ((controller_elapsed > max_controller_ms)); then
    printf 'controller exceeded %sms with %sms in case %s\n' \
      "$max_controller_ms" "$controller_elapsed" "$case_name" >&2
    return 1
  fi
  if ! grep -a -q "YONDER_MATRIX_${case_name}" "$case_root/controller.stdout"; then
    printf 'controller output missed the marker in case %s\n' "$case_name" >&2
    return 1
  fi
  if ! wait_for_process "$host_pid" 30; then
    printf 'host did not exit after the terminal session in case %s\n' "$case_name" >&2
    return 1
  fi
  if ! wait "$host_pid"; then
    printf 'host exited unsuccessfully in case %s\n' "$case_name" >&2
    return 1
  fi

  printf 'PASS %s controller_ms=%s\n' "$case_name" "$controller_elapsed"
}

run_public_ipv4() {
  local case_name=public-ipv4 case_id=1
  local bridge="b${tag}${case_id}" relay_ns="${tag}-${case_id}-relay"
  local host_ns="${tag}-${case_id}-host" controller_ns="${tag}-${case_id}-controller"
  new_bridge "$bridge"
  new_namespace "$relay_ns"
  new_namespace "$host_ns"
  new_namespace "$controller_ns"
  attach_ipv4 "$relay_ns" "$bridge" "v${tag}${case_id}r" 10.240.1.2/24
  attach_ipv4 "$host_ns" "$bridge" "v${tag}${case_id}h" 10.240.1.3/24
  attach_ipv4 "$controller_ns" "$bridge" "v${tag}${case_id}c" 10.240.1.4/24
  run_session "$case_name" "$relay_ns" "$host_ns" "$controller_ns" \
    10.240.1.2 ip4 4401 20000
  cleanup_topology
}

run_single_nat_ipv4() {
  local case_name=single-nat-ipv4 case_id=2
  local bridge="b${tag}${case_id}" relay_ns="${tag}-${case_id}-relay"
  local host_ns="${tag}-${case_id}-host" controller_ns="${tag}-${case_id}-controller"
  local nat_ns="${tag}-${case_id}-nat"
  new_bridge "$bridge"
  new_namespace "$relay_ns"
  new_namespace "$controller_ns"
  new_namespace "$host_ns"
  new_namespace "$nat_ns"
  attach_ipv4 "$relay_ns" "$bridge" "v${tag}${case_id}r" 10.240.2.2/24
  attach_ipv4 "$controller_ns" "$bridge" "v${tag}${case_id}c" 10.240.2.3/24
  attach_ipv4 "$nat_ns" "$bridge" "v${tag}${case_id}n" 10.240.2.254/24
  rename_nat_wan "$nat_ns"
  connect_private_ipv4 "$host_ns" "$nat_ns" "p${tag}${case_id}" \
    10.241.2.2/24 10.241.2.1/24 10.241.2.1
  configure_nat "$nat_ns" 10.241.2.0/24
  run_session "$case_name" "$relay_ns" "$host_ns" "$controller_ns" \
    10.240.2.2 ip4 4402 20000
  cleanup_topology
}

run_strict_dual_nat_ipv4() {
  local case_name=strict-dual-nat-ipv4 case_id=3
  local bridge="b${tag}${case_id}" relay_ns="${tag}-${case_id}-relay"
  local host_ns="${tag}-${case_id}-host" controller_ns="${tag}-${case_id}-controller"
  local host_nat="${tag}-${case_id}-host-nat" controller_nat="${tag}-${case_id}-controller-nat"
  new_bridge "$bridge"
  new_namespace "$relay_ns"
  new_namespace "$host_ns"
  new_namespace "$controller_ns"
  new_namespace "$host_nat"
  new_namespace "$controller_nat"
  attach_ipv4 "$relay_ns" "$bridge" "v${tag}${case_id}r" 10.240.3.2/24
  attach_ipv4 "$host_nat" "$bridge" "v${tag}${case_id}h" 10.240.3.101/24
  attach_ipv4 "$controller_nat" "$bridge" "v${tag}${case_id}c" 10.240.3.102/24
  rename_nat_wan "$host_nat"
  rename_nat_wan "$controller_nat"
  connect_private_ipv4 "$host_ns" "$host_nat" "h${tag}${case_id}" \
    10.241.3.2/24 10.241.3.1/24 10.241.3.1
  connect_private_ipv4 "$controller_ns" "$controller_nat" "c${tag}${case_id}" \
    10.242.3.2/24 10.242.3.1/24 10.242.3.1
  configure_nat "$host_nat" 10.241.3.0/24
  configure_nat "$controller_nat" 10.242.3.0/24
  run_session "$case_name" "$relay_ns" "$host_ns" "$controller_ns" \
    10.240.3.2 ip4 4403 20000
  cleanup_topology
}

run_ipv6_only() {
  local case_name=ipv6-only case_id=4
  local bridge="b${tag}${case_id}" relay_ns="${tag}-${case_id}-relay"
  local host_ns="${tag}-${case_id}-host" controller_ns="${tag}-${case_id}-controller"
  new_bridge "$bridge"
  new_namespace "$relay_ns"
  new_namespace "$host_ns"
  new_namespace "$controller_ns"
  attach_ipv6 "$relay_ns" "$bridge" "v${tag}${case_id}r" fd70:240:4::2/64
  attach_ipv6 "$host_ns" "$bridge" "v${tag}${case_id}h" fd70:240:4::3/64
  attach_ipv6 "$controller_ns" "$bridge" "v${tag}${case_id}c" fd70:240:4::4/64
  run_session "$case_name" "$relay_ns" "$host_ns" "$controller_ns" \
    fd70:240:4::2 ip6 4404 20000
  cleanup_topology
}

run_public_ipv4
run_single_nat_ipv4
run_strict_dual_nat_ipv4
run_ipv6_only
printf 'PASS all network namespace cases\n'
