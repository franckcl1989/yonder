#![forbid(unsafe_code)]

use std::hint::black_box;
use std::path::Path;
use std::time::{Duration, Instant};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ed25519_dalek::{Signer, SigningKey};
use yon::audit::session::{AuditError, AuditSession, ConnectionSecret, Ledger, PersistentIdentity};
use yon::audit::writer::AuditWriter;
use yon::file_semantics::{
    FileTransferBackend, SealedTransferTempFile, TokioFileTransferBackend, TransferSource,
    TransferTempFile,
};
use yon::pake::OpaquePake;
use yon::terminal::TerminalChunk;
use yonder_core::random::{RandomError, SecureRandom};
use yonder_core::wire::audit::{
    AUDIT_FORMAT_VERSION, AuditNonce, AuditRole, AuthMode, BindingDigest, ChainHead,
    CommitmentDigest, DIGEST_LEN, Digest32, Ed25519PublicKey, Ed25519Signature,
    IdentityFingerprint, JointManifest, LedgerCommit, LedgerRoot, LocalRecordSeal, ManifestEnding,
    ManifestSignature, SessionId, SessionResult, SharedSnapshot, StreamSnapshot,
};
use yonder_core::wire::audit_container::AuditContainerHeader;
use yonder_core::wire::file_transfer::Sha256Digest;
use yonder_core::{Pake, PakeSecret, PeerIdBytes};

const FILE_BLOCK_LEN: usize = 64 * 1024;
const CONNECTION_SECRET: &[u8] = b"authenticated-benchmark-connection-secret";
const ZERO_HEAD: ChainHead = ChainHead::new([0; DIGEST_LEN]);
const ZERO_ROOT: LedgerRoot = LedgerRoot::new([0; DIGEST_LEN]);

fn opaque_round_trip(criterion: &mut Criterion) {
    let peer = PeerIdBytes::new(b"benchmark-target-peer").expect("valid peer id bytes");
    let secret = PakeSecret::from_u64(0x0123_4567_89AB_CDEF).expect("valid PAKE secret");
    let mut opaque = OpaquePake;
    let registration = opaque
        .register(&peer, &secret)
        .expect("registration succeeds");

    criterion.bench_function("opaque/login_round_trip", |bencher| {
        bencher.iter(|| {
            let (client, ke1) = opaque
                .client_start(&peer, &secret)
                .expect("client start succeeds");
            let (server, ke2) = opaque
                .server_start(&registration, &ke1, b"benchmark-context")
                .expect("server start succeeds");
            let (ke3, client_key) = opaque
                .client_finish(client, &ke2, b"benchmark-context")
                .expect("client finish succeeds");
            let server_key = opaque
                .server_finish(server, &ke3)
                .expect("server finish succeeds");
            black_box((client_key, server_key));
        })
    });
}

fn fixed_terminal_buffer_copy(criterion: &mut Criterion) {
    let source = [0xA5_u8; 16 * 1024];

    criterion.bench_function("terminal/fixed_buffer_copy_16k", |bencher| {
        bencher.iter(|| black_box(copy_terminal_chunk(black_box(&source))));
    });
}

fn file_stream_hash_atomic_commit(criterion: &mut Criterion) {
    use sha2::{Digest, Sha256};

    let runtime = benchmark_runtime();
    let directory = tempfile::tempdir().expect("benchmark directory");
    let source_path = directory.path().join("source.bin");
    let source_bytes = [0xA5; FILE_BLOCK_LEN];
    std::fs::write(&source_path, source_bytes).expect("benchmark source write");
    let expected_digest = Sha256Digest::new(Sha256::digest(source_bytes).into());
    let mut sequence = 0_u64;
    let mut group = criterion.benchmark_group("file");
    group.throughput(Throughput::Bytes(FILE_BLOCK_LEN as u64));
    group.bench_function("async_stream_hash_atomic_commit_64k", |bencher| {
        bencher.iter_custom(|iterations| {
            let mut measured = Duration::ZERO;
            for _ in 0..iterations {
                sequence = sequence.wrapping_add(1);
                let final_path = directory.path().join(format!("received-{sequence}.bin"));
                let started = Instant::now();
                runtime.block_on(stream_hash_atomic_commit(
                    &source_path,
                    &final_path,
                    expected_digest,
                ));
                measured += started.elapsed();
                std::fs::remove_file(&final_path).expect("benchmark destination cleanup");
            }
            measured
        });
    });
    group.finish();
}

fn audit_writer_and_terminal_concurrency(criterion: &mut Criterion) {
    let runtime = benchmark_runtime();
    let directory = tempfile::tempdir().expect("benchmark directory");
    let (mut session, header) = active_controller_session(1);
    let writer = initialized_writer(&runtime, directory.path(), session.session_id(), &header);
    let payload = [0x5A; FILE_BLOCK_LEN];

    let mut group = criterion.benchmark_group("audit");
    group.throughput(Throughput::Bytes(FILE_BLOCK_LEN as u64));
    group.bench_function("append_batch_64k", |bencher| {
        bencher.iter(|| {
            let batch = session
                .record_input(black_box(&payload), sequence_time(&session))
                .expect("audit input batch");
            runtime
                .block_on(writer.append_batch(batch))
                .expect("audit batch append");
        });
    });
    group.finish();

    let (mut concurrent_session, concurrent_header) = active_controller_session(9);
    let concurrent_writer = initialized_writer(
        &runtime,
        directory.path(),
        concurrent_session.session_id(),
        &concurrent_header,
    );
    let terminal_source = [0xA5; 16 * 1024];
    criterion.bench_function("terminal/audit_concurrent_copy_16k", |bencher| {
        bencher.iter_custom(|iterations| {
            let mut concurrent_latency = Duration::ZERO;
            for _ in 0..iterations {
                let batch = concurrent_session
                    .record_input(&payload, sequence_time(&concurrent_session))
                    .expect("concurrent audit input batch");
                let started = Instant::now();
                let (append, ()) = runtime.block_on(async {
                    tokio::join!(concurrent_writer.append_batch(batch), async {
                        tokio::task::yield_now().await;
                        black_box(copy_terminal_chunk(black_box(&terminal_source)));
                    })
                });
                append.expect("concurrent audit batch append");
                concurrent_latency += started.elapsed();
            }
            concurrent_latency
        });
    });
}

fn audit_finalize(criterion: &mut Criterion) {
    let runtime = benchmark_runtime();
    let directory = tempfile::tempdir().expect("benchmark directory");
    let mut sequence = 0_u64;
    criterion.bench_function("audit/finalize_sync", |bencher| {
        bencher.iter_custom(|iterations| {
            let mut measured = Duration::ZERO;
            for _ in 0..iterations {
                sequence = sequence.wrapping_add(1);
                let session_id = benchmark_session_id(sequence);
                let header = benchmark_header(session_id);
                let writer =
                    initialized_writer(&runtime, directory.path(), Some(session_id), &header);
                let started = Instant::now();
                runtime.block_on(async {
                    writer
                        .write_manifest_and_signatures(
                            &benchmark_manifest(session_id),
                            &benchmark_signature(),
                            &benchmark_signature(),
                        )
                        .await
                        .expect("audit manifest write");
                    writer
                        .write_seal(&benchmark_seal(session_id))
                        .await
                        .expect("audit seal write");
                    writer
                        .write_ledger_commit(&benchmark_commit(session_id))
                        .await
                        .expect("audit commit and sync");
                });
                measured += started.elapsed();
            }
            measured
        });
    });
}

fn copy_terminal_chunk(source: &[u8; 16 * 1024]) -> TerminalChunk {
    let mut chunk = TerminalChunk::new();
    chunk.writable().copy_from_slice(source);
    chunk
        .set_len(source.len())
        .expect("benchmark payload matches the frozen chunk capacity");
    chunk
}

async fn stream_hash_atomic_commit(
    source_path: &Path,
    final_path: &Path,
    expected_digest: Sha256Digest,
) {
    let backend = TokioFileTransferBackend;
    let mut source = backend
        .open_source(source_path.to_path_buf())
        .await
        .expect("benchmark async source open");
    let mut destination = backend
        .create_temp(
            final_path
                .parent()
                .expect("benchmark destination parent")
                .to_path_buf(),
        )
        .await
        .expect("benchmark async temporary file");
    let mut buffer = [0_u8; FILE_BLOCK_LEN];
    loop {
        let read = source
            .read_block(&mut buffer)
            .await
            .expect("benchmark source read");
        if read == 0 {
            break;
        }
        destination
            .write_block_async(&buffer[..read])
            .await
            .expect("benchmark destination write");
    }
    source
        .recheck_source()
        .await
        .expect("benchmark source remains stable");
    assert_eq!(source.size(), FILE_BLOCK_LEN as u64);
    assert_eq!(source.bytes_read(), FILE_BLOCK_LEN as u64);
    let sealed = destination
        .finish_async()
        .await
        .expect("benchmark destination flush and sync");
    sealed
        .verify_finish(FILE_BLOCK_LEN as u64, expected_digest)
        .expect("benchmark sealed size and digest");
    sealed
        .commit_async(final_path.to_path_buf())
        .await
        .expect("benchmark atomic no-replace commit");
}

fn benchmark_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("benchmark runtime")
}

fn initialized_writer(
    runtime: &tokio::runtime::Runtime,
    directory: &Path,
    session_id: Option<SessionId>,
    header: &AuditContainerHeader,
) -> AuditWriter {
    let session_id = session_id.expect("active benchmark session ID");
    runtime.block_on(async {
        let records = directory.join("records");
        let writer = AuditWriter::open(&records, &session_id, AuditRole::Controller)
            .expect("benchmark audit writer");
        writer
            .initialize(header)
            .await
            .expect("benchmark audit header");
        writer
    })
}

fn sequence_time(session: &AuditSession) -> u64 {
    session.local_event_count().saturating_add(1)
}

struct SequentialRandom(u8);

impl SecureRandom for SequentialRandom {
    fn try_fill(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

struct BenchmarkIdentity(SigningKey);

impl BenchmarkIdentity {
    fn new(seed: u8) -> Self {
        Self(SigningKey::from_bytes(&[seed; 32]))
    }
}

impl PersistentIdentity for BenchmarkIdentity {
    fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey::new(self.0.verifying_key().to_bytes())
    }

    fn fingerprint(&self) -> IdentityFingerprint {
        use sha2::{Digest, Sha256};

        IdentityFingerprint::new(Sha256::digest(self.0.verifying_key().as_bytes()).into())
    }

    fn sign(&self, input: &[u8]) -> Result<Ed25519Signature, AuditError> {
        Ok(Ed25519Signature::new(self.0.sign(input).to_bytes()))
    }
}

struct BenchmarkLedger;

impl Ledger for BenchmarkLedger {
    fn snapshot(&self) -> Result<(u64, LedgerRoot), AuditError> {
        Ok((0, ZERO_ROOT))
    }

    fn begin_commit(&mut self) -> Result<(u64, LedgerRoot), AuditError> {
        Ok((1, ZERO_ROOT))
    }

    fn finish_commit(&mut self, _commit: &LedgerCommit) -> Result<(), AuditError> {
        Ok(())
    }
}

fn active_controller_session(seed: u8) -> (AuditSession, AuditContainerHeader) {
    let binding = BindingDigest::new([seed; DIGEST_LEN]);
    let mut controller = AuditSession::new(
        AuditRole::Controller,
        Box::new(BenchmarkIdentity::new(seed)),
        Box::new(BenchmarkLedger),
        binding,
        1_700_000_000,
        &mut SequentialRandom(seed),
    )
    .expect("controller audit session");
    let mut host = AuditSession::new(
        AuditRole::Host,
        Box::new(BenchmarkIdentity::new(seed.wrapping_add(1))),
        Box::new(BenchmarkLedger),
        binding,
        1_700_000_000,
        &mut SequentialRandom(seed.wrapping_add(100)),
    )
    .expect("host audit session");
    let controller_hello = *controller.local_hello();
    let controller_contribution = controller.local_contribution().clone();
    let host_hello = *host.local_hello();
    let host_contribution = host.local_contribution().clone();
    controller
        .receive_peer_hello(&host_hello, &host_contribution)
        .expect("controller receives host audit hello");
    host.receive_peer_hello(&controller_hello, &controller_contribution)
        .expect("host receives controller audit hello");
    let controller_ready = controller
        .compute_ready(ConnectionSecret::Authenticated(CONNECTION_SECRET))
        .expect("controller audit ready");
    let host_ready = host
        .compute_ready(ConnectionSecret::Authenticated(CONNECTION_SECRET))
        .expect("host audit ready");
    let header = controller
        .build_header(&controller_ready, Digest32::new([7; DIGEST_LEN]))
        .expect("controller audit header");
    controller
        .receive_peer_ready(&host_ready)
        .expect("controller verifies host ready");
    (controller, header)
}

fn benchmark_session_id(sequence: u64) -> SessionId {
    let mut bytes = [0x5A; DIGEST_LEN];
    bytes[..8].copy_from_slice(&sequence.to_be_bytes());
    SessionId::new(bytes)
}

fn benchmark_header(session_id: SessionId) -> AuditContainerHeader {
    AuditContainerHeader::new(
        AuditRole::Controller,
        session_id,
        Ed25519PublicKey::new([1; 32]),
        Ed25519PublicKey::new([2; 32]),
        Ed25519PublicKey::new([3; 32]),
        Ed25519PublicKey::new([4; 32]),
        7,
        ZERO_ROOT,
        1_700_000_000,
        AuthMode::Enterprise,
        Digest32::new([5; DIGEST_LEN]),
        yonder_core::wire::audit::AuditHello::new(
            AuditRole::Controller,
            Ed25519PublicKey::new([1; 32]),
            Ed25519PublicKey::new([2; 32]),
            AuditNonce::new([3; 32]),
            7,
            ZERO_ROOT,
            BindingDigest::new([4; DIGEST_LEN]),
            AUDIT_FORMAT_VERSION,
            CommitmentDigest::new([5; DIGEST_LEN]),
            Ed25519Signature::new([6; 64]),
        ),
        yonder_core::wire::audit::AuditReady::new(
            session_id,
            Digest32::new([2; DIGEST_LEN]),
            AUDIT_FORMAT_VERSION,
            Ed25519Signature::new([3; 64]),
        ),
    )
    .with_header_signature(Ed25519Signature::new([9; 64]))
}

fn benchmark_snapshot() -> SharedSnapshot {
    SharedSnapshot::new([
        StreamSnapshot::new(10, ZERO_HEAD),
        StreamSnapshot::new(20, ZERO_HEAD),
        StreamSnapshot::new(30, ZERO_HEAD),
        StreamSnapshot::new(40, ZERO_HEAD),
    ])
}

fn benchmark_manifest(session_id: SessionId) -> JointManifest {
    JointManifest::new(
        AUDIT_FORMAT_VERSION,
        session_id,
        IdentityFingerprint::new([2; DIGEST_LEN]),
        IdentityFingerprint::new([3; DIGEST_LEN]),
        Ed25519PublicKey::new([4; 32]),
        Ed25519PublicKey::new([5; 32]),
        BindingDigest::new([6; DIGEST_LEN]),
        Digest32::new([7; DIGEST_LEN]),
        benchmark_snapshot(),
        ManifestEnding::ShellExit(0),
        true,
        9,
    )
}

fn benchmark_signature() -> ManifestSignature {
    ManifestSignature::new(Ed25519Signature::new([6; 64]))
}

fn benchmark_seal(session_id: SessionId) -> LocalRecordSeal {
    LocalRecordSeal::new(
        session_id,
        AuditRole::Controller,
        ZERO_HEAD,
        12,
        [ZERO_HEAD; 4],
        Digest32::new([2; DIGEST_LEN]),
        Digest32::new([3; DIGEST_LEN]),
        Ed25519Signature::new([4; 64]),
    )
}

fn benchmark_commit(session_id: SessionId) -> LedgerCommit {
    LedgerCommit::new(
        13,
        ZERO_ROOT,
        session_id,
        Digest32::new([2; DIGEST_LEN]),
        Digest32::new([3; DIGEST_LEN]),
        IdentityFingerprint::new([4; DIGEST_LEN]),
        SessionResult::Normal,
        Ed25519Signature::new([5; 64]),
    )
}

criterion_group!(
    benches,
    opaque_round_trip,
    fixed_terminal_buffer_copy,
    file_stream_hash_atomic_commit,
    audit_writer_and_terminal_concurrency,
    audit_finalize
);
criterion_main!(benches);
