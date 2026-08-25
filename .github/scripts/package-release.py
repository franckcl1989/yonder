"""Create one-file release archives with normalized metadata."""

from __future__ import annotations

import argparse
import gzip
import shutil
import stat
import tarfile
import time
import zipfile
from pathlib import Path


EXECUTABLE_MODE = 0o755
ZIP_EPOCH = 315532800  # 1980-01-01T00:00:00Z, the first ZIP timestamp.


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("tar.gz", "zip"), required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    return parser.parse_args()


def validate(source: Path, output: Path, name: str, epoch: int) -> None:
    if not name or Path(name).name != name:
        raise ValueError("archive member name must be one basename")
    if source.is_symlink() or not source.is_file():
        raise ValueError("archive input must be one regular, non-symlink file")
    if output.exists():
        raise FileExistsError(f"refusing to replace existing archive: {output}")
    if epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must not be negative")


def write_tar_gz(source: Path, output: Path, name: str, epoch: int) -> None:
    with output.open("xb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=epoch
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
            ) as archive:
                info = tarfile.TarInfo(name)
                info.size = source.stat().st_size
                info.mode = EXECUTABLE_MODE
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = epoch
                with source.open("rb") as binary:
                    archive.addfile(info, binary)


def write_zip(source: Path, output: Path, name: str, epoch: int) -> None:
    timestamp = time.gmtime(max(epoch, ZIP_EPOCH))[:6]
    info = zipfile.ZipInfo(filename=name, date_time=timestamp)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | EXECUTABLE_MODE) << 16
    with zipfile.ZipFile(output, mode="x") as archive:
        with source.open("rb") as binary, archive.open(info, mode="w") as member:
            shutil.copyfileobj(binary, member, length=1024 * 1024)


def main() -> None:
    args = parse_args()
    validate(args.input, args.output, args.name, args.source_date_epoch)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "tar.gz":
        write_tar_gz(args.input, args.output, args.name, args.source_date_epoch)
    else:
        write_zip(args.input, args.output, args.name, args.source_date_epoch)


if __name__ == "__main__":
    main()
