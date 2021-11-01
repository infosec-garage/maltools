"""Helper functions"""
import hashlib
from pathlib import Path


def sha256sum(filename: Path) -> str:
    """Calculate the SHA256 value of a file"""
    # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
    h = hashlib.sha256()
    b = bytearray(128 * 1024)
    mv = memoryview(b)

    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda: f.readinto(mv), 0):  # type: ignore
            h.update(mv[:n])

    return h.hexdigest()


def read_file(filename: Path) -> str:
    """Read the contents of a file"""
    with open(filename, 'r') as f:
        contents = f.read()

    return contents
