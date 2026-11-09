"""Install an explicitly selected local model ZIP without overwriting a working model."""
import argparse
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ai.genti.contract import verify_bundle


def install(archive, destination):
    destination = Path(destination).resolve()
    if destination.exists():
        raise ValueError('Destination exists; retain it for rollback and choose an empty destination')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temp:
        root = Path(temp)
        with zipfile.ZipFile(archive) as z:
            entries = z.infolist()
            if len(entries) > 450 or sum(x.file_size for x in entries) > 32*1024**3:
                raise ValueError('Model ZIP exceeds allowed size/file count')
            for info in entries:
                path = (root / info.filename).resolve()
                if not path.is_relative_to(root) or stat.S_ISLNK(info.external_attr >> 16):
                    raise ValueError('Unsafe ZIP entry')
            z.extractall(root)
        manifest = verify_bundle(root)
        shutil.move(str(root), str(destination))
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('archive', type=Path)
    parser.add_argument('--destination', type=Path, default=ROOT/'experiments/genti/main')
    args = parser.parse_args()
    print(install(args.archive, args.destination)['artifact_sha256'])
