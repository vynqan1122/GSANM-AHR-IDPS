"""Validate and stage a trusted Colab v2 ZIP without overwriting legacy models."""
import argparse
import hashlib
import json
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
REQUIRED = {'network-xgboost.json', 'log-ai.joblib', 'graphsage-security-event.joblib',
            'fusion-hybrid-xgboost.json'}


def install(archive, destination):
    archive, destination = Path(archive), Path(destination)
    if destination.exists():
        raise ValueError('Destination already exists; use a new version folder. Existing models are preserved.')
    with zipfile.ZipFile(archive) as z:
        members = z.infolist()
        if len(members) > 2000 or sum(i.file_size for i in members) > 2 * 1024**3:
            raise ValueError('Bundle exceeds file/size limits')
        names = set()
        for i in members:
            parts = Path(i.filename).parts
            if ('\\' in i.filename or ':' in i.filename or Path(i.filename).is_absolute()
                    or '..' in parts or i.filename in names
                    or stat.S_ISLNK(i.external_attr >> 16)):
                raise ValueError('Unsafe or duplicate ZIP member')
            names.add(i.filename)
        manifest = json.loads(z.read('manifest.json'))
        if manifest.get('contract') != 'colab-local-v2' or not REQUIRED <= set(manifest['files']):
            raise ValueError('Not a deployable DVWA v2 bundle; CIC benchmark is incompatible')
        for name, digest in manifest['files'].items():
            if Path(name).name != name or name not in names or hashlib.sha256(z.read(name)).hexdigest() != digest:
                raise ValueError(f'Bundle checksum mismatch: {name}')
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp = Path(tempfile.mkdtemp(prefix='bundle-stage-', dir=destination.parent))
        try:
            z.extractall(temp)
            # User supplied this trusted joblib bundle; validate load before making it active.
            from ai.colab.scorer import BundleScorer
            scorer = BundleScorer(temp, device='cpu')
            result = scorer.score([{'event_id': 'bundle-install-check', 'source': 'nginx',
                                   'http': {'method': 'GET', 'uri': '/index.php', 'status': 200}}])
            assert len(result) == 1
            temp.rename(destination)
        except BaseException:
            shutil.rmtree(temp)
            raise
    return {'path': str(destination.resolve()), 'bundle_version': scorer.version,
            'counts': manifest['counts'], 'checksum_and_cpu_inference': 'pass'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zip', default=str(ROOT/'dist/ahr-models-v2.zip'))
    parser.add_argument('--output', default=str(ROOT/'experiments/bundles/colab-v2'))
    args = parser.parse_args()
    print(json.dumps(install(args.zip, args.output), indent=2))
