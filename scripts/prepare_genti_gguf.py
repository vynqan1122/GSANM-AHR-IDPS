"""Convert the verified user-trained model offline; keep the active model untouched."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ai.genti.contract import CONTRACT, GGUF_CONTRACT, verify_bundle


def prepare(source, destination):
    source = Path(source).resolve(); destination = Path(destination).resolve()
    if not destination.is_relative_to(ROOT / 'experiments/genti') or destination.exists():
        raise ValueError('Choose a new directory inside experiments/genti; no overwrite')
    original = verify_bundle(source)
    if original['contract'] != CONTRACT:
        raise ValueError('Input must be the merged, checksum-verified Colab export')
    subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'], check=True)
    tag = 'ghcr.io/ggml-org/llama.cpp:full'
    if subprocess.run(['docker', 'image', 'inspect', tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        subprocess.run(['docker', 'pull', tag], check=True)
    image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tag]))[0]['RepoDigests'][0]
    destination.mkdir()
    work = destination.parent / (destination.name + '-conversion')
    work.mkdir(exist_ok=False)
    common = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
              '--security-opt', 'no-new-privileges:true', '--memory', '8g', '--cpus', '4',
              '--pids-limit', '128', '--tmpfs', '/tmp:rw,size=536870912',
              '-e', 'HF_HUB_OFFLINE=1', '-e', 'OMP_NUM_THREADS=4',
              '-v', f'{source}:/source:ro', '-v', f'{destination}:/out', '-v', f'{work}:/work']
    for name, args in [('convert', ['--convert', '/source', '--outfile', '/work/model-f16.gguf', '--outtype', 'f16']),
                       ('quantize', ['--quantize', '/work/model-f16.gguf', '/out/model.gguf', 'Q4_K_M', '4'])]:
        print(name, image, flush=True)
        with (work / f'{name}.log').open('wb') as log:
            subprocess.run(common + [image] + args, stdout=log, stderr=subprocess.STDOUT, check=True)
    for name in ('config.json', 'chat_template.jinja'):
        shutil.copy2(source / name, destination / name)
    shutil.copy2(source / 'genti-manifest.json', destination / 'source-manifest.json')
    manifest = {k: v for k, v in original.items() if k not in ('files', 'artifact_sha256', 'contract')}
    manifest.update(contract=GGUF_CONTRACT, source_artifact_sha256=original['artifact_sha256'],
                    quantization='Q4_K_M', conversion_image=image,
                    quality_evaluation='Quantized runtime requires fresh native replay; no sensor deployment')
    manifest['files'] = {}
    for path in destination.iterdir():
        with path.open('rb') as stream:
            digest = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        manifest['files'][path.name] = digest.hexdigest()
    (destination / 'genti-manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    verified = verify_bundle(destination)
    (work / 'model-f16.gguf').unlink()
    print('VERIFIED', verified['artifact_sha256'], flush=True)
    return verified


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=ROOT / 'experiments/genti/colab-source')
    p.add_argument('--destination', type=Path, default=ROOT / 'experiments/genti/staging-7b')
    a = p.parse_args()
    prepare(a.source, a.destination)
