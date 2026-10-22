"""Private local telemetry -> reviewed credential-redacted JSONL for Colab."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from ai.colab.data import load_events,sanitized_event


def main():
    p=argparse.ArgumentParser();p.add_argument('--input',default='datasets/raw/events.jsonl')
    p.add_argument('--output',default='exports/colab-data')
    p.add_argument('--exclude-conflicts',action='store_true',help='Explicitly quarantine conflicting event IDs, never relabel')
    a=p.parse_args()
    rows,excluded=load_events(a.input,exclude_conflicts=a.exclude_conflicts)
    out=Path(a.output)
    if out.exists():raise ValueError('Use new output directory to preserve an existing dataset snapshot')
    out.mkdir(parents=True)
    path=out/'events-colab.jsonl'
    with path.open('w',encoding='utf-8') as f:
        for row in rows:f.write(json.dumps(sanitized_event(row),ensure_ascii=False)+'\n')
    report={'records':len(rows),'excluded':excluded,'input_sha256':hashlib.sha256(Path(a.input).read_bytes()).hexdigest(),
            'output_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'privacy':'allowlisted canonical fields; still review IPs/URIs before personal Drive upload'}
    (out/'manifest.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    with zipfile.ZipFile(out/'colab-dataset.zip','w',zipfile.ZIP_DEFLATED) as z:
        z.write(path,path.name);z.write(out/'manifest.json','manifest.json')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
