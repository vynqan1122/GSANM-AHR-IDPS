"""Normalize native sensor logs read-only when live DB ingestion is still catching up.

Uses exactly the collector IDs and normalizer mappings used by the live pipeline.
No replay into Redis/DB, and no change to the raw logs or running services.
"""
import argparse
import hashlib
import json
from pathlib import Path

from collector.collectors import parse_nginx,parse_suricata,parse_falco,parse_wazuh
from normalizer.schemas import RawEnvelope
from normalizer.mappings import normalize
from dataset_collection.large_campaign import open_journal,request_marker,export_rows

SOURCES={
    'nginx':('/var/log/ahr-nginx/access.jsonl',parse_nginx),
    'suricata':('/var/log/suricata/eve.json',parse_suricata),
    'falco':('/var/log/falco/events.jsonl',parse_falco),
    'wazuh':('/var/log/wazuh/alerts/alerts.json',parse_wazuh),
}


def native_rows(run_id,journal,provenance):
    markers={r[0] for r in journal.execute('SELECT marker FROM results WHERE valid=1')}
    prefix=('ahrbulk_'+run_id+'_').encode()
    for source,(filename,parser) in SOURCES.items():
        path=Path(filename)
        if not path.exists():continue
        print('Normalizing actual sensor snapshot:',source,flush=True)
        limit=path.stat().st_size
        h=hashlib.sha256();matched=0;invalid=0;read=0
        with path.open('rb') as stream:
            while read<limit:
                line=stream.readline(limit-read);read+=len(line);h.update(line)
                if not line.endswith(b'\n'):break
                if prefix not in line:continue
                try:
                    raw=parser(json.loads(line),{'offline_native_export':True})
                    envelope=RawEnvelope.from_stream_fields(raw.stream_fields())
                    event=normalize(envelope).model_dump(mode='json')
                    event['raw_event']=event.pop('raw',{})
                    if request_marker(event,run_id) not in markers:continue
                    matched+=1
                    yield event
                except (ValueError,TypeError,KeyError):
                    invalid+=1
        provenance.append({'source':source,'path':filename,'read_bytes':read,'prefix_snapshot_sha256':h.hexdigest(),
                           'matching_events':matched,'invalid_matching_records':invalid})


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--campaign',type=Path,required=True)
    args=p.parse_args();meta=json.loads((args.campaign/'plan-manifest.json').read_text())
    journal=open_journal(args.campaign)
    provenance=[]
    try:
        report=export_rows(args.campaign,meta,journal,native_rows(meta['run_id'],journal,provenance))
        report['provenance']='native sensor snapshot normalized with live collector parsers/IDs and normalizer mappings; exact marker join to valid requests'
        report['native_sources']=provenance
        report['live_database_not_required']=True
        # Regenerate ZIP manifest after adding source evidence.
        manifest=args.campaign/'export/manifest.json'
        manifest.write_text(json.dumps(report,indent=2),encoding='utf-8')
        import zipfile
        with zipfile.ZipFile(args.campaign/'export/colab-dataset.zip','w',zipfile.ZIP_DEFLATED) as z:
            z.write(args.campaign/'export/events-colab.jsonl','events-colab.jsonl');z.write(manifest,'manifest.json')
        progress_path=args.campaign/'progress.json'
        if progress_path.exists():
            state=json.loads(progress_path.read_text())
            state['live_database_observed_events']=state.get('observed_events',0)
            state['export']=report
            state['export_source']='native_sensor_snapshot'
            state['status']='complete' if report['real_sensor_events']>=state['target_events'] else 'partial'
            progress_path.write_text(json.dumps(state,indent=2),encoding='utf-8')
        print(json.dumps(report,indent=2))
    finally:journal.close()


if __name__=='__main__':main()
