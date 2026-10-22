"""Deterministic validation of notebook, source ZIP and optional smoke bundle."""
from pathlib import Path
import ast
import hashlib
import json
import sys
import zipfile
from datetime import date
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))


def main():
    nbpath=ROOT/'notebooks/AHR_IDPS_L4_Training.ipynb'
    nb=json.loads(nbpath.read_text(encoding='utf-8'))
    assert nb['nbformat']==4
    ids=[];code=0
    for cell in nb['cells']:
        ids.append(cell['id'])
        if cell['cell_type']=='code':
            ast.parse(''.join(cell['source']));code+=1
            assert cell['outputs']==[] and cell['execution_count'] is None
    assert len(ids)==len(set(ids))
    target=ROOT/'dist/AHR-IDPS-Colab-AI.zip'
    with zipfile.ZipFile(target) as z:
        assert z.testzip() is None
        names=z.namelist()
        assert not any('/.env' in n or n.endswith('colab_token') or '/datasets/' in n or '__pycache__' in n for n in names)
    report={'date':date.today().isoformat(),'notebook_cells':len(ids),'code_cells_ast_validated':code,
            'notebook_has_no_saved_outputs':True,'source_zip_integrity':'pass','source_zip_files':len(names),
            'zip_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
            'colab_account_accessed':False,'l4_execution_verified':False}
    output=ROOT/'output/colab';output.mkdir(parents=True,exist_ok=True)
    (output/'artifact-validation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
