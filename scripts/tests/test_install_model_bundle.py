import hashlib
import json
import zipfile

import pytest
from scripts.install_model_bundle import install, REQUIRED


def test_installer_rejects_tampered_artifact_before_loading_joblib(tmp_path):
    archive=tmp_path/'bundle.zip'
    manifest={'contract':'colab-local-v2','files':{n:hashlib.sha256(b'original').hexdigest() for n in REQUIRED}}
    with zipfile.ZipFile(archive,'w') as z:
        z.writestr('manifest.json',json.dumps(manifest))
        for name in REQUIRED:z.writestr(name,b'tampered')
    with pytest.raises(ValueError,match='checksum'):install(archive,tmp_path/'dest')
    assert not (tmp_path/'dest').exists()


def test_installer_rejects_traversal_and_preserves_existing_folder(tmp_path):
    archive=tmp_path/'bad.zip'
    with zipfile.ZipFile(archive,'w') as z:z.writestr('../outside','invalid')
    with pytest.raises(ValueError,match='Unsafe'):install(archive,tmp_path/'dest')
    destination=tmp_path/'existing';destination.mkdir()
    (destination/'keep').write_text('keep')
    with pytest.raises(ValueError,match='already exists'):install(archive,destination)
    assert (destination/'keep').read_text()=='keep'
