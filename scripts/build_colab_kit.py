"""Create a private-data-free Colab source kit and runnable notebook."""
from pathlib import Path
import json
import zipfile
import ast

ROOT=Path(__file__).resolve().parents[1]


def notebook():
    cells=[]
    def md(text):cells.append({'cell_type':'markdown','metadata':{},'source':text.splitlines(keepends=True)})
    def code(text):
        ast.parse(text)
        cells.append({'cell_type':'code','metadata':{},'source':text.splitlines(keepends=True),'outputs':[],'execution_count':None})
    md('''# AHR-IDPS legacy AI trên Colab L4

Mở notebook bằng Colab → Runtime → Change runtime type → L4 GPU (nếu tài khoản được cấp).
Đây là bản AI legacy, không sửa `llm-system/`. Network/Fusion XGBoost dùng GPU;
Log IF/MLP và Graph aggregation+MLP vẫn CPU theo thuật toán đang có.
Không cấp phát VRAM rỗng để giả sử dụng 100%. XGBoost không có batch neural-net;
tăng số mẫu gốc, max_bin/max_depth có ảnh hưởng RAM/VRAM và phải đánh giá validation.
L4 có VRAM danh định 24 GB; bộ nhớ dùng được thực tế phụ thuộc runtime. Không thể
bảo đảm loại GPU hoặc thời lượng Colab. Dùng tối đa hữu ích và giữ headroom.

## Phần train ở đâu?
- **A — TRAIN NETWORK TỪ CICIDS2017**: tải Kaggle → xem dữ liệu → train XGBoost → xem loss/đánh giá.
- **B — TRAIN ĐẦY ĐỦ AI DVWA**: upload telemetry có nhãn → OOF Network/Log/Graph/Fusion → xem loss/đánh giá.
- Chạy A nếu hiện bạn chỉ có CSV Kaggle. Chạy B khi đã có telemetry từ lab; CSV CIC không thay thế log/graph DVWA.
- Mọi ảnh là số liệu thực từ run, xuất **PNG + SVG** vào thư mục `figures/` của run trên Drive.
- XGBoost có train/validation logloss theo boosting round; MLP có train loss theo epoch.
  Random Forest/Isolation Forest không có loss theo epoch; không tạo đường loss giả cho chúng.
''')
    code('''import os, sys, json, subprocess, time
from pathlib import Path
os.environ['OMP_NUM_THREADS']='4'
os.environ['OPENBLAS_NUM_THREADS']='4'
subprocess.run(['nvidia-smi'], check=True)
gpu=subprocess.check_output(['nvidia-smi','--query-gpu=name,memory.total','--format=csv,noheader'],text=True)
print('GPU actual:', gpu)
if 'L4' not in gpu: print('Runtime hiện tại không phải L4; đổi runtime nếu muốn dùng L4.')
''')
    md('''## Upload source kit và dữ liệu riêng
Upload `AHR-IDPS-Colab-AI.zip` (nguồn không có dữ liệu/mật khẩu) từ máy lab.
Dataset local đã khử credentials nằm trong ZIP riêng do `prepare_colab_data.py` tạo.
Không upload .env, cookie, PCAP hoặc raw logs chưa review vào notebook.
Sau cell cài đặt, chọn **Runtime → Restart session** (không Delete runtime).
Sau khi restart, chạy từ cell **Khởi tạo sau restart**; không chạy lại cell cài đặt.
Không dùng Run all xuyên qua bước cài đặt lần đầu: cell kế tiếp sẽ dừng nếu kernel chưa restart.
''')
    code('''# CÀI ĐẶT: chưa import numpy/pandas/sklearn/xgboost trong kernel này.
import os, sys, json, subprocess, shutil, zipfile, hashlib
from pathlib import Path
from google.colab import files
uploaded=files.upload()
kit=next((name for name in uploaded if name.endswith('.zip')),None)
if kit is None: raise ValueError('Upload source AHR-IDPS-Colab-AI.zip')
WORK=Path('/content/ahr-colab'); WORK.mkdir(exist_ok=True)
# Giữ bản ZIP tại vị trí cố định để còn truy cập được sau kernel restart.
kit_bytes=Path(kit).read_bytes()
with zipfile.ZipFile(kit) as z:
    for info in z.infolist():
        target=(WORK/info.filename).resolve()
        if not target.is_relative_to(WORK.resolve()): raise ValueError('Unsafe ZIP path')
    z.extractall(WORK)
(WORK/'AHR-IDPS-Colab-AI.zip').write_bytes(kit_bytes)
os.chdir(WORK)
marker=WORK/'.dependencies-ready.json'
marker.unlink(missing_ok=True)
requirements=WORK/'ai/colab/requirements.txt'
subprocess.run([sys.executable,'-m','pip','install','-r',str(requirements)],check=True)
# Kiểm tra bằng Python con mới: kernel hiện tại có thể vẫn giữ NumPy cũ trong RAM.
probe="import numpy, scipy, pandas, sklearn, xgboost; print('Fresh imports OK:', numpy.__version__, scipy.__version__, pandas.__version__, sklearn.__version__, xgboost.__version__); assert xgboost.build_info().get('USE_CUDA'), 'XGBoost wheel has no CUDA'"
try:
    subprocess.run([sys.executable,'-c',probe],check=True)
except subprocess.CalledProcessError:
    print('Fresh imports failed; reinstall wheels without cache to repair mixed package files.')
    subprocess.run([sys.executable,'-m','pip','install','--force-reinstall','--no-cache-dir','-r',str(requirements)],check=True)
    subprocess.run([sys.executable,'-c',probe],check=True)
marker.write_text(json.dumps({'installer_pid':os.getpid(),
    'python':sys.version,'executable':sys.executable,
    'requirements_sha256':hashlib.sha256(requirements.read_bytes()).hexdigest()}),encoding='utf-8')
print('CÀI ĐẶT XONG. Chọn Runtime > Restart session, rồi chạy từ cell Khởi tạo sau restart. KHÔNG chạy lại cell cài đặt.')
''')
    md('''## Khởi tạo sau restart
Chọn **Runtime → Restart session** trước khi chạy cell này. File trong `/content`
vẫn còn sau restart session. Cell tự kiểm tra kernel đã đổi; mọi biến cần thiết
đều được khởi tạo lại tại đây. Nếu đã xóa runtime, cần upload và cài lại source.
''')
    code('''import os, sys, json, subprocess, time, zipfile, shutil, hashlib
from pathlib import Path
WORK=Path('/content/ahr-colab')
marker=WORK/'.dependencies-ready.json'
if not marker.exists(): raise RuntimeError('Chạy cell upload/cài đặt trước; nếu runtime bị xóa thì phải cài lại.')
setup=json.loads(marker.read_text(encoding='utf-8'))
if setup['installer_pid']==os.getpid():
    raise RuntimeError('Kernel chưa restart sau pip install. Chọn Runtime > Restart session; sau đó chạy từ cell Khởi tạo sau restart, KHÔNG chạy lại cell cài đặt.')
if setup['requirements_sha256']!=hashlib.sha256((WORK/'ai/colab/requirements.txt').read_bytes()).hexdigest():
    raise RuntimeError('Requirements đã đổi: chạy lại cell cài đặt rồi restart session.')
os.environ['OMP_NUM_THREADS']='4'
os.environ['OPENBLAS_NUM_THREADS']='4'
os.chdir(WORK)
sys.path.insert(0,str(WORK))
subprocess.run(['nvidia-smi'],check=True)
import numpy as np, scipy, pandas as pd, sklearn
import xgboost as xgb
print('Python:',sys.version)
print('Versions:',np.__version__,scipy.__version__,pd.__version__,sklearn.__version__,xgb.__version__)
print('CUDA build:',xgb.build_info())
if not xgb.build_info().get('USE_CUDA'): raise RuntimeError('XGBoost wheel không có CUDA')
from google.colab import files, drive
drive.mount('/content/drive')
DRIVE_ROOT=Path('/content/drive/MyDrive/AHR-IDPS')
RUNS=DRIVE_ROOT/'runs'; RUNS.mkdir(parents=True,exist_ok=True)
# Mỗi phiên giữ một snapshot mã nguồn/notebook trong Drive; không ghi đè phiên cũ.
SNAPSHOT=DRIVE_ROOT/'source-snapshots'/time.strftime('%Y%m%d-%H%M%S')
SNAPSHOT.mkdir(parents=True,exist_ok=True)
(SNAPSHOT/'AHR-IDPS-Colab-AI.zip').write_bytes((WORK/'AHR-IDPS-Colab-AI.zip').read_bytes())
for rel in ('ai','feature_engine','scripts/prepare_colab_data.py','notebooks/AHR_IDPS_L4_Training.ipynb','ai/colab/requirements.txt'):
    src=WORK/rel
    if src.is_dir(): shutil.copytree(src,SNAPSHOT/rel,dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))    elif src.exists():
        dst=SNAPSHOT/rel; dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(src,dst)
(SNAPSHOT/'RUN_SOURCE.txt').write_text('Source snapshot for this Colab run. Do not store credentials here.\\n',encoding='utf-8')
print('Drive source snapshot:',SNAPSHOT)
''')
    md('''## A1 — Dataset Kaggle cho Network AI
Network benchmark: full CICIDS2017 (nhiều triệu flow), hoặc CSE-CIC-IDS2018
(lớn hơn, khoảng hàng chục triệu flow). Chỉ file Thursday WebAttacks có 2.180
attack, không đủ để ép thành tập web attack hàng triệu mẫu độc lập.
Kaggle có nhiều bản sao: nhập handle của bản CSV bạn chọn, kiểm schema/nguồn/license.
Benchmark công khai giữ đặc trưng CIC native, tuyệt đối không deploy vào runtime 21 feature.
Local triển khai: ưu tiên 20.000–100.000 request DVWA thật từ nhiều session/day,
bao gồm benign cùng challenge, login hợp lệ, hard negatives và attack có oracle.
''')
    code('''# Tải CICIDS2017; để chuỗi rỗng nếu chỉ train telemetry DVWA local.
import importlib.util
KAGGLE_HANDLE='mdalamintalukder/cicids2017'
PUBLIC_DATA=None
if KAGGLE_HANDLE:
    if KAGGLE_HANDLE.strip() in {'owner/dataset','owner/dataset-name'}:
        raise ValueError('owner/dataset là tên mẫu. Dùng mdalamintalukder/cicids2017 hoặc handle thật từ URL Kaggle.')
    if importlib.util.find_spec('kagglehub') is None:
        print('Đang cài kagglehub; chờ pip hoàn tất. Output cài đặt hiển thị bên dưới.',flush=True)
        subprocess.run([sys.executable,'-m','pip','install','--disable-pip-version-check',
                        '--timeout','60','--retries','2','kagglehub>=0.3,<1'],check=True,timeout=600)
    import kagglehub
    print('Đang tải:',KAGGLE_HANDLE,flush=True)
    PUBLIC_DATA=Path(kagglehub.dataset_download(KAGGLE_HANDLE))
    print('Dataset cache:',PUBLIC_DATA)
    csv_files=sorted(PUBLIC_DATA.rglob('*.csv'))
    print('CSV files:',len(csv_files))
    for path in csv_files[:15]: print(path.relative_to(PUBLIC_DATA))
''')
    md('''## A2 — Xem dữ liệu trước khi train
Cell dưới hiển thị mẫu CSV và thống kê tối đa 5.000 dòng từ file đầu tiên, không phải toàn dataset.
Khi train, toàn bộ file được đọc theo chunks; số đếm trước/sau làm sạch được ghi vào `preprocessing.csv`.
Biểu đồ tương quan/phân bố đặc trưng chỉ dùng mẫu của tập **train**; tập test giữ riêng.
''')
    code('''if PUBLIC_DATA is not None:
    from ai.colab.visuals import preview_csv
    preview_csv(PUBLIC_DATA)
else:
    print('Không tải CIC; chuyển tới phần B nếu chỉ train telemetry DVWA.')
''')
    md('''## A3 — TRAIN NETWORK TỪ CICIDS2017 (bấm ▶ tại cell dưới)
Đây là lệnh train thật. `PUBLIC_ROUNDS` là số boosting rounds, không phải epoch neural network.
Mặc định bật train. Đổi `RUN_PUBLIC=False` nếu chỉ chạy phần B.
Trong lúc chạy sẽ thấy train/validation logloss mỗi 25 rounds. Test không nằm trong eval set.
Ảnh tiền xử lý được ghi trước train; ảnh loss và đánh giá được ghi sau train.
''')
    code('''RUN_PUBLIC=True
PUBLIC_ROUNDS=400
CAP_PER_CLASS=150000  # tối đa mỗi nhãn gốc; tăng khi RAM cho phép, không nhân bản mẫu
if RUN_PUBLIC:
    if PUBLIC_DATA is None: raise ValueError('Set KAGGLE_HANDLE và download trước')
    from ai.colab.public_benchmark import benchmark
    PUBLIC_OUT=RUNS/('cic-'+time.strftime('%Y%m%d-%H%M%S'))
    public_report=benchmark(PUBLIC_DATA,PUBLIC_OUT,
                            cap_per_class=CAP_PER_CLASS,device='cuda',rounds=PUBLIC_ROUNDS)
    print(json.dumps(public_report,indent=2)[:6000])
    print('Model / figures / reports saved to Drive:',PUBLIC_OUT)
''')
    md('''## A4 — Xem hình loss và đánh giá Network vừa train
Cell dưới hiển thị gallery ngay trong notebook. Mọi PNG/SVG, CSV và `training-history.json`
đều đã được lưu vào Drive. Dùng `names=None` trong `show_run` nếu muốn hiển thị toàn bộ ảnh.
Nếu chỉ train Kaggle, hoàn tất tại đây; không cần chạy các cell upload DVWA/server phía sau.
''')
    code('''if RUN_PUBLIC:
    from ai.colab.visuals import show_run
    show_run(PUBLIC_OUT,names=['01_preprocessing','02_class_distribution','03_split_counts',
        '04_feature_correlation','05_feature_distributions','06_missing_values',
        'loss_network_xgboost','learning_network_xgboost','cm_network_xgboost','08_roc_pr','09_calibration',
        'scores_network_xgboost','10_feature_importance'])
''')
    md('''## B1 — Upload telemetry DVWA để train đủ bốn model triển khai
Chạy `prepare_colab_data.py` trên máy chính, review file trước upload.
Chọn `events-colab.jsonl` hoặc ZIP chỉ chứa file này. Giữ training runs trong Drive.
Mọi split chia theo scenario/campaign; Fusion dùng 3-fold OOF. Test được lưu riêng.
Phần B cần telemetry có nhãn đúng schema; không upload CSV CIC vào cell này.
''')
    code('''uploaded_data=files.upload()
DATA=WORK/'events-colab.jsonl'
for name in uploaded_data:
    if name.endswith('.jsonl'):
        DATA.write_bytes(Path(name).read_bytes())
    elif name.endswith('.zip'):
        with zipfile.ZipFile(name) as z:
            hits=[n for n in z.namelist() if n.endswith('events-colab.jsonl')]
            if len(hits)!=1: raise ValueError('ZIP phải có đúng events-colab.jsonl')
            DATA.write_bytes(z.read(hits[0]))
if not DATA.exists(): raise ValueError('Chưa upload telemetry local')
from ai.colab.data import load_events,split_groups
events,excluded=load_events(DATA)
split,y=split_groups(events)
print('Events',len(events),'Excluded',excluded)
print('Group-disjoint splits:',{k:len(v) for k,v in split.items()})
# Dữ liệu đã canonical/redact được ghi kèm run để tái lập; không tải raw PCAP/cookie.
DATA_ARCHIVE=DRIVE_ROOT/'datasets'; DATA_ARCHIVE.mkdir(parents=True,exist_ok=True)(DATA_ARCHIVE/'events-colab.jsonl').write_bytes(DATA.read_bytes())
print('Sanitized dataset copy:',DATA_ARCHIVE/'events-colab.jsonl')
''')
    md('''## B2 — TRAIN NETWORK + LOG + GRAPH + FUSION DVWA (bấm ▶ tại cell dưới)
Pipeline train ba fold OOF trước, fit model final, rồi đánh giá test. Log/Graph MLP chạy CPU;
Network/Fusion XGBoost chạy CUDA. Số round và số mẫu tối đa được cấu hình ngay dưới.
Lưu loss thật từng fold/final vào `training-history.json`, PNG/SVG trong `figures/`.
XGBoost đo validation logloss theo round; MLP chỉ xuất train loss hiện có.
''')
    code('''# Monitor thực đo toàn GPU; không cấp phát bộ nhớ rỗng.
DVWA_ROUNDS=150
MAX_DVWA_EVENTS=500000
import threading
GPU_SAMPLES=[]; GPU_STOP=threading.Event()
def gpu_monitor():
    while not GPU_STOP.is_set():
        raw=subprocess.check_output(['nvidia-smi','--query-gpu=memory.used,memory.total,utilization.gpu','--format=csv,noheader,nounits'],text=True)
        GPU_SAMPLES.append({'time':time.time(),'gpu':raw.strip()})
        GPU_STOP.wait(1)
GPU_THREAD=threading.Thread(target=gpu_monitor,daemon=True);GPU_THREAD.start()
OUT=RUNS/('dvwa-'+time.strftime('%Y%m%d-%H%M%S'))
from ai.colab.train import train
try:
    manifest=train(DATA,OUT,device='cuda',rounds=DVWA_ROUNDS,max_events=MAX_DVWA_EVENTS)
finally:
    GPU_STOP.set();GPU_THREAD.join(timeout=5)
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'gpu-samples.json').write_text(json.dumps(GPU_SAMPLES,indent=2))
print('Models/reports saved:',OUT)
print('All outputs are already under Google Drive:',OUT)
''')
    md('''## B3 — Xem loss, so sánh thuật toán và đánh giá test DVWA
So sánh rule-only, Network, Log, Graph, weighted hybrid, Fusion OOF và hai baseline
trên cùng test. Gallery hiển thị ảnh chính; dùng `names=None` để xem toàn bộ loss OOF,
confusion matrix và phân bố score của từng model.
''')
    code('''from ai.colab.visuals import show_run
show_run(OUT,names=['01_preprocessing','02_class_distribution','03_split_counts',
    '04_feature_correlation','05_feature_distributions','loss_final_network',
    'loss_final_log_mlp','loss_final_graph_mlp','loss_final_fusion','learning_final_network','learning_final_fusion',
    '07_model_comparison','cm_fusion_oof','08_roc_pr','09_calibration','10_feature_importance'])
print('Train time:',manifest['training_wall_seconds'])
''')
    md('''## Tuỳ chọn dùng trực tiếp Colab làm AI server
Chỉ bật sau khi model đã train và bạn muốn kết nối lab. Cần token ngrok trong
Colab Secrets (`NGROK_AUTHTOKEN`) của chính bạn. Tunnel public HTTPS có Bearer
token ngẫu nhiên; không public database/Redis/DVWA. Colab có thể disconnect,
ngrok URL thay đổi; bridge lab sẽ báo degraded, giữ pending, không tạo attack giả.
Không chia sẻ notebook output chứa inference token. Token chỉ lưu trên máy lab
trong secrets/colab_token; xoay token khi phiên mới.
''')
    code('''RUN_REMOTE=False
if RUN_REMOTE:
    import secrets, threading, uvicorn
    from google.colab import userdata
    from pyngrok import ngrok
    from ai.colab.serve import create_app
    INFERENCE_TOKEN=secrets.token_urlsafe(48)
    app=create_app(OUT,INFERENCE_TOKEN,device='cuda')
    server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=8765,log_level='warning',access_log=False))
    SERVER_THREAD=threading.Thread(target=server.run,daemon=True);SERVER_THREAD.start()
    time.sleep(2)
    ngrok.set_auth_token(userdata.get('NGROK_AUTHTOKEN'))
    tunnel=ngrok.connect(8765,bind_tls=True)
    ENDPOINT=tunnel.public_url
    print('COLAB_ENDPOINT =', ENDPOINT)
    # Tải secret riêng, không in token trong notebook output.
    token_path=WORK/'colab_token';token_path.write_text(INFERENCE_TOKEN)
    files.download(str(token_path))
''')
    code('''# Kết thúc server và tunnel khi không sử dụng.
STOP_REMOTE=False
if STOP_REMOTE and RUN_REMOTE:
    ngrok.disconnect(ENDPOINT)
    server.should_exit=True
''')
    md('''## Tải model về local (tuỳ chọn)
Bundle v2 dùng shared scorer với graph single-event causal. Dùng BundleScorer
trên local CPU khi không cần Colab; không copy mù vào tên artifact window-model
cũ. Không mở joblib từ nguồn không tin cậy. Đọc README về staging/rollback.
''')
    code('''import shutil
archive=shutil.make_archive('/content/ahr-models-v2','zip',OUT)
files.download(archive)
''')
    return {'nbformat':4,'nbformat_minor':5,'metadata':{'colab':{'name':'AHR_IDPS_L4_Training.ipynb'},
            'kernelspec':{'display_name':'Python 3','language':'python','name':'python3'},'accelerator':'GPU'},'cells':cells}


def main():
    nb=notebook();out=ROOT/'notebooks';out.mkdir(exist_ok=True)
    for i,cell in enumerate(nb['cells']):cell['id']=f'ahr-{i:03}'
    (out/'AHR_IDPS_L4_Training.ipynb').write_text(json.dumps(nb,ensure_ascii=False,indent=2),encoding='utf-8')
    target=ROOT/'dist/AHR-IDPS-Colab-AI.zip';target.parent.mkdir(exist_ok=True)
    paths=[]
    for folder in ('ai','feature_engine'):
        paths.extend(p for p in (ROOT/folder).rglob('*.py') if '__pycache__' not in p.parts)
    paths+=[ROOT/'ai/colab/requirements.txt',ROOT/'notebooks/AHR_IDPS_L4_Training.ipynb',
            ROOT/'ai/compose.colab.yml',ROOT/'scripts/prepare_colab_data.py',ROOT/'scripts/start_colab_ai.ps1']
    for name in ('COLAB_AI_GUIDE.md','COLAB_AI_VALIDATION.md','COLAB_FULL_TRAIN_RUNBOOK.md','COLAB_TRAINING_FIGURES_VALIDATION.md'):
        guide=ROOT/'docs'/name
        if guide.exists():paths.append(guide)
    with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as z:
        for p in sorted(set(paths)):z.write(p,p.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(target) as z:
        assert z.testzip() is None
    print(json.dumps({'notebook_cells':len(nb['cells']),'source_files':len(set(paths)),'zip':str(target),'bytes':target.stat().st_size}))

if __name__=='__main__':main()
