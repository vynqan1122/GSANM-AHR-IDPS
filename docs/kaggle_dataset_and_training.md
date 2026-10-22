# Dataset Kaggle va huan luyen Network AI cho AHR-IDPS

## Ket luan ngan

Dataset phu hop nhat de bo sung cho phan Network AI la **CIC-IDS2017**, uu tien
cac dong nhan `Web Attack - Brute Force`, `Web Attack - XSS`,
`Web Attack - Sql Injection` va mot phan `BENIGN`. Co the tai ban CSV/ZIP tren
Kaggle voi tu khoa `CICIDS2017` hoac tai tu trang goc cua Canadian Institute
for Cybersecurity. Ten nguoi dang tai Kaggle co the thay doi, vi vay can kiem
tra cot `Label` thay vi phu thuoc vao mot URL cu the.

Dataset nay chi la du lieu bo sung cho Network AI. Du lieu chinh de danh gia
de tai van la telemetry thu tu DVWA local, vi CIC-IDS2017 khong co Falco
syscall, Wazuh alert, Nginx session va quan he container/process cua he thong.
Khong tron ngau nhien hai nguon roi goi chung la ket qua DVWA.

Neu muon nghien cuu rieng request HTTP, co the tham khao **CSIC 2010 HTTP
Dataset** tren Kaggle. Dataset nay sat voi web request hon nhung khong co flow,
Falco hay Wazuh; vi vay no khong duoc dua truc tiep vao `network-v1`. Can viet
adapter cho `Path`, `Body`, `Method`, response/status va label truoc khi dung
cho Log AI hoac mot baseline HTTP rieng. Trong pham vi bai tap lon hien tai,
chi nen chon CICIDS2017 + telemetry DVWA de giam so luong code phai bao tri.

## Quy mo phu hop may lab

Bat dau voi 10.000-30.000 dong CICIDS2017, giu can bang benign/attack. Mot may
CPU 4 nhan, RAM 8 GB khong can GPU cho pipeline nay. Neu may yeu, dung
`--max-rows 5000` hoac `--max-rows 10000`; bo script lay mau theo lop truoc
khi train. Khi da co model on dinh, moi tang den 50.000-100.000 dong.

Ty le chia du lieu mac dinh la 80% train va 20% holdout. Neu co
`scenario_id`/`Day`/`Date`, script uu tien chia theo group de tranh cung mot
scenario xuat hien ca train va test. Neu dataset qua it group hoac holdout
chi co mot lop, script dung stratified split va ghi ro
`split_strategy` trong file ket qua.

## Cach dat file dataset

Dat file tai tu Kaggle vao `datasets/external/`, vi du:

```text
datasets/external/CICIDS2017_Web_Attacks.zip
```

Script doc duoc ba dang:

- CSV CICIDS2017 co cot `Label` va cac cot flow;
- ZIP chua mot hoac nhieu CSV;
- JSONL AHR-IDPS, vi du `datasets/network/flows.jsonl`.

Khong commit dataset Kaggle lon vao Git. Them `datasets/external/` vao ignore
neu can, va chi commit manifest, checksum, so dong va nguon tai.

## Lenh train va so sanh

Tren PowerShell:

```powershell
python -m pip install -r .\ai\requirements.txt
python .\scripts\train_kaggle_network.py `
  --input .\datasets\external\CICIDS2017_Web_Attacks.zip `
  --max-rows 20000 `
  --output-dir .\experiments\comparison\network
```

Hoac dung wrapper:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\train_kaggle_network.ps1 `
  -InputPath .\datasets\external\CICIDS2017_Web_Attacks.zip `
  -MaxRows 20000
```

Tren Linux/WSL:

```bash
MAX_ROWS=20000 bash ./scripts/train_kaggle_network.sh \
  datasets/external/CICIDS2017_Web_Attacks.zip
```

Neu may khong co Python package tren host, dung image AI sau khi Docker daemon
da chay:

```powershell
docker build -f .\ai\Dockerfile -t ahr-idps/ai-network:local .
docker run --rm `
  -v "${PWD}\datasets:/opt/ahr-idps/datasets" `
  -v "${PWD}\experiments:/opt/ahr-idps/experiments" `
  ahr-idps/ai-network:local `
  python scripts/train_kaggle_network.py `
    --input /opt/ahr-idps/datasets/external/CICIDS2017_Web_Attacks.zip `
    --max-rows 20000 `
    --output-dir /opt/ahr-idps/experiments/comparison/network
```

Neu muon cai model runtime bang Docker, them `--install-xgboost` vao lenh tren.
Thu muc `experiments` duoc bind tu may chu nen artifact van nam tren may chu.

Lenh tren train va so sanh:

- Logistic Regression co chuan hoa;
- Random Forest;
- HistGradientBoosting;
- XGBoost neu co `xgboost`.

Ket qua nam trong `experiments/comparison/network/`:

```text
network_model_comparison.csv       # bang so lieu de dua vao bao cao
network_model_comparison.md        # bang doc nhanh
network_model_comparison.json      # metrics + provenance + schema
logistic_regression.joblib
random_forest.joblib
hist_gradient_boosting.joblib
xgboost-network.json
```

Chi so duoc ghi gom accuracy, precision, recall, F1, FPR, ROC-AUC, PR-AUC va
confusion-matrix counts. Khi viet bao cao, uu tien F1, PR-AUC va FPR tren
holdout; khong dung accuracy mot minh khi dataset mat can bang.

## Dua model vao AHR-IDPS runtime

Chi XGBoost dung feature contract `network-v1` moi co the dung truc tiep voi
`ai.network.infer`. Sau khi kiem tra file so sanh, chay:

```powershell
python .\scripts\train_kaggle_network.py `
  --input .\datasets\external\CICIDS2017_Web_Attacks.zip `
  --max-rows 20000 `
  --install-xgboost
```

Lenh nay copy artifact vao:

```text
experiments/models/network-xgboost.json
experiments/models/network-xgboost.metadata.json
```

Neu file cu ton tai, ban sao `.bak` duoc tao truoc khi ghi de. Docker mount
thu muc `experiments/models` vao `/opt/ahr-idps/experiments/models`, vi vay
khong can copy file vao container bang tay.

Sau do dang ky lai artifact trong PostgreSQL va khoi dong AI:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_ai.ps1
```

Neu chi muon chay cac model AI da dang ky, khong muon thay model runtime,
bo qua `--install-xgboost`; file `xgboost-network.json` trong thu muc
comparison van duoc giu de so sanh.

## Du lieu DVWA nen dung de bao cao

De co ket qua sat voi de tai, thu thap them du lieu AHR-IDPS local:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\collect_dvwa_training_dataset.ps1 -Profile all
```

Sau khi co nhan va event trong PostgreSQL, co the export JSONL roi train lai:

```powershell
python .\scripts\train_kaggle_network.py `
  --input .\datasets\network\flows.jsonl `
  --max-rows 0 `
  --output-dir .\experiments\comparison\network-dvwa `
  --install-xgboost
```

Dataset DVWA can co cac scenario doc lap:

| Nhom | Nhan | Noi dung | Vai tro |
|---|---|---|---|
| baseline | benign | login, instructions, request hop le | do false positive |
| web_injection | attack | SQLi, XSS, command/file inclusion co kiem soat | do detection |
| auth_abuse | attack | login sai gioi han, path probe lab | do correlation |

Moi scenario phai co `scenario_id`; chia train/test theo scenario, khong chia
tung event ngau nhien. De xuat ban dau 60 scenario va 2.000-3.200 event da
gan nhan, sau do giu 10% scenario/variant lam unknown holdout.

## Cac file can co de train

Khong can them file model thu cong. Toi thieu can:

```text
ai/requirements.txt
feature_engine/network_features.py
scripts/train_kaggle_network.py
datasets/external/<dataset>.csv hoac .zip
```

Neu muon cap nhat realtime Docker, can them `docker-compose.yml`,
`ai/compose.fragment.yml`, PostgreSQL va Redis dang chay; lenh train doc dataset
local va khong can truy cap database, con `start_ai.ps1` dang ky model va bat
cac service inference.

## Luu y ve Log AI, Graph AI va Fusion AI

Mot file CICIDS CSV khong du thong tin de train dung Log AI va Graph AI cua
AHR-IDPS. Hai model nay can log da chuan hoa, process/container, rule, event
sequence va graph edges tu DVWA/Falco/Wazuh. Sau khi thu du local telemetry,
dung train DB-native hien co:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\train_dvwa_models.ps1
```

Thu tu hop ly la Network AI tu CSV bo sung + local flows, sau do Log AI, Graph
AI va cuoi cung Fusion AI tu cac prediction da co. Khong train Fusion tu cac
cot Kaggle don le vi nhu vay khong phan anh ba diem AI va rule score cua he thong.
