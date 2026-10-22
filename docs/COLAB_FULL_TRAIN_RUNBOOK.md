# AHR-IDPS: train đầy đủ trên Google Colab L4

Notebook dùng một file chính: `notebooks/AHR_IDPS_L4_Training.ipynb`. Bộ mã
được notebook nạp là `dist/AHR-IDPS-Colab-AI.zip`. Notebook tự mount Google
Drive, tải dataset Kaggle khi được bật, train, đánh giá và lưu artifact vào
`MyDrive/AHR-IDPS/`.

## 1. Chuẩn bị một lần

1. Tải hai file từ repository sang máy của bạn:

   - `notebooks/AHR_IDPS_L4_Training.ipynb`
   - `dist/AHR-IDPS-Colab-AI.zip`

2. Mở notebook bằng <https://colab.research.google.com/>.
3. Chọn **Runtime → Change runtime type → L4 GPU** (nếu tài khoản có L4).
4. Chạy tới cell cài đặt và upload đúng `AHR-IDPS-Colab-AI.zip` mới.
   Cell kiểm tra import trong một Python process mới; nếu lỗi, nó cài lại wheel
   không cache rồi kiểm tra lại. Chờ xuất hiện thông báo `CÀI ĐẶT XONG`.
5. Chọn **Runtime → Restart session**. Không chọn Delete runtime.
6. Sau restart, chạy từ cell **Khởi tạo sau restart** trở xuống; không chạy lại
   cell cài đặt và không Run all từ đầu. Cell này khởi tạo lại toàn bộ biến,
   kiểm tra GPU/CUDA và yêu cầu mount Google Drive của chính bạn.

Không thể upload trực tiếp vào Drive cá nhân từ máy phát triển này vì cần OAuth
của bạn. Notebook thực hiện việc đó trong phiên Colab, không cần gửi mật khẩu
cho tôi.

## 2. Dataset nào được dùng

Có hai đường dữ liệu, không trộn nhãn/schema một cách im lặng:

- **Train model triển khai AHR-IDPS:** tạo telemetry DVWA đã làm sạch từ máy lab
  rồi upload `events-colab.jsonl` (hoặc `colab-dataset.zip`). Đây là nguồn dùng
  để train Network, Log, Graph và Fusion cùng một contract.
- **Benchmark network công khai:** đặt `KAGGLE_HANDLE` trong notebook, ví dụ
  `mdalamintalukder/cicids2017`, rồi đặt `RUN_PUBLIC=True` ở cell benchmark kế
  tiếp. `owner/dataset` chỉ là tên mẫu, không phải nguồn tải. Giữ `PUBLIC_DATA=None`
  trước tải; biến này sẽ nhận đường dẫn dataset, không đặt thành `True`.
  CICIDS2017/CSE-
  CIC-IDS2018 được đọc theo chunks và lưu report riêng. Artifact có tên
  `CIC_BENCHMARK_ONLY_NOT_RUNTIME.json`, **không** được ném vào runtime 21
  feature của DVWA vì khác schema và khác miền dữ liệu.

Tạo telemetry DVWA trên máy chính:

```powershell
python scripts/prepare_colab_data.py `
  --input datasets/raw/events.jsonl `
  --output exports/colab-training `
  --exclude-conflicts
```

Chỉ upload file đã review. Không upload `.env`, cookie, token, password, PCAP
hoặc raw log chưa redact.

## 3. Thứ tự chạy trong notebook

Notebook mới có tiêu đề phần train rõ ràng. Nếu hiện chỉ có Kaggle CSV, chạy
**A1 → A2 → A3 → A4** sau setup. A3 mặc định `RUN_PUBLIC=True`,
`PUBLIC_ROUNDS=400`, `CAP_PER_CLASS=150000`; A4 hiển thị ảnh. Không cần chạy phần B
khi chưa có telemetry DVWA. Để train đủ bốn model của lab, chạy **B1 → B2 → B3**;
B2 mặc định `DVWA_ROUNDS=150`, `MAX_DVWA_EVENTS=500000`.

1. Kiểm tra GPU/driver và cài phiên bản thư viện cố định.
2. Giải nén source kit, cài thư viện, kiểm tra import trong process mới. Restart
   session, chạy cell Khởi tạo sau restart, kiểm tra `USE_CUDA: True`, mount Drive.
3. Tùy chọn tải benchmark Kaggle (`KAGGLE_HANDLE`, `RUN_PUBLIC`).
4. Upload telemetry DVWA; notebook kiểm tra nhãn, loại operational false label
   và chia train/validation/test theo `scenario_id` hoặc `campaign_id`.
5. Train OOF base models và Fusion:
   - Network: XGBoost histogram CUDA.
   - Log: Hashing384 + MLP/Isolation Forest (CPU).
   - Graph: causal single-event graph aggregation + MLP (CPU).
   - Fusion: XGBoost meta-model trên OOF scores (CUDA).
6. Train thêm Logistic Regression và Random Forest làm baseline, tính precision,
   recall, F1, FPR, ROC-AUC và PR-AUC trên test giữ riêng.
7. Xuất model, prediction, manifest, bảng CSV/JSON và biểu đồ PNG/SVG.
8. Tuỳ chọn bật `RUN_REMOTE=True` để mở endpoint inference qua ngrok; chỉ dùng
   token trong Colab Secrets, không dùng cho giám sát 24/7.

## 4. Cấu trúc kết quả trên Drive

Mỗi phiên có timestamp riêng, không ghi đè phiên cũ:

```text
MyDrive/AHR-IDPS/
├── source-snapshots/YYYYMMDD-HHMMSS/  # source kit + notebook + requirements
├── datasets/events-colab.jsonl        # telemetry đã canonical/redact
└── runs/dvwa-YYYYMMDD-HHMMSS/
    ├── network-xgboost.json
    ├── log-ai.joblib
    ├── graphsage-security-event.joblib
    ├── fusion-hybrid-xgboost.json
    ├── logistic_regression.joblib
    ├── random_forest.joblib
    ├── comparison.csv / comparison.json / comparison.png
    ├── predictions.jsonl
    ├── manifest.json
    ├── training-history.json
    ├── preprocessing.json / preprocessing.csv
    ├── train-feature-summary.csv
    ├── train-feature-correlation.csv
    ├── evaluation-metrics.csv
    ├── figures-index.json
    ├── figures/                       # PNG + SVG để chèn vào báo cáo
    └── gpu-samples.json
```

`manifest.json` chứa SHA-256 input/artifact, số mẫu từng split, nhóm split,
thiết bị yêu cầu và thời gian train. Đây là file cần trích dẫn trong báo cáo.

Các run CIC được lưu tại `runs/cic-YYYYMMDD-HHMMSS/`, có `report.json`, model
`CIC_BENCHMARK_ONLY_NOT_RUNTIME.json`, bảng `test-predictions.csv`,
`split-indices.csv` và cùng cấu trúc ảnh/lịch sử train. Tên model này nhắc rằng
nó chưa tương thích runtime DVWA. `figures-index.json` chứa chú thích và SHA-256
của từng ảnh; gallery notebook không hiển thị hết mọi ảnh để tránh output quá dài.

### Các hình được xuất

| Nhóm | Nội dung và ý nghĩa |
|---|---|
| Tiền xử lý | Số dòng đã đọc, hợp lệ, lấy mẫu, loại trùng/mâu thuẫn; class counts trước/sau chọn mẫu |
| Chia tập | Số benign/attack trong train, validation, test |
| EDA | Tương quan tối đa 12 cột không hằng, histogram 6 đặc trưng từ mẫu train tối đa 5.000 dòng |
| Chất lượng CIC | Missing/nonfinite cells trước fillna(0); histogram hiển thị signed log, không thay đổi input train |
| Loss XGBoost | Train/validation logloss theo boosting round; train/validation accuracy và ROC-AUC |
| Loss MLP | Train loss theo epoch của Log, Graph và Graph baseline; cả OOF và final |
| Đánh giá | Confusion matrix từng model, ROC, Precision–Recall, score distributions, reliability diagram |
| Giải thích | Feature importance theo gain của Network XGBoost (không phải SHAP hay quan hệ nhân quả) |
| So sánh | F1, FPR và bảng precision/recall/AUC; DVWA có 8 phương pháp, CIC hiện chỉ Network XGBoost |

Không tự tạo validation loss cho MLP: implementation hiện tại chỉ lưu train
loss. Random Forest, Isolation Forest và rule-only không có loss theo epoch.
Giá trị `pr_auc` trong code dùng **average precision (AP)**. Dataset CIC mất cân
bằng mạnh, vì vậy cần đọc PR/AP và FPR cùng confusion matrix thay vì chỉ accuracy.
Threshold cố định trước test: .5 cho base/baseline, .55 cho weighted/Fusion.
Test không được dùng trong `evals` để theo dõi train hoặc chọn hyperparameter.

EDA preview A2 chỉ đọc file đầu; thống kê khi benchmark mới đọc tất cả CSV.
EDA tương quan/phân bố dùng mẫu train có seed, không phải toàn dữ liệu.
CIC chia theo hàng sau khi loại exact duplicates, vẫn có thể lạc quan vì
near-duplicates/flow tương quan; DVWA chia theo campaign/scenario, dùng OOF cho Fusion.
Không coi metric CIC là chất lượng phát hiện thực tế trên DVWA.

## 5. GPU L4 và CPU kết hợp

Notebook dùng GPU ở nơi thuật toán hỗ trợ: XGBoost Network/Fusion. Log AI,
Graph AI và baseline sklearn chạy CPU theo đúng implementation hiện có. Không
được cấp phát tensor rỗng để làm đầy VRAM: việc đó không tăng chất lượng và có
thể gây OOM. Notebook lấy mẫu `nvidia-smi` mỗi giây vào `gpu-samples.json`.

Muốn tăng tải hữu ích, tăng dữ liệu gốc hoặc `cap_per_class`, sau đó mới tăng
`rounds`, `max_bin`/`max_depth` trong giới hạn RAM/VRAM. Chừa 10–15% headroom và
không chạy đồng thời nhiều thí nghiệm lớn. Không có cam kết mọi phiên Colab đều
cấp L4 hoặc dùng đúng 100% VRAM.

## 6. Kiểm tra hoàn tất

Run được xem là hợp lệ khi:

- cell GPU báo đúng GPU và XGBoost không fallback CPU;
- `comparison.csv`, `manifest.json`, bốn model và `gpu-samples.json` tồn tại;
- `manifest.json` ghi `counts` của cả train/validation/test và hai lớp;
- thư mục `source-snapshots/...` xuất hiện trong Drive;
- không có secret trong snapshot hoặc `predictions.jsonl`.

Nếu gặp `ImportError: cannot import name '_slice' from numpy._core.umath`,
NumPy có thể bị trộn giữa bản trên đĩa và bản đã nạp trong kernel sau `pip install`.
Không dùng `importlib.reload` hoặc xóa `sys.modules` để sửa NumPy đang chạy.
Dùng notebook/ZIP mới, chờ cell cài đặt hoàn tất, chọn **Runtime → Restart
session**, rồi chạy từ **Khởi tạo sau restart**. Bản mới lưu trạng thái setup
trên đĩa để không phụ thuộc các biến đã mất sau restart. Nếu cell kiểm tra Python
con vẫn lỗi sau khi tự cài lại wheel, giữ lại output pip/probe để chẩn đoán; không
tiếp tục train. Nếu XGBoost báo không có CUDA, kiểm tra lại runtime L4 và
`xgboost.build_info()` trước khi train.

## 7. Đưa model về lab

Không ghi đè mù artifact cũ. Tải cả thư mục run và dùng scorer v2:

```python
from ai.colab.scorer import BundleScorer
scorer = BundleScorer('downloaded-bundle-folder', device='cpu')
results = scorer.score(canonical_events)
```

Khi cần dùng Colab trực tiếp, bật endpoint tùy chọn và đặt token vào
`secrets/colab_token` ở lab. Colab mất kết nối thì bridge phải giữ pending và
không tự tạo score/incident giả.
