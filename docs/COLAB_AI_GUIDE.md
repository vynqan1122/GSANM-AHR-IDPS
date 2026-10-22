# Train AHR-IDPS legacy trên Google Colab L4

Runbook tuần tự đầy đủ, bao gồm snapshot mã nguồn và lưu dataset đã làm sạch vào
Google Drive: [COLAB_FULL_TRAIN_RUNBOOK.md](COLAB_FULL_TRAIN_RUNBOOK.md).

Notebook có mục **A3 — TRAIN NETWORK TỪ CICIDS2017** (mặc định bật) và **B2 —
TRAIN NETWORK + LOG + GRAPH + FUSION DVWA**. Các mục A4/B3 hiển thị PNG trực
tiếp; toàn bộ PNG/SVG, training-history.json, EDA và evaluation CSV được lưu
trong thư mục run trên Drive. MLP hiện chỉ có train loss; XGBoost có cả train/
validation logloss, accuracy, ROC-AUC theo round. Test không được dùng trong evals.

Notebook: `notebooks/AHR_IDPS_L4_Training.ipynb`. Source kit:
`dist/AHR-IDPS-Colab-AI.zip`. Phần LLM riêng ở llm-system không bị thay đổi.

## 1. Chọn dữ liệu lớn hơn

Hai nguồn có mục đích khác nhau, không trộn schema rồi deploy mù:

| Nguồn | Quy mô tham khảo | Dùng cho |
|---|---|---|
| Full CICIDS2017 CSV | Khoảng 2,8 triệu flow, nhiều loại attack | Benchmark Network native CIC |
| CSE-CIC-IDS2018 CSV | Hàng chục triệu flow tùy bản phân phối | Benchmark lớn hơn, cần RAM/đĩa |
| Telemetry DVWA có nhãn | Khởi đầu 20.000–100.000 request gốc, nhiều ngày/session | Bộ Network/Log/Graph/Fusion triển khai |

Chỉ file Thursday WebAttacks có 2.180 attack, trong đó SQLi chỉ 21 mẫu.
Tải các ngày khác làm tăng network attacks nói chung, không tự tăng số SQLi/XSS
độc lập. Không oversample trước split để giả tăng diversity.

Nguồn gốc: https://www.unb.ca/cic/datasets/ids-2017.html và
https://www.unb.ca/cic/datasets/ids-2018.html. Tìm bản CSV trên Kaggle bằng
https://www.kaggle.com/datasets?search=CICIDS2017 hoặc CSE-CIC-IDS2018; chọn
handle owner/dataset thực từ trang của bản bạn tải. Notebook dùng kagglehub
download/cache và tạo SHA-256/provenance từng CSV. Không tự dùng tài khoản Kaggle
của bạn hoặc tải về hàng GB khi chưa chọn nguồn trong notebook.

`public_benchmark.py` đọc chunks 50k, reservoir tối đa 150k mỗi nhãn gốc. Với đủ
class, có thể giữ trên một triệu mẫu; tăng cap khi RAM runtime cho phép. Loại
exact duplicate trước split, loại conflicting fingerprint. Random split vẫn có
thể lạc quan với correlated/near-duplicate flow: ghi rõ giới hạn. Report public
được lưu riêng và model tên CIC_BENCHMARK_ONLY_NOT_RUNTIME.json không thể coi là
model 21 feature của runtime. Chưa adapter flow CSV sang log/syscall/graph.

## 2. L4 và yêu cầu sử dụng VRAM

L4 có VRAM danh định 24 GB, Colab có thể cấp GPU khác tùy gói/quota. Chọn
Runtime → Change runtime type → L4, sau đó notebook kiểm tra GPU actual và
XGBoost USE_CUDA. Trainer từ chối silent CPU fallback khi device=cuda.

Không có cách hữu ích buộc các model hiện tại sử dụng đúng 100% VRAM. Chiếm
VRAM rỗng không tăng throughput hoặc chất lượng và làm dễ OOM. XGBoost dùng
histogram CUDA và QuantileDMatrix, chỉ cấp phát theo data/cây. Log IF/MLP và
Graph aggregation+MLP là sklearn CPU, không thể chuyển GPU bằng biến CUDA.
Notebook đo nvidia-smi theo giây và lưu gpu-samples.json, không cam kết mức dùng.

Để tăng tải hữu ích: thêm mẫu gốc/cột hợp lệ, tăng cap_per_class, num_boost_round,
max_bin/max_depth sau validation; theo dõi RAM/VRAM, giữ headroom 10–15% nếu tăng
workload. Tăng rounds chủ yếu tăng thời gian, không bảo đảm tăng VRAM. Không tăng
độ phức tạp chỉ để đầy VRAM; không chạy hai experiment lớn đồng thời trên L4.

## 3. Chuẩn bị telemetry local để train cả bốn model

Chạy export schema mới trong backend sau rebuild (dùng cùng Compose overlays của
lab), hoặc `collect_dvwa_training_dataset.ps1`/campaign như tài liệu hiện có.
Exporter nay giữ port/http/network/process/file đầy đủ. Collection traffic.py cũ
vẫn có giới hạn login; ưu tiên campaign có đăng nhập trong
`docs/dvwa_dataset_campaign.md`, review endpoint reached/outcome trước train.

```powershell
python scripts/prepare_colab_data.py --input datasets/raw/events.jsonl --output exports/colab-20261019
```

Script loại nhãn attack sai trên login/setup/health/navigation; không sửa nhãn
âm thầm sang benign. Nó chỉ xuất canonical allowlist, bỏ raw logs, cookie, token,
password, marker URI và cmdline. Vẫn còn IP/URI/rule name: review trước upload
vào Drive cá nhân. Không zip toàn bộ repository/.env/PCAP.

Nếu báo conflicting event labels: mặc định dừng. Review nhãn theo event_id;
nếu chưa có ground truth, có thể loại **cả event mâu thuẫn** một cách tường minh
bằng `--exclude-conflicts`. Manifest ghi số bị loại, không chọn nhãn theo ý model.

Upload `exports/.../colab-dataset.zip` khi notebook hỏi telemetry. Có >=10
scenario/campaign groups, mỗi train/validation/test cần cả hai lớp. Dataset quá
nhỏ/không có nhãn sẽ báo lỗi thay tự tạo sample giả. Những log khác sensor của
cùng request nên giữ cùng scenario/campaign. Có thể bổ sung campaign_id để chia
theo whole day/session; loader ưu tiên campaign_id trên scenario_id.

## 4. Mở và chạy notebook

Vào https://colab.research.google.com/ → File → Upload notebook → chọn ipynb.
Chọn L4. Chạy đến cell cài đặt và upload `AHR-IDPS-Colab-AI.zip` mới. Sau thông
báo `CÀI ĐẶT XONG`, chọn **Runtime → Restart session** rồi chạy từ cell **Khởi
tạo sau restart**; không chạy lại cell cài đặt/Run all từ đầu. Bản mới kiểm tra
fresh imports trong Python con, có repair wheel không cache nếu cần và chặn
kernel chưa restart để tránh lỗi NumPy `_slice`. Bộ mã trong kit không có
credential/data/model local. Mount Drive bằng luồng Google của chính bạn.

Các phần notebook:

1. GPU actual, CUDA build, CPU thread budget.
2. Source kit upload và private Drive output.
3. Kaggle download/cache (tùy chọn), public native Network benchmark riêng.
4. Local telemetry upload, group split 60/20/20 theo scenario/campaign.
5. Train 3-fold out-of-fold base scores; train Fusion trên OOF; fit base final.
6. Test độc lập, bảng CSV/JSON, prediction từng mẫu và PNG so sánh.
7. Colab inference server qua HTTPS/token (tùy chọn).
8. Download bundle về máy, hoặc giữ Colab online để chấm AI.

Tham số notebook: public cap150k/class; local max_events500k; XGBoost150 rounds
(smoke-test có thể 5). Mọi scalar P/R/F1/FPR/AUC tính từ y_true/y_score, không
dùng API Experiments E1-E9 ước lượng của dashboard cũ.

## 5. Những model thực sự được train

| Model | Algorithm/contract | Device |
|---|---|---|
| network-xgboost.json | 21 network-v1 features chung với runtime | CUDA train |
| log-ai.joblib | Hashing384 redacted, IF+scaled MLP, anomaly_weight=0.5 | CPU |
| graphsage-security-event.joblib | Neighbor mean pooling + MLP, context current event | CPU |
| fusion-hybrid-xgboost.json | XGBoost meta trên 3-fold OOF scores, density=0 | CUDA train |
| Logistic Regression/Random Forest | Network baselines cùng split | CPU |

V2 sửa leakage bằng shared learning_event (bỏ marker/labels/old ai), JSON decode,
named feature schema. Không train MiniLM Transformer hay GraphSAGE GNN trainable.
Graph context v2 là một event causal để server remote và local scorer thống
nhất, không giả rằng một batch HTTP có đầy đủ graph window thời gian. Density
Fusion=0 cho cả train/serve. Các thuật toán này không đòi 24GB VRAM khi dataset
local ít; tập public native lớn giúp benchmark GPU, vẫn report riêng miền.

`manifest.json` có hash dataset/artifacts, split group IDs, OOF fold event IDs và
training wall time. `comparison.csv/png` so từng model, rule-only, weighted hybrid
và Fusion OOF trên cùng test. Threshold cố định .5 cho base, .55 cho hybrid.
Validation metrics nên dùng để thiết kế sau này; test không dùng feedback train.
Group split chưa loại được mọi near-duplicate payload giữa các campaign, cần
đánh giá holdout theo ngày/client/biến thể để kết luận mạnh hơn.

## 6. Kết nối dùng trực tiếp AI Colab khi lab đang chạy

Không thể dùng `localhost` của Colab như localhost máy nhà. Chọn cell RUN_REMOTE=True,
thêm `NGROK_AUTHTOKEN` trong Colab Secrets, notebook chạy FastAPI một GPU inference
tại một thời điểm, public HTTPS tunnel có Bearer token ngẫu nhiên. File colab_token
được tải riêng, không print token vào output. Tunnel URL cần cập nhật mỗi phiên.

Trên máy lab đặt file vào `secrets/colab_token`, không commit nó. Khởi động core,
sensors,pipeline,backend theo thứ tự cũ trước. Sau đó:

Compose bridge dùng `!override`, cần Compose>=2.24.4. Với Linux, process bridge
chạy UID/GID65532: cấp file token group-read cho GID65532 (chmod640, group65532)
và giữ thư mục secrets private; không đổi token thành world-readable để chữa lỗi.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start_colab_ai.ps1 `
  -Endpoint 'https://YOUR-SESSION.ngrok-free.app' `
  -TokenFile '.\secrets\colab_token'
```

Script build bridge image, dừng đúng ai-network/ai-log/graph-builder/fusion-engine
local để tránh cùng ghi score, bật colab-bridge và giữ incident/evidence local.
Không mở PostgreSQL/Redis ra Internet. Bridge gửi tối đa32 event/batch đã redact,
Colab trả bốn score cùng bundle_version. Local kiểm finite/range/IDs, ghi prediction
versioned rồi publish một message đủ scores cho Incident Engine. Nguồn model là
colab-*-v2; không ghi đè model JSON đang active của hệ thống cũ.

API có token, cap128 event/1MiB, trả429 nếu bận. Ngrok/Colab link qua mạng ngoài;
chỉ dùng tài khoản của bạn và dữ liệu đã review. Thời gian roundtrip khác inference
GPU; không lấy server_batch_ms làm latency packet. Colab disconnect là bình thường:
bridge báo degraded, không ACK mẫu lỗi và không bịa score attack; ba lần lỗi thì
thoát, pending còn đó. Khởi động lại cùng consumer để nhận pending. Không phù hợp
giám sát 24/7; nếu cần ổn định, download bundle và dùng CPU local scorer.

Khôi phục AI cũ: dừng colab-bridge bằng Compose overlay tương ứng rồi chạy
scripts/start_ai.ps1. Những log score v2 đã ghi vẫn là evidence lịch sử. Không
chạy lại local Fusion đồng thời với bridge vì nó sẽ re-fuse và ghi đè score.

## 7. Chạy model tải về trên CPU

Không ném mù artifact v2 vào thư mục model cũ: graph window và IF weighting khác.
Dùng đúng scorer versioned trong kit:

```python
from ai.colab.scorer import BundleScorer
scorer=BundleScorer('downloaded-bundle-folder',device='cpu')
results=scorer.score(canonical_events)
```

Scorer kiểm manifest checksum và load trusted joblib. Có thể nối scorer này với
bridge provider local khi cần vận hành lâu dài; bản này cung cấp HTTP Colab path
và offline CPU method, không tự đổi service architecture hay overwrite old models.
Chép kèm code bundle/requirements version để tránh joblib load lỗi khác môi trường.

## 8. Giảm báo sai khi chính chủ đăng nhập

Nguyên nhân trước đây: Incident Engine tạo incident cho mọi prediction, kể cả
navigation. Code mới giữ raw log/prediction nhưng chỉ tạo incident nếu có rule
hoặc risk>=.5; clean GET/HEAD login/index/logout/instructions/... không query lạ,
status200/3xx, không severity/rule/process được xem là routine navigation.

Không whitelist IP server/localhost: cùng máy vẫn có thể gửi SQLi/bruteforce.
Login có query đáng ngờ, rule match, failed status hoặc POST body chưa kiểm
chứng vẫn đi đường phân tích bình thường. Không có đủ body/outcome để tuyên bố
mọi POST /login.php là benign. Các incident lịch sử và native sensor alerts
không bị tự xóa hoặc suppress: cần xem rule/SID cụ thể nếu vẫn báo sai.

Code context_score bỏ labels.scenario_id/attack_type hint; log representation
bỏ marker URI. Thay đổi này cần retrain/chạy bộ v2; model cũ chưa được tự replace.
Muốn áp dụng local correlation policy phải rebuild image ai-network (chứa
correlation) và restart incident-engine bằng cùng Compose overlays. Docker hiện
không chạy ở phiên kiểm thử này nên chưa tự rebuild/restart hay sửa DB cũ.

## 9. Kiểm thử và phạm vi

Các test local kiểm navigation vs malicious request cùng IP, redaction/JSON parity,
group split, operational label exclusion, finite remote output, XGBoost named
input và notebook AST. Smoke training CPU trên dataset thực xuất local kiểm
OOF, save/load bundle, bảng đo và endpoint auth (mock scorer). Đây không thay
chạy Colab L4, Kaggle full download, ngrok public hay Docker integration thật.

Trong phiên bàn giao không có quyền truy cập tài khoản Colab/ngrok cá nhân.
Không tuyên bố đã chạy L4 hoặc dùng 100% VRAM. Mở notebook và thực thi trong
tài khoản của bạn sẽ tạo GPU actual/VRAM samples, checksums và reports thật.
