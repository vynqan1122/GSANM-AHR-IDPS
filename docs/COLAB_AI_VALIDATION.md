# Kiểm thử Colab AI v2 ngày 19/10/2026

## Đã thực hiện trên máy local

- 27 unit/contract/regression tests đạt: navigation sạch không tự tạo incident; cùng IP có
  query đáng ngờ/rule/status lỗi vẫn được phân tích; JSON decode và feature order;
  marker/password redaction; operational attack label exclusion; quarantine
  conflicting labels có flag; group-disjoint split; remote IDs/finite score
  validation; endpoint Bearer token; XGBoost named input; notebook AST.
- Export hiện có có 2 event_id với nhãn mâu thuẫn. Mặc định load từ chối; smoke
  run dùng flag --exclude-conflicts, loại hai event chứ không chọn nhãn. Sau
  dedup/exclusion còn 340 event; không thay đổi DB hay raw dataset gốc.
- Train thật toàn bộ 4 model trên CPU với 5 XGBoost rounds: train185,
  validation87, test68; 3-fold OOF cho Fusion. Wall time đo khoảng20,96 giây
  trên máy local, không bao gồm cài dependency. Một số MLP graph có
  ConvergenceWarning sau600 iterations: đây chưa phải model đủ chất lượng deploy.
- Lưu/load BundleScorer thành công; batch8 canonical events trả score; endpoint
  trong TestClient với bundle thật trả HTTP200 sau xác thực. Không mở tunnel public.
- Native CIC CSV buổi sáng thứ Năm (170.366 flow đầu vào) được đọc chunk thực,
  cap1000/class và dedup còn2.652 mẫu để smoke benchmark CPU5 rounds; report
  giữ riêng và marked deployable=false. Không tuyên bố đã tải/train full CIC2017/2018.
- Synthetic CUDA smoke: 50.000x21 float32 samples, XGBoost5 rounds; actual
  device=cuda:0 trên RTX3050 Laptop4096MiB. Đây chỉ xác nhận đường CUDA hoạt động,
  không là bằng chứng train L4 hoặc detection quality.
- Compose Colab overlay parse hợp lệ với endpoint/token-file giả dùng cho
  validation; không in DB credentials. Token/endpoint thật chưa được cấp.

Các bảng/PNG smoke nằm ở experiments/comparison/colab-v2-smoke-20261019-b/.
Do bộ test nhỏ và chứa telemetry legacy từ runner trước đây chưa chắc đã
reach challenge, không lấy F1 cao trong smoke làm kết quả nghiên cứu cuối.
Network5-round smoke có FPR1.0, minh họa rằng pipeline chạy không đồng nghĩa
model tốt. Không tự thay thế artifact active bằng các model này.

## Chưa thực hiện được trong tài khoản người dùng

- Chưa truy cập Google Colab/Drive, chưa cấp L4 hoặc đo24GB VRAM L4.
- Chưa tải full CICIDS2017/CSE-CIC-IDS2018 trong phiên này.
- Chưa chạy ngrok public, chưa đo Internet roundtrip/Colab timeout thực tế.
- Docker daemon không hoạt động lúc kiểm thử, nên chưa rebuild/start bridge,
  chưa truy PostgreSQL/Redis live hoặc kiểm tra đăng nhập mới trên dashboard.
- Không xóa incident/alert lịch sử, không whitelist IP chủ máy, không bật
  containment, không chỉnh sửa hệ thống LLM riêng.

## Bằng chứng được tạo khi chạy notebook thật

GPU actual/USE_CUDA, manifest SHA-256, group split/OOF IDs, measured training
wall time, comparison.csv/json/png, predictions.jsonl và gpu-samples.json.
Theo dõi CUDA allocation hữu ích; không có dummy allocation để quảng cáo100%
VRAM. Giữ headroom thay cố tình OOM runtime.
