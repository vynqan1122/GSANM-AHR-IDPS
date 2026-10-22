# Kiểm thử phần train và hình báo cáo — 20/10/2026

Notebook có 25 cell, 13 cell Python hợp lệ, không lưu output/secret. Bộ ZIP đã
được tái tạo với module `ai/colab/visuals.py` và hướng dẫn mới.

`python -m pytest ai/colab/tests -q`: **14 passed**, một cảnh báo deprecation từ
Starlette/AnyIO. Test tích hợp dùng CSV tổng hợp được đánh dấu là fixture; kiểm
tra nhãn mâu thuẫn, exact duplicates, số dòng sau tiền xử lý, split không trùng,
validation logloss khớp dự đoán thật, metrics và checksum của PNG/SVG.

Đã chạy pipeline DVWA trên file export hiện có:

```powershell
python -m ai.colab.train `
  --input exports/colab-smoke-20261019/events-colab.jsonl `
  --output output/colab/visual-training-20261020 `
  --device cpu --rounds 3
```

340 sự kiện; train/validation/test là 185/87/68 theo scenario groups. Kết quả có
47 PNG và 47 SVG, bảng EDA/evaluation, loss các fold/final và đủ artifact.
Đã mở xem loss, correlation, ROC/PR; không thấy chữ/legend bị cắt. Checksum ảnh
đạt, BundleScorer nạp lại bundle và chấm ba sự kiện thành công.

Lần chạy CPU ba rounds chỉ kiểm tra tích hợp và xuất kết quả. Một số MLP báo
ConvergenceWarning khi chạm max_iter=600; chưa thể coi là đã hội tụ. Dataset ít,
chia scenario không loại mọi tương quan giữa campaign, không dùng kết quả này
để khẳng định hiệu năng trên dữ liệu mới hoặc chất lượng production.

Chưa chạy GPU L4/Colab, chưa tải đầy đủ CICIDS2017 hoặc mount Drive tài khoản
người dùng. Biểu đồ Kaggle đầy đủ sẽ được tạo khi người dùng chạy A3/A4 trong
Colab. MLP validation loss không có trong implementation hiện tại; không tự vẽ
đường giả. Random Forest/Isolation Forest không có epoch loss.
