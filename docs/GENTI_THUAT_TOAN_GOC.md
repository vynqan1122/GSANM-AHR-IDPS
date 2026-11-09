**GenTI nguyên bản và phạm vi áp dụng trong AHR IDPS**

Nguồn phương pháp là bài “GenTI: Benchmarking LLMs for Autonomous IDPS Rule Generation for Unseen Attacks”, Hassan Jalil Hadi, Rehana Yasmin và Ali Shoker, arXiv:2606.05844, công bố ngày 04/06/2026. Phần này được đối chiếu với Algorithm 1, các mục IV–VI của bản gốc và bản dịch tiếng Việt. GenTI là một quy trình tạo, sửa và kiểm chứng quy tắc có sử dụng LLM; GTI là corpus phục vụ quy trình đó. Một lần gọi mô hình sinh được chuỗi rule chưa đồng nghĩa với hoàn thành toàn bộ GenTI.

**Dữ liệu phục vụ phương pháp gốc**

GTI tổ chức khoảng 150 nghìn quy tắc IDPS và 50 nghìn quy tắc YARA. Nhóm IDPS tổng hợp chữ ký Snort, Suricata và nguồn cộng đồng; nhóm YARA bổ sung các mẫu nhận diện ở cấp payload. Đơn vị học là quy tắc gắn ngữ cảnh, yêu cầu và chú giải, không phải một dòng sự kiện mạng. Vì vậy, số sự kiện thu thập trong AHR-IDPS không được dùng thay cho số mẫu rule của GTI, và quy mô GTI không được ghi thành quy mô dữ liệu đã huấn luyện của đề tài.

Quy trình xây dựng corpus bắt đầu bằng thu thập, chuẩn hóa và loại trùng. Bộ phân tích tách header, chiều luồng, giao thức, cổng, điều kiện payload của rule IDPS; với YARA, cấu trúc điều kiện được biểu diễn bằng cây cú pháp. Từ đó hệ thống rút IoC, CVE, CWE và họ mối đe dọa, tra OTX, lưu thông tin theo STIX/TAXII, ánh xạ ATT&CK và D3FEND, rồi gắn thuộc tính, sự kiện, tag, galaxy và nguồn gốc qua MISP. Các trường chất lượng, mức nghiêm trọng và độ tin cậy đi cùng thông tin xuất xứ để hỗ trợ chọn lọc mẫu.

Paper còn sử dụng LLM trong làm giàu corpus: Qwen 7B tạo CTI tổng hợp khi thiếu IoC, LLaMA 3.2 7B hỗ trợ xây dựng prompt, DeepSeek 7B hỗ trợ diễn đạt và phần giải thích. CTI tổng hợp phải được nhận diện đúng là nội dung sinh, không tự trở thành tình báo đã xác minh. Lược đồ GTI có 48 trường được phân nhóm theo thông tin quy tắc, bối cảnh và chú giải. Sản phẩm cuối cùng ghép yêu cầu đầu vào, ngữ cảnh, cấu trúc rule và các thông tin phản hồi, cho phép mô hình học cả sinh rule và kiểm tra rule.

**Huấn luyện trong paper**

Corpus được chia phân tầng 80% train, 10% validation và 10% test, xét nguồn rule, ATT&CK, mức nghiêm trọng và độ khó; một rule chỉ thuộc một phân vùng. Cách chia này không tự bảo đảm toàn bộ họ tấn công của test vắng mặt trong train. Khi đánh giá khả năng tổng quát hóa theo họ, cần một thiết kế tách nhóm riêng và công bố rõ tiêu chí đó.

CoT trong phương pháp gốc bổ sung phần diễn giải logic phát hiện và liên hệ ngữ cảnh vào ví dụ học. CoVe bổ sung ví dụ xác minh cú pháp, logic và dương tính giả. Khi triển khai, những giải thích có thể kiểm tra phải gắn với evidence, lỗi parser và kết quả replay; một lời giải thích trôi chảy không thay được kết quả chạy engine.

Chương trình học gồm bốn giai đoạn nối tiếp: đầu tiên học rule đơn giản và header cơ bản; sau đó thêm ngữ cảnh CTI và giải thích đơn giản; tiếp theo tăng các ví dụ khó định hướng kiểm chứng CoVe; cuối cùng học trên toàn dải độ khó. Trọng số ở cuối giai đoạn trước khởi tạo cho giai đoạn sau. Độ khó xét số ràng buộc header và payload, mức phong phú CTI và ví dụ suy luận hay xác minh đi kèm.

Thí nghiệm của tác giả dùng DeepSeek 7B, QLoRA, tám GPU NVIDIA A100, tốc độ học $10^{-4}$ và dừng sớm theo điểm validation. Đây là cấu hình của paper. Cấu hình Qwen chạy với GPU L4 trong đề tài là lựa chọn triển khai riêng; không được mô tả như đã tái lập nguyên vẹn thí nghiệm tám A100.

**Đầu vào và các biến của thuật toán**

Gọi $P$ là yêu cầu của nhà phân tích; $S$ là tập payload đại diện; $\mathcal{C}$ là kho CTI. Quy tắc ở lần lặp thứ $k$ ký hiệu $r_k$; ngữ cảnh đe dọa là $c_k$; phần diễn giải đi kèm được ký hiệu $C_k$. Hai ký hiệu $\mathcal{C}$ và $C_k$ chỉ những đối tượng khác nhau. Đầu ra là cặp quy tắc đã qua xác minh $\hat r$ và ngữ cảnh $\hat c$.

**Trình tự đầy đủ của Algorithm 1**

1. BuildPrompt xử lý $P,S$ để tạo prompt có cấu trúc, prompt theo yêu cầu người dùng và tập đặc trưng nổi bật $F_0$. Đặc trưng có thể mô tả giao thức, hướng luồng và dấu hiệu payload cần phát hiện. Đây là bước chuyển yêu cầu nghiệp vụ thành đầu vào mà mô hình có thể dùng.

2. LLMGenerate nhận hai prompt cùng $F_0$, tạo bản rule đầu tiên $r_0$ và diễn giải $C_0$. Bản rule này mới là ứng viên. Hành động alert, drop hoặc reject trong chuỗi ký tự chưa chứng minh sensor đã nạp hay thực thi được rule.

3. MapCTI đối chiếu $r_0,S$ với kho $\mathcal{C}$ để tạo $c_0$. Ngữ cảnh giúp kiểm tra rule đang phát hiện hành vi nào, liên quan kỹ thuật hay lỗ hổng nào và vì sao nội dung đó phù hợp. Liên kết CTI phải có căn cứ nguồn, không suy ra một mã ATT&CK chỉ từ tên gọi tấn công.

4. Khởi tạo $k=0$. Khi cặp rule và ngữ cảnh chưa hội tụ, EvaluateRule đánh giá $r_k$ trên mẫu thử và tạo vector $M_k$. Algorithm 1 liệt kê DR, FPR, CPU và độ bao phủ. Phần mô tả của paper yêu cầu lưu lượng độc hại lẫn lành tính; nếu chỉ có tấn công, không thể xác định FPR.

5. Nếu MeetsThresholds chấp nhận $M_k$, thoát vòng lặp. Nếu chưa đạt, BuildFeedback biến lỗi và các chỉ số thành phản hồi tập trung: bỏ sót mẫu nào, nhầm mẫu lành nào hoặc ràng buộc nào chưa phù hợp. LLMRefine dùng prompt ban đầu, diễn giải hiện tại và phản hồi mới để tạo $r_{k+1},C_{k+1}$. UpdateCTI cập nhật ngữ cảnh theo rule mới, tăng $k$ rồi quay lại đánh giá.

6. Sau vòng tinh luyện, CoVe kiểm tra theo thứ tự SyntacticOK, LogicOK và FPAnalysisOK. Cổng thứ nhất yêu cầu cú pháp được chấp nhận. Cổng thứ hai xét ý định phát hiện và tính nhất quán với ngữ cảnh. Cổng thứ ba kiểm tra nguy cơ dương tính giả trên traffic lành. Trong mã giả Algorithm 1, bất kỳ cổng nào thất bại đều trả RejectRule và kết thúc.

7. Nếu vượt cả ba cổng, gán $\hat r=r_k$, dùng BuildContext tạo $\hat c$ từ diễn giải và CTI, rồi trả về cặp kết quả. Ngữ cảnh đầu ra gồm giải thích, báo cáo liên hệ MITRE và hướng dẫn triển khai ngắn. Việc đưa rule vào vị trí chặn của một hạ tầng cụ thể cần cơ chế triển khai riêng.

**Mã giả diễn giải tương ứng với paper**

Đầu vào: yêu cầu P, payload S, kho CTI.

BuildPrompt(P,S) → P_struct, P_user, F(0).

LLMGenerate(P_struct,P_user,F(0)) → r(0), C(0).

MapCTI(r(0),S,kho CTI) → c(0); đặt k = 0.

Lặp khi cặp (r(k),c(k)) chưa hội tụ:

– EvaluateRule(r(k),S) → M(k).

– Nếu MeetsThresholds(M(k)), thoát vòng lặp.

– BuildFeedback(M(k)) → F(k+1).

– LLMRefine(P_struct,P_user,C(k),F(k+1)) → r(k+1), C(k+1).

– UpdateCTI(r(k+1),kho CTI) → c(k+1); tăng k.

Sau vòng lặp: nếu SyntacticOK sai → RejectRule.

Nếu LogicOK sai → RejectRule; nếu FPAnalysisOK sai → RejectRule.

Ngược lại trả r(k) và BuildContext(C(k),c(k)).

Mã giả trên giữ nguyên các nhánh quyết định của Algorithm 1. Phần diễn giải trong paper có đề cập việc quay lại tinh luyện khi kiểm chứng thất bại, nhưng Algorithm 1 không vẽ nhánh quay lại đó mà trả RejectRule. Nếu xây dựng cơ chế thử lại sau CoVe, cần công bố đó là lựa chọn triển khai. Paper không chỉ rõ ngưỡng số, số vòng tối đa, thời gian chờ hay định nghĩa hội tụ có thể thực thi; các giới hạn này phải được bổ sung và ghi rõ trong một hệ thống vận hành.

**Một ví dụ để đọc thuật toán**

Ví dụ minh họa giả định, không phải kết quả đo của AHR-IDPS: yêu cầu là phát hiện một mẫu payload script trong truy vấn của endpoint thử nghiệm. Bộ mẫu có 10 request tấn công và 10 request lành. Rule đầu tiên dùng dấu hiệu quá rộng nên bắt 10 request tấn công nhưng nhầm 4 request lành: TP = 10, FN = 0, FP = 4, TN = 6; DR = 100% và FPR = 40%. Khả năng bắt đủ tấn công trong ví dụ này chưa đủ để chấp nhận rule.

Phản hồi cho mô hình nêu rõ bốn request bị nhầm và yêu cầu ràng buộc endpoint, hướng luồng và nội dung phù hợp hơn. Rule sửa lại bắt 9 request tấn công và không bắt request lành: TP = 9, FN = 1, FP = 0, TN = 10; DR = 90%, FPR = 0%. Mẫu tấn công còn bỏ sót phải được giải thích hoặc dùng để tinh luyện tiếp theo chính sách đã công bố. Không thể kết luận rule tốt chỉ vì FPR giảm; ngưỡng chấp nhận phải xét cả DR.

Tiếp đến engine kiểm tra cú pháp, người hoặc bộ xác minh kiểm tra logic với evidence và CTI, rồi replay benign để kiểm tra FP. Chỉ khi ba cổng đều đạt mới có rule đã xác minh. Đối với AHR-IDPS, rule còn đi qua vòng đời Candidate → kiểm chứng native → Shadow → Active và enforcement tại gateway. Phần vòng đời này được trình bày như sự bổ sung của hệ thống.

**Các công thức đánh giá trong paper**

Với $N$ rule, $\mathbf{1}\{\cdot\}$ là hàm chỉ báo. Syntax Accuracy là tỷ lệ rule được parser của engine chấp nhận:

$$SA=\frac{1}{N}\sum_{i=1}^{N}\mathbf{1}\{ParseOK(\hat r_i)\}.$$

Semantic Similarity đối chiếu tập trường $F$ như giao thức, chiều, cổng, flow, content và action. Đây là tỷ lệ trường phù hợp với rule tham chiếu, không phải độ tương đồng cosine giữa hai câu:

$$SS_i=\frac{1}{|F|}\sum_{f\in F}\mathbf{1}\{f(\hat r_i)=f(r_i)\},\qquad SS=\frac{1}{N}\sum_{i=1}^{N}SS_i.$$

CTI Coverage dùng Jaccard giữa tập kỹ thuật ATT&CK chuẩn $T_i$ và tập dự đoán $\hat T_i$:

$$CC_i=\frac{|T_i\cap\hat T_i|}{|T_i\cup\hat T_i|},\qquad CC=\frac{1}{N}\sum_{i=1}^{N}CC_i.$$

Paper không quy định rõ trường hợp cả hai tập rỗng. Khi triển khai phải công bố cách xử lý mẫu thiếu chú giải; không mặc nhiên ghi độ bao phủ hoàn hảo cho dữ liệu không có CTI chuẩn.

Hiệu quả phát hiện và dương tính giả được đo bằng replay có nhãn:

$$DR=\frac{TP}{TP+FN},\qquad FPR=\frac{FP}{FP+TN}.$$

$$SE=\alpha DR+(1-\alpha)(1-FPR),\qquad \alpha=0.5.$$

Điểm tổng hợp trong công thức (8) của paper là:

$$CS=0.2SA+0.3SS+0.2MC+0.3SE.$$

Ký hiệu MC ở công thức tổng hợp không thống nhất với CC được định nghĩa trước đó. Có thể hiểu đây là thành phần độ bao phủ CTI/MITRE, nhưng đó là diễn giải; báo cáo giữ nguyên ký hiệu gốc và nêu rõ điểm chưa thống nhất. CPU được theo dõi riêng, không xuất hiện như một số hạng trong SE hay CS. Khi thiếu chuẩn CTI, rule tham chiếu hoặc replay có nhãn, chưa đủ căn cứ tính đầy đủ CS.

**Ranh giới giữa paper và kết quả của đề tài**

Trong AHR-IDPS, LLM fine-tune sinh candidate; bộ kiểm chứng native đánh giá trước khi cho phép đi tiếp. Shadow quan sát đối sánh trước khi Active; Active chỉ có tác dụng chặn khi tầng enforcement nhận đúng rule và áp dụng trên đường request. Suricata phát alert ở vai trò IDS khác với gateway từ chối request ở vai trò IPS. Cần dùng evidence về request, rule, trạng thái áp dụng và phản hồi gateway để chứng minh hành động chặn, không chỉ dùng nhãn Active trên dashboard.

Việc AI chọn evidence và benign là một cơ chế chọn mẫu của ứng dụng. Nhãn do AI suy ra phải được ghi nguồn và độ bất định; một mẫu được mô hình gọi là benign chưa phải ground truth độc lập. Các cổng xác minh, nguồn CTI, vòng lặp sửa rule và số liệu native phải được thể hiện theo đúng mức thực hiện; không ghi rằng đã tái lập toàn bộ GenTI nếu mới triển khai một phần quy trình.

OOF ở mục 5.4 là phương pháp tạo dự đoán ngoài tập huấn luyện cho tầng Fusion của đề tài, không phải bước trong Algorithm 1 của GenTI. OOF hỗ trợ hạn chế rò rỉ khi huấn luyện bộ kết hợp phân loại. GenTI học và kiểm chứng quy tắc. Hai bài toán có thể phối hợp nhưng cần dataset, nhãn và cách đánh giá riêng. Những biểu thức chọn mẫu, Shadow và điều kiện Active dưới đây mô hình hóa AHR-IDPS, không phải công thức do tác giả GenTI công bố.
