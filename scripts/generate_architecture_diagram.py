from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "ahr-idps-model-overview.png"
WIDTH, HEIGHT = 2600, 1720

BG = "#F4F6F8"
INK = "#18232E"
MUTED = "#5B6875"
LINE = "#7A8793"
WHITE = "#FFFFFF"
LAB = "#2F6FB2"
SENSOR = "#16826C"
PIPELINE = "#B7791F"
AI = "#6D527C"
OPS = "#C4563A"
CONTROL = "#A63D40"

FONT_REGULAR = Path("C:/Windows/Fonts/segoeui.ttf")
FONT_BOLD = Path("C:/Windows/Fonts/segoeuib.ttf")


@dataclass(frozen=True)
class Node:
    key: str
    title: str
    body: str
    x: int
    y: int
    w: int
    h: int
    accent: str
    tag: str

    @property
    def left(self) -> tuple[int, int]:
        return self.x, self.y + self.h // 2

    @property
    def right(self) -> tuple[int, int]:
        return self.x + self.w, self.y + self.h // 2

    @property
    def top(self) -> tuple[int, int]:
        return self.x + self.w // 2, self.y


def font(size: int, *, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONT_BOLD if bold else FONT_REGULAR), size)


def wrap(draw: ImageDraw.ImageDraw, text: str, fnt: ImageFont.FreeTypeFont, width: int) -> list[str]:
    lines: list[str] = []
    for paragraph in text.split("\n"):
        words = paragraph.split()
        current = ""
        for word in words:
            candidate = f"{current} {word}".strip()
            if draw.textbbox((0, 0), candidate, font=fnt)[2] <= width:
                current = candidate
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
    return lines


def draw_node(draw: ImageDraw.ImageDraw, node: Node) -> None:
    draw.rounded_rectangle(
        (node.x, node.y, node.x + node.w, node.y + node.h),
        radius=8,
        fill=WHITE,
        outline="#C9D1D9",
        width=2,
    )
    draw.rounded_rectangle(
        (node.x, node.y, node.x + 12, node.y + node.h),
        radius=6,
        fill=node.accent,
    )
    draw.text((node.x + 28, node.y + 17), node.tag, font=font(20, bold=True), fill=node.accent)
    draw.text((node.x + 28, node.y + 46), node.title, font=font(30, bold=True), fill=INK)
    body_font = font(22)
    for index, line in enumerate(wrap(draw, node.body, body_font, node.w - 56)):
        draw.text((node.x + 28, node.y + 88 + index * 29), line, font=body_font, fill=MUTED)


def arrow_head(draw: ImageDraw.ImageDraw, start: tuple[int, int], end: tuple[int, int], color: str) -> None:
    x1, y1 = start
    x2, y2 = end
    size = 12
    if abs(x2 - x1) >= abs(y2 - y1):
        direction = 1 if x2 > x1 else -1
        points = [(x2, y2), (x2 - direction * size, y2 - 7), (x2 - direction * size, y2 + 7)]
    else:
        direction = 1 if y2 > y1 else -1
        points = [(x2, y2), (x2 - 7, y2 - direction * size), (x2 + 7, y2 - direction * size)]
    draw.polygon(points, fill=color)


def connector(
    draw: ImageDraw.ImageDraw,
    points: Iterable[tuple[int, int]],
    *,
    color: str = LINE,
    dashed: bool = False,
    width: int = 4,
    label: str | None = None,
    label_at: tuple[int, int] | None = None,
) -> None:
    pts = list(points)
    for start, end in zip(pts, pts[1:]):
        if not dashed:
            draw.line((start, end), fill=color, width=width, joint="curve")
            continue
        x1, y1 = start
        x2, y2 = end
        length = max(abs(x2 - x1), abs(y2 - y1))
        if length == 0:
            continue
        step = 20
        for offset in range(0, length, step):
            if (offset // step) % 2:
                continue
            ratio1 = offset / length
            ratio2 = min(offset + step, length) / length
            p1 = (round(x1 + (x2 - x1) * ratio1), round(y1 + (y2 - y1) * ratio1))
            p2 = (round(x1 + (x2 - x1) * ratio2), round(y1 + (y2 - y1) * ratio2))
            draw.line((p1, p2), fill=color, width=width)
    arrow_head(draw, pts[-2], pts[-1], color)
    if label and label_at:
        bbox = draw.textbbox((0, 0), label, font=font(18, bold=True))
        padding = 7
        x, y = label_at
        draw.rounded_rectangle(
            (x - padding, y - padding, x + bbox[2] + padding, y + bbox[3] + padding),
            radius=6,
            fill=BG,
        )
        draw.text((x, y), label, font=font(18, bold=True), fill=color)


def main() -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)

    draw.text((64, 42), "AHR-IDPS", font=font(54, bold=True), fill=INK)
    draw.text(
        (64, 106),
        "Luồng phát hiện xâm nhập lai Rule + AI và vai trò của từng node",
        font=font(30),
        fill=MUTED,
    )
    draw.line((64, 159, WIDTH - 64, 159), fill="#CBD3DC", width=2)

    connector(draw, [(1860, 78), (1935, 78)], color=LINE, width=4)
    draw.text((1950, 62), "Dữ liệu / sự kiện", font=font(20), fill=MUTED)
    connector(draw, [(2160, 78), (2235, 78)], color=CONTROL, dashed=True, width=4)
    draw.text((2250, 62), "Luật / phản ứng", font=font(20), fill=MUTED)

    columns = [
        (54, 430, "1  NGUỒN & LAB", LAB, "Traffic và hoạt động runtime thật"),
        (504, 430, "2  SENSOR", SENSOR, "Quan sát mạng, host và container"),
        (954, 430, "3  PIPELINE & DATA", PIPELINE, "Thu thập, chuẩn hóa và lưu trữ"),
        (1404, 520, "4  AI & CORRELATION", AI, "Chấm điểm, ghép chuỗi và sinh luật"),
        (1944, 602, "5  SOC & RESPONSE", OPS, "Hiển thị, điều tra và phản ứng"),
    ]
    for x, w, title, accent, subtitle in columns:
        draw.rounded_rectangle((x, 188, x + w, HEIGHT - 54), radius=8, fill="#E9EDF1")
        draw.rectangle((x, 188, x + w, 198), fill=accent)
        draw.text((x + 24, 218), title, font=font(25, bold=True), fill=accent)
        draw.text((x + 24, 253), subtitle, font=font(19), fill=MUTED)

    nodes = {
        node.key: node
        for node in [
            Node("client", "Người kiểm thử / Client", "Sinh traffic hợp lệ hoặc kịch bản pentest có ủy quyền.", 79, 315, 380, 145, LAB, "ENTRY"),
            Node("nginx", "Nginx Gateway", "Cổng duy nhất 127.0.0.1:8080; proxy DVWA, API và dashboard.", 79, 500, 380, 160, LAB, "INGRESS"),
            Node("dvwa", "DVWA + MariaDB", "Ứng dụng web cố ý có lỗ hổng và CSDL mục tiêu trong mạng nội bộ.", 79, 705, 380, 160, LAB, "LAB TARGET"),
            Node("runtime", "Docker / Linux Runtime", "Nguồn syscall, process, file, network và vòng đời container.", 79, 930, 380, 160, LAB, "RUNTIME"),
            Node("windows", "Wazuh Windows Agent", "Tùy chọn: gửi Security/System/Application event của Windows host.", 79, 1160, 380, 160, LAB, "OPTIONAL"),
            Node("suricata", "Suricata NIDS", "Phân tích HTTP, DNS, TLS, flow và signature; xuất EVE JSON.", 529, 315, 380, 160, SENSOR, "NETWORK"),
            Node("nginxlog", "Nginx Access Log", "Ghi request, status, latency, upstream và trace_id dạng JSONL.", 529, 520, 380, 160, SENSOR, "APPLICATION"),
            Node("falco", "Falco / eBPF", "Phát hiện shell, process bất thường trong web container, ghi file nhạy cảm và kết nối lạ.", 529, 750, 380, 175, SENSOR, "RUNTIME"),
            Node("wazuh", "Wazuh Manager", "SIEM manager: nhận Suricata, Falco, Docker và agent Windows; tạo alert.", 529, 990, 380, 175, SENSOR, "SIEM"),
            Node("collector", "Collector", "Tail bốn nguồn log, giữ checkpoint, chống đọc lặp và publish event raw.", 979, 350, 380, 175, PIPELINE, "INGEST"),
            Node("redis", "Redis Streams", "Event bus cho raw, normalized, predictions, incidents, rules và responses.", 979, 585, 380, 175, PIPELINE, "STREAM BUS"),
            Node("normalizer", "Normalizer", "Đưa event về schema chung, deduplicate, quarantine lỗi và gắn severity.", 979, 820, 380, 175, PIPELINE, "SCHEMA"),
            Node("postgres", "PostgreSQL", "Nguồn dữ liệu chuẩn: events, labels, models, incidents, rules và responses.", 979, 1055, 380, 175, PIPELINE, "PERSISTENCE"),
            Node("dataset", "Dataset & Model Registry", "Lưu split, provenance, feature artifact, model version và metrics.", 979, 1290, 380, 175, PIPELINE, "RESEARCH"),
            Node("networkai", "Network AI", "XGBoost chấm điểm bất thường từ đặc trưng flow và cửa sổ traffic.", 1429, 315, 470, 150, AI, "MODEL 1"),
            Node("logai", "Log AI", "MiniLM + IsolationForest/classifier phát hiện mẫu log bất thường.", 1429, 500, 470, 150, AI, "MODEL 2"),
            Node("graphai", "Graph AI", "GraphSAGE học quan hệ entity, process, container và network theo phiên.", 1429, 685, 470, 150, AI, "MODEL 3"),
            Node("fusion", "Fusion Engine", "Kết hợp rule, Network AI, Log AI, Graph AI và context thành risk score.", 1429, 885, 470, 165, OPS, "HYBRID SCORE"),
            Node("incident", "Incident Engine", "Sessionize, correlation, timeline và attack graph từ event liên quan.", 1429, 1100, 470, 165, AI, "CORRELATION"),
            Node("rulegen", "Rule Generator", "Khai phá mẫu lặp; validate, SHADOW và chỉ ACTIVE sau phê duyệt.", 1429, 1315, 470, 165, AI, "LIFECYCLE"),
            Node("backend", "FastAPI Backend", "REST/WebSocket đọc event, alert, incident, model và health cho SOC.", 1969, 315, 552, 160, OPS, "API"),
            Node("dashboard", "SOC Dashboard", "Theo dõi live event, alert, attack graph, AI score, rules và responses.", 1969, 525, 552, 160, OPS, "VISIBILITY"),
            Node("response", "Response Engine", "Mặc định alert_only; block/isolate chỉ khi được phép, có TTL và rollback.", 1969, 770, 552, 175, CONTROL, "POLICY"),
            Node("evidence", "Evidence Bundle", "Đóng gói timeline, raw event, process tree, metadata và SHA-256 manifest.", 1969, 1010, 552, 175, OPS, "FORENSICS"),
            Node("decision", "Nguyên tắc quyết định", "AI đơn lẻ không đủ để containment; cần risk cao + rule/đa nguồn/graph.", 1969, 1250, 552, 180, OPS, "SAFETY"),
        ]
    }

    # Source and telemetry paths.
    connector(draw, [nodes["client"].right, (479, 387), (479, 580), nodes["nginx"].right], label="HTTP", label_at=(424, 466))
    connector(draw, [nodes["nginx"].right, (484, 580), (484, 395), nodes["suricata"].left], label="packet", label_at=(466, 342))
    connector(draw, [nodes["nginx"].right, (486, 580), nodes["nginxlog"].left], label="access", label_at=(463, 604))
    connector(draw, [nodes["nginx"].left, (54, 580), (54, 785), nodes["dvwa"].left], color=LAB, label="proxy", label_at=(67, 672))
    connector(draw, [nodes["runtime"].right, (486, 1010), (486, 838), nodes["falco"].left], label="syscall", label_at=(464, 910))
    connector(draw, [nodes["runtime"].right, (486, 1010), (486, 1078), nodes["wazuh"].left], label="Docker", label_at=(462, 1035))
    connector(draw, [nodes["windows"].right, (486, 1240), (486, 1078), nodes["wazuh"].left], label="agent", label_at=(462, 1183))

    # Sensor fan-in to collector.
    sensor_bus_x = 932
    for key in ("suricata", "nginxlog", "falco", "wazuh"):
        connector(draw, [nodes[key].right, (sensor_bus_x, nodes[key].right[1])], color=SENSOR, width=3)
    connector(draw, [(sensor_bus_x, 395), (sensor_bus_x, 1160)], color=SENSOR, width=4)
    connector(draw, [(sensor_bus_x, 438), nodes["collector"].left], color=SENSOR, label="JSON / JSONL", label_at=(900, 405))

    # Pipeline.
    connector(draw, [nodes["collector"].top, (1169, 545), nodes["redis"].top], color=PIPELINE, label="RAW", label_at=(1184, 540))
    connector(draw, [nodes["redis"].top, (1169, 780), nodes["normalizer"].top], color=PIPELINE)
    connector(draw, [nodes["normalizer"].top, (1169, 1015), nodes["postgres"].top], color=PIPELINE, label="persist", label_at=(1184, 1010))
    connector(draw, [nodes["postgres"].top, (1169, 1250), nodes["dataset"].top], color=PIPELINE)

    # Normalized-event distribution to the three models.
    model_bus_x = 1382
    connector(draw, [nodes["normalizer"].right, (model_bus_x, 908), (model_bus_x, 390)], color=AI, label="normalized", label_at=(1302, 870))
    for key in ("networkai", "logai", "graphai"):
        connector(draw, [(model_bus_x, nodes[key].left[1]), nodes[key].left], color=AI, width=3)

    # Model fan-in and hybrid decision flow.
    fusion_bus_x = 1918
    for key in ("networkai", "logai", "graphai"):
        connector(draw, [nodes[key].right, (fusion_bus_x, nodes[key].right[1])], color=AI, width=3)
    connector(draw, [(fusion_bus_x, 390), (fusion_bus_x, 968), nodes["fusion"].right], color=AI, label="scores", label_at=(1874, 853))
    connector(draw, [nodes["fusion"].top, (1664, 1072), nodes["incident"].top], color=OPS, label="risk", label_at=(1679, 1067))
    connector(draw, [nodes["incident"].top, (1664, 1288), nodes["rulegen"].top], color=AI)

    # SOC, response and evidence.
    connector(draw, [nodes["postgres"].right, (1382, 1142), (1382, 285), (1938, 285), (1938, 395), nodes["backend"].left], color=PIPELINE, label="query", label_at=(1760, 258))
    connector(draw, [nodes["incident"].right, (1938, 1182), (1938, 395), nodes["backend"].left], color=OPS, width=3)
    connector(draw, [nodes["backend"].top, (2240, 500), nodes["dashboard"].top], color=OPS, label="REST / WS", label_at=(2254, 493))
    connector(draw, [nodes["incident"].right, (1938, 1182), (1938, 858), nodes["response"].left], color=CONTROL, label="policy", label_at=(1900, 982))
    connector(draw, [nodes["response"].top, (2245, 980), nodes["evidence"].top], color=CONTROL, label="audit", label_at=(2260, 974))
    connector(draw, [nodes["evidence"].top, (2245, 1215), nodes["decision"].top], color=OPS)

    # Feedback paths are deliberately dashed because they are gated control actions.
    connector(draw, [nodes["rulegen"].right, (1922, 1398), (1922, 1510), (728, 1510), (728, 1188)], color=CONTROL, dashed=True, label="rule SHADOW / ACTIVE", label_at=(1200, 1482))
    connector(draw, [nodes["response"].right, (2540, 858), (2540, 1530), (28, 1530), (28, 785), nodes["dvwa"].left], color=CONTROL, dashed=True, label="block / isolate có kiểm soát", label_at=(2020, 1493))

    for node in nodes.values():
        draw_node(draw, node)

    draw.text(
        (64, 1652),
        "Luồng chính: telemetry thật → chuẩn hóa → Rule + 3 mô hình AI → fusion risk → incident → SOC/response.  Mặc định response = alert_only.",
        font=font(22, bold=True),
        fill=INK,
    )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUTPUT, "PNG", optimize=True, dpi=(180, 180))
    print(OUTPUT)


if __name__ == "__main__":
    main()
