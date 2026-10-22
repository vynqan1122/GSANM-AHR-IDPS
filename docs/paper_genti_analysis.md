# Phan tich bai bao va cach ap dung vao AHR-IDPS

Tai lieu tham khao: GenTI: Benchmarking LLMs for Autonomous IDPS Rule
Generation for Unseen Attacks, arXiv:2606.05844v1, 4/6/2026.

## Bai bao de xuat gi

GenTI tap trung vao sinh luat IDPS cho tan cong chua gap. Dataset GTI duoc mo ta
la tap luat lon, gom luat Snort, Suricata, Emerging Threats va YARA, kem payload,
ngon ngu luat, CTI, ATT&CK/D3FEND, CVE/CWE, action va provenance. Pipeline co
bon y chinh:

1. Chuyen analyst prompt va payload mau thanh prompt co cau truc.
2. Tao candidate rule va threat context.
3. Lap vong danh gia DR, FPR, coverage, CPU va tinh rule; neu chua dat nguong
   thi tao feedback va tinh chinh.
4. Chay Chain-of-Verification (CoVe): syntax, logic, false-positive; chi rule
   vuot ca ba gate moi duoc dua vao output.

Bai bao con dung CoT/CoVe augmentation va curriculum learning theo do kho. Thi
nghiem cua bai bao su dung QLoRA tren DeepSeek-7B voi 8 GPU A100. Cac so lieu
89.4%, 94.8%, 87.4% va 2.3% la ket qua cua GenTI tren corpus GTI; khong duoc
gan truc tiep cho AHR-IDPS neu chua chay lai thi nghiem tren dataset cua AHR.

## Muc do phu hop voi AHR-IDPS

AHR-IDPS da co cac diem tuong ung: Collector/Normalizer tao event chuan hoa,
Network/Log/Graph/Fusion AI tao score, Rule Generator co pattern miner va
template Suricata/Falco/Wazuh, Validator co replay metrics, va lifecycle
`candidate -> validating -> shadow -> active`. Vi vay co the ap dung y tuong
GenTI o lop Rule Intelligence ma khong can thay the cac model phat hien hien
tai.

GTI khong phai la dataset flow nhu CICIDS2017. CICIDS2017 chi phu hop cho
Network AI. Neu dung no de sinh luat, can payload HTTP/normalized event va
provenance tu DVWA; khong suy dien rule payload tu mot dong flow thieu payload.

## Thay doi da thuc hien

Them `rule_engine/genti.py` voi GenTI-lite deterministic:

- `build_context`: tao block header, flow, payload, threat context, difficulty,
  provenance va verification policy.
- `map_threat_context`: anh xa than trong cac nhom DVWA sang CWE/ATT&CK/tactic;
  nhan ro mapping nao la taxonomy noi bo va giam confidence khi khong chac chan.
- `difficulty_score`: diem [0, 1] de sau nay xep curriculum; khong dua
  `scenario_id`, IP, event_id hay timestamp vao rule.
- `logic_check`: kiem tra engine, action alert-only va behavior anchor.
- `cove_verify`: chay syntax, logic va false-positive/replay thanh ba gate;
  tinh `security_effectiveness` va `composite_score`.

`rule_engine/generator.py` luu `genti_context` trong metadata cua rule candidate
va gan version `genti-lite-v1`. `rule_engine/validator.py` chay CoVe khi validate
candidate; rule chi vao SHADOW neu CoVe va replay thresholds cung dat. CoVe khong
tu dong chuyen rule sang ACTIVE.

## Cach van hanh de he thong on dinh

1. De Rule Generator tao candidate, giu mac dinh `alert_only`.
2. Xem metadata `genti_context` va `model_versions` trong Dashboard/DB.
3. Chay Validator tren toan bo event da gan nhan.
4. Kiem tra ba gate: syntax parser, logic anchor va FPR replay.
5. Neu dat, candidate vao SHADOW va chi tao alert; khong drop/reject.
6. Nguoi quan tri xem shadow metrics, sau do moi phe duyet ACTIVE.

Lenh kiem tra nhanh trong project:

```bash
python -m pytest rule_engine/tests/test_genti.py rule_engine/tests/test_validation.py rule_engine/tests/test_rule_generation.py -q
python -m rule_engine.generator --once --min-support 2 --min-confidence 0.30 --window-minutes 1440 --max-candidates 5
python -m rule_engine.validator <rule_id> --min-precision 0.90 --min-recall 0.75 --max-fpr 0.02 --min-positive-matches 5
```

Trong Docker, chay cac lenh tren trong service `ai-network` sau khi
PostgreSQL/Redis/pipeline healthy. Neu khong co du event attack va benign, rule
se bi reject thay vi duoc lam active.

## Cac chi so nen dua vao bao cao

Bao cao AHR-IDPS nen dung nam nhom chi so cua bai bao, nhung dieu chinh cho
he thong lai:

| Chi so | Cach do trong AHR-IDPS |
|---|---|
| Syntax Accuracy | `syntax_check` cua Suricata/Falco/Wazuh |
| Logic Consistency | engine, protocol, URI/process/event anchor va CTI context |
| CTI Coverage | do phu ATT&CK/CWE cua context; ghi ro mapping noi bo |
| Security Effectiveness | recall va `1 - FPR` tren replay event |
| Composite Score | 0.2 syntax + 0.3 logic/semantic + 0.2 precision + 0.3 security |

Can bao cao them support, confidence, processing cost, shadow alert volume,
latency va ty le candidate bi reject. Unknown attack nen la mot scenario DVWA
hoac bien the payload khong xuat hien trong train; khong coi ngau nhien mot dong
CICIDS2017 la unknown scenario.

## Gioi han va quyet dinh thiet ke

AHR-IDPS khong fine-tune DeepSeek-7B/QLoRA trong phien ban lab nho vi chi co
dataset DVWA va tai nguyen CPU/GPU han che. Phan GenTI-lite giu duoc cau truc
thuat toan va co the thay backend LLM sau nay, nhung luat mac dinh van xac dinh,
de debug, de replay va an toan hon. Neu them LLM, LLM chi duoc tao candidate
JSON; khong duoc ghi truc tiep file active rule va khong duoc bo qua CoVe.
