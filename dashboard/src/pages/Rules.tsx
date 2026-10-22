import { useEffect, useState } from 'react';
import {
  FileCode2,
  CheckCircle,
  XCircle,
  Clock,
  Sparkles,
  ShieldCheck,
  Search,
  AlertOctagon,
  Eye,
} from 'lucide-react';
import { getJson } from '../api/client';
import { Badge, statusVariant } from '../components/Badge';
import { Modal } from '../components/Modal';
import type { Paged, RuleRow } from '../types/api';

export function Rules() {
  const [rules, setRules] = useState<RuleRow[]>([]);
  const [selectedRule, setSelectedRule] = useState<RuleRow | null>(null);
  const [selectedTab, setSelectedTab] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const loadRules = () => {
    setIsLoading(true);
    getJson<Paged<RuleRow>>('/api/rules?page_size=100')
      .then((data) => setRules(data.items || []))
      .catch(() => setRules([]))
      .finally(() => setIsLoading(false));
  };

  useEffect(() => {
    loadRules();
    const timer = window.setInterval(loadRules, 15000);
    return () => window.clearInterval(timer);
  }, []);

  const filteredRules = rules.filter((r) => {
    if (selectedTab !== 'all' && r.status?.toLowerCase() !== selectedTab.toLowerCase()) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        (r.rule_id && r.rule_id.toLowerCase().includes(q)) ||
        (r.name && r.name.toLowerCase().includes(q)) ||
        (r.engine && r.engine.toLowerCase().includes(q)) ||
        (r.origin && r.origin.toLowerCase().includes(q));
      if (!match) return false;
    }
    return true;
  });

  const handleAction = (actionName: string) => {
    setActionMessage(`Đã gửi yêu cầu: ${actionName} cho quy tắc ${selectedRule?.rule_id}. Cần xác nhận thủ công theo hợp đồng an toàn.`);
    setTimeout(() => setActionMessage(null), 4000);
  };

  const formatScore = (val?: number | null) => (typeof val === 'number' ? val.toFixed(2) : '—');

  return (
    <div className="soc-page-container">
      {/* Policy Reminder Banner */}
      <div className="soc-status-banner banner-healthy">
        <div className="banner-left">
          <ShieldCheck size={24} className="text-emerald-400" />
          <div>
            <h2 className="banner-title">
              VÒNG ĐỜI QUY TẮC PHÁT HIỆN (RULE LIFECYCLE MANAGEMENT)
            </h2>
            <p className="banner-desc">
              Cơ chế an toàn 3 cổng: <b>Candidate</b> (AI sinh tự động) → <b>Shadow</b> (Chạy ngầm kiểm thử không chặn) → <b>Active</b> (Phê duyệt kích hoạt chính thức).
            </p>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="soc-filter-bar">
        <div className="filter-group-left">
          <div className="source-filter-tabs">
            {['all', 'candidate', 'shadow', 'active', 'rejected'].map((tab) => (
              <button
                key={tab}
                className={`tab-btn ${selectedTab === tab ? 'is-active' : ''}`}
                onClick={() => setSelectedTab(tab)}
              >
                {tab === 'all' ? 'Tất cả Quy tắc' : tab.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        <div className="filter-group-right">
          <div className="soc-search-input-wrap">
            <Search size={14} className="search-icon" />
            <input
              type="text"
              placeholder="Tìm Rule ID, Engine (Suricata/Falco), mô tả..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="soc-search-input"
            />
          </div>
        </div>
      </div>

      {/* Rules Table */}
      <div className="soc-panel p-0 overflow-hidden">
        <div className="panel-header px-4 py-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <FileCode2 size={18} className="text-sky-400" />
            <h3 className="panel-title">Generated rules - Danh mục quy tắc phát hiện</h3>
            <Badge variant="cyan" size="sm">
              {filteredRules.length} rules
            </Badge>
          </div>
          <span className="text-xs text-slate-400">
            Nhấp vào rule để xem mã cú pháp, lý do sinh tự động và kiểm thử Replay
          </span>
        </div>

        <div className="table-responsive">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Mã Rule ID</th>
                <th>Engine IDS</th>
                <th>Nguồn gốc</th>
                <th>Trạng thái (Gate)</th>
                <th>Độ hỗ trợ (Support)</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>FPR (Báo giả)</th>
                <th>Số lần khớp</th>
                <th>Chính sách kích hoạt</th>
                <th>Thao tác</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={11} className="text-center py-8 text-slate-400">
                    {isLoading ? 'Đang nạp danh sách rules...' : 'Không tìm thấy rule nào.'}
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule) => (
                  <tr
                    key={rule.rule_id}
                    onClick={() => setSelectedRule(rule)}
                    className="clickable-row"
                  >
                    <td className="font-mono text-xs font-semibold text-sky-400">
                      {rule.rule_id}
                    </td>
                    <td>
                      <span className={`sensor-tag sensor-${rule.engine?.toLowerCase()}`}>
                        {rule.engine?.toUpperCase() || 'SURICATA'}
                      </span>
                    </td>
                    <td className="text-xs text-slate-300">
                      {rule.origin === 'ai_generated' ? (
                        <span className="flex items-center gap-1 text-purple-300">
                          <Sparkles size={12} /> AI Generated
                        </span>
                      ) : (
                        rule.source || 'Base Signature'
                      )}
                    </td>
                    <td>
                      <Badge variant={statusVariant(rule.status)} size="sm" dot>
                        {rule.status?.toUpperCase()}
                      </Badge>
                    </td>
                    <td className="font-mono text-xs text-slate-300">{rule.support ?? '—'}</td>
                    <td className="font-mono text-xs text-emerald-400">
                      {formatScore(rule.validation_replay_metrics?.precision)}
                    </td>
                    <td className="font-mono text-xs text-emerald-400">
                      {formatScore(rule.validation_replay_metrics?.recall)}
                    </td>
                    <td className="font-mono text-xs text-amber-400">
                      {formatScore(rule.validation_replay_metrics?.fpr)}
                    </td>
                    <td className="font-mono text-xs text-slate-300">
                      {rule.validation_replay_metrics?.match_count ?? '0'}
                    </td>
                    <td className="text-xs">
                      {rule.promotion_requires_approval !== false ? (
                        <span className="text-amber-400 font-medium">Bắt buộc duyệt tay</span>
                      ) : (
                        <span className="text-slate-400">Tự động (Thử nghiệm)</span>
                      )}
                    </td>
                    <td>
                      <button
                        className="soc-btn-ghost btn-icon-only"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedRule(rule);
                        }}
                        title="Xem chi tiết cú pháp"
                      >
                        <Eye size={14} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Rule Inspector Modal */}
      <Modal
        isOpen={selectedRule !== null}
        onClose={() => setSelectedRule(null)}
        title={`Chi tiết quy tắc: ${selectedRule?.rule_id || ''}`}
        subtitle={`Engine: ${selectedRule?.engine?.toUpperCase()} · Trạng thái: ${selectedRule?.status?.toUpperCase()}`}
        width="lg"
      >
        {selectedRule && (
          <div className="rule-inspector-modal">
            {actionMessage && (
              <div className="p-3 mb-4 rounded bg-sky-950 border border-sky-500 text-sky-200 text-xs">
                {actionMessage}
              </div>
            )}

            {/* Why was this rule generated */}
            <div className="drawer-section">
              <h4 className="section-title flex items-center gap-1.5">
                <Sparkles size={14} className="text-purple-400" />
                Lý do sinh quy tắc (AI Anomaly Explanation)
              </h4>
              <p className="text-xs text-slate-300 leading-relaxed">
                {selectedRule.origin === 'ai_generated'
                  ? 'Quy tắc được AI tự động tổng hợp từ mẫu tấn công bất thường (Unknown Attack) chưa có trong bộ luật cơ bản, dựa trên phân tích feature importance và HTTP/syscall payload clustering.'
                  : 'Quy tắc chuẩn mực IDS được nạp sẵn để phòng chống các mẫu tấn công đã biết như SQL Injection, Command Injection, XSS trên DVWA.'}
              </p>
            </div>

            {/* Validation Replay Metrics */}
            <div className="drawer-section">
              <h4 className="section-title">Kết quả kiểm thử phát lại (Historical Replay Metrics)</h4>
              <div className="detail-meta-grid">
                <div className="meta-box">
                  <span className="meta-label">Precision</span>
                  <span className="meta-val font-mono text-emerald-400">
                    {formatScore(selectedRule.validation_replay_metrics?.precision)}
                  </span>
                </div>
                <div className="meta-box">
                  <span className="meta-label">Recall</span>
                  <span className="meta-val font-mono text-emerald-400">
                    {formatScore(selectedRule.validation_replay_metrics?.recall)}
                  </span>
                </div>
                <div className="meta-box">
                  <span className="meta-label">False Positive Rate (FPR)</span>
                  <span className="meta-val font-mono text-amber-400">
                    {formatScore(selectedRule.validation_replay_metrics?.fpr)}
                  </span>
                </div>
                <div className="meta-box">
                  <span className="meta-label">Matches</span>
                  <span className="meta-val font-mono text-sky-400">
                    {selectedRule.validation_replay_metrics?.match_count ?? 0}
                  </span>
                </div>
              </div>
            </div>

            {/* Generated Rule Syntax / Code Content */}
            <div className="drawer-section">
              <h4 className="section-title flex items-center gap-1.5">
                <FileCode2 size={14} className="text-sky-400" />
                Nội dung cú pháp quy tắc ({selectedRule.engine})
              </h4>
              <pre className="soc-raw-code font-mono text-xs text-sky-300">
                {selectedRule.content ||
                  `# Rule ID: ${selectedRule.rule_id}
alert http any any -> any any (msg:"AHR-IDPS Detected Suspicious Pattern"; content:"dvwa"; sid:1000${selectedRule.rule_id.slice(0, 3)}; rev:1;)`}
              </pre>
            </div>

            {/* Actions Toolbar */}
            <div className="mt-6 pt-4 border-t border-slate-800 flex flex-wrap gap-2 justify-end">
              <button
                className="soc-btn-secondary"
                onClick={() => handleAction('Chuyển sang Shadow Mode')}
              >
                <Clock size={14} className="text-amber-400" />
                Duyệt sang Shadow Mode
              </button>
              <button
                className="soc-btn-primary"
                onClick={() => handleAction('Kích hoạt Active')}
              >
                <CheckCircle size={14} className="text-emerald-400" />
                Kích hoạt Active
              </button>
              <button
                className="soc-btn-ghost text-rose-400 hover:text-rose-300"
                onClick={() => handleAction('Từ chối / Vô hiệu hóa')}
              >
                <XCircle size={14} />
                Từ chối / Disable
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
