import { useEffect, useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  RotateCcw,
  Clock,
  Lock,
  FileCheck,
  CheckCircle2,
  RefreshCw,
  Eye,
} from 'lucide-react';
import { getJson } from '../api/client';
import { Badge, statusVariant } from '../components/Badge';
import { Modal } from '../components/Modal';
import { formatTime } from '../utils/format';
import type { Paged, ResponseRow } from '../types/api';

export function Responses() {
  const [responses, setResponses] = useState<ResponseRow[]>([]);
  const [selectedResponse, setSelectedResponse] = useState<ResponseRow | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const loadResponses = () => {
    setIsLoading(true);
    getJson<Paged<ResponseRow>>('/api/responses?page_size=50')
      .then((data) => setResponses(data.items || []))
      .catch(() => setResponses([]))
      .finally(() => setIsLoading(false));
  };

  useEffect(() => {
    loadResponses();
    const timer = window.setInterval(loadResponses, 15000);
    return () => window.clearInterval(timer);
  }, []);

  const formatPct = (value?: number | null) =>
    typeof value === 'number' ? `${Math.round(value * 100)}%` : '—';

  return (
    <div className="soc-page-container">
      {/* Policy Reminder Banner */}
      <div className="soc-status-banner banner-healthy">
        <div className="banner-left">
          <Lock size={24} className="text-emerald-400" />
          <div>
            <h2 className="banner-title">
              CƠ CHẾ PHẢN ỨNG PHÒNG THỦ CHỦ ĐỘNG (ACTIVE RESPONSE & CONTAINMENT)
            </h2>
            <p className="banner-desc">
              Chính sách an toàn Lab: Các hành động chặn IP (Temporary Blocks) và cách ly Container đều có thời hạn (TTL), tự động Rollback, lưu trữ chứng cứ số (Evidence Cryptographic SHA-256) và tuyệt đối không xóa dữ liệu người dùng.
            </p>
          </div>
        </div>
        <div className="banner-actions">
          <button
            className="soc-btn-ghost btn-sm"
            onClick={loadResponses}
            disabled={isLoading}
          >
            <RefreshCw size={14} className={isLoading ? 'spin-anim' : ''} />
            Làm mới
          </button>
        </div>
      </div>

      {/* Responses Table */}
      <div className="soc-panel p-0 overflow-hidden">
        <div className="panel-header px-4 py-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <ShieldAlert size={18} className="text-amber-400" />
            <h3 className="panel-title">Lịch sử thực thi phản ứng phòng vệ</h3>
            <Badge variant="cyan" size="sm">
              {responses.length} hành động
            </Badge>
          </div>
          <span className="text-xs text-slate-400">
            Xem vết can thiệp của hệ thống IDS đối với các hành vi tấn công
          </span>
        </div>

        <div className="table-responsive">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Thời gian</th>
                <th>Incident ID</th>
                <th>Hành động phòng vệ</th>
                <th>Mục tiêu tác động</th>
                <th>Lý do kích hoạt</th>
                <th>Mức rủi ro</th>
                <th>Trạng thái</th>
                <th>Hết hạn (Expires)</th>
                <th>Khôi phục (Rollback)</th>
                <th>Bằng chứng (Evidence)</th>
              </tr>
            </thead>
            <tbody>
              {responses.length === 0 ? (
                <tr>
                  <td colSpan={10} className="text-center py-8 text-slate-400">
                    {isLoading ? 'Đang đọc nhật ký phòng vệ...' : 'Chưa có hành vi phòng vệ nào được thực thi.'}
                  </td>
                </tr>
              ) : (
                responses.map((resp) => (
                  <tr
                    key={resp.response_id}
                    onClick={() => setSelectedResponse(resp)}
                    className="clickable-row"
                  >
                    <td className="font-mono text-xs text-slate-300">
                      {formatTime(resp.started_at)}
                    </td>
                    <td className="font-mono text-xs text-sky-400">
                      {resp.incident_id ? resp.incident_id.slice(0, 8) + '…' : '—'}
                    </td>
                    <td>
                      <span className="font-semibold text-white text-xs flex items-center gap-1.5">
                        <Lock size={12} className="text-amber-400" />
                        {resp.action?.toUpperCase()}
                      </span>
                    </td>
                    <td className="font-mono text-xs text-slate-300">{resp.target || '—'}</td>
                    <td className="text-xs text-slate-300 max-w-xs truncate">{resp.reason || '—'}</td>
                    <td className="font-mono text-xs text-emerald-400">{formatPct(resp.risk)}</td>
                    <td>
                      <Badge variant={statusVariant(resp.status)} size="sm" dot>
                        {resp.status?.toUpperCase()}
                      </Badge>
                    </td>
                    <td className="text-xs text-slate-400 font-mono">
                      {resp.expires_at ? formatTime(resp.expires_at) : 'Vĩnh viễn'}
                    </td>
                    <td>
                      <span className="text-xs text-emerald-400 flex items-center gap-1">
                        <RotateCcw size={12} />
                        {resp.rollback_status || 'Auto Rollback'}
                      </span>
                    </td>
                    <td>
                      {resp.evidence_file_count ? (
                        <span className="text-xs text-purple-300 flex items-center gap-1">
                          <FileCheck size={12} />
                          {resp.evidence_file_count} tệp
                        </span>
                      ) : (
                        <span className="text-xs text-slate-500">—</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Response Detail Modal */}
      <Modal
        isOpen={selectedResponse !== null}
        onClose={() => setSelectedResponse(null)}
        title={`Chi tiết phản ứng: ${selectedResponse?.action?.toUpperCase() || ''}`}
        subtitle={`Response ID: ${selectedResponse?.response_id || ''}`}
        width="md"
      >
        {selectedResponse && (
          <div className="space-y-4">
            <div className="detail-meta-grid">
              <div className="meta-box">
                <span className="meta-label">Mục tiêu</span>
                <span className="meta-val font-mono">{selectedResponse.target || '127.0.0.1'}</span>
              </div>
              <div className="meta-box">
                <span className="meta-label">Mức rủi ro</span>
                <span className="meta-val font-mono text-amber-400">
                  {formatPct(selectedResponse.risk)}
                </span>
              </div>
              <div className="meta-box">
                <span className="meta-label">Trạng thái</span>
                <Badge variant={statusVariant(selectedResponse.status)}>
                  {selectedResponse.status?.toUpperCase()}
                </Badge>
              </div>
            </div>

            <div className="drawer-section">
              <h4 className="section-title">Nguyên nhân kích hoạt</h4>
              <p className="text-xs text-slate-300 leading-relaxed">
                {selectedResponse.reason || 'Tự động kích hoạt do chỉ số rủi ro vượt ngưỡng an toàn quy định.'}
              </p>
            </div>

            {selectedResponse.bundle_sha256 && (
              <div className="drawer-section">
                <h4 className="section-title flex items-center gap-1.5">
                  <FileCheck size={14} className="text-purple-400" />
                  Mã băm chứng cứ số (Evidence SHA-256)
                </h4>
                <code className="text-xs text-sky-300 font-mono break-all block p-2 bg-slate-900 rounded border border-slate-800">
                  {selectedResponse.bundle_sha256}
                </code>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}
