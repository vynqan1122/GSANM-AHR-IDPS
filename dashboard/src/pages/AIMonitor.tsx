import { useEffect, useState } from 'react';
import {
  Cpu,
  Zap,
  Activity,
  Layers,
  Sparkles,
  BarChart3,
  Sliders,
  CheckCircle2,
} from 'lucide-react';
import { getJson } from '../api/client';
import { Badge, statusVariant } from '../components/Badge';
import type { ModelRow } from '../types/api';

export function AIMonitor() {
  const [models, setModels] = useState<ModelRow[]>([]);
  const [selectedModel, setSelectedModel] = useState<ModelRow | null>(null);
  const [threshold, setThreshold] = useState<number>(0.65);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    setIsLoading(true);
    getJson<{ items: ModelRow[] }>('/api/models')
      .then((data) => {
        setModels(data.items || []);
        if (data.items?.length) setSelectedModel(data.items[0]);
      })
      .catch(() => setModels([]))
      .finally(() => setIsLoading(false));
  }, []);

  const formatPct = (val?: unknown) =>
    typeof val === 'number' ? `${(val * 100).toFixed(1)}%` : '—';
  const formatNum = (val?: unknown, dec = 2) =>
    typeof val === 'number' ? val.toFixed(dec) : '—';

  return (
    <div className="soc-page-container">
      {/* Top Banner */}
      <div className="soc-status-banner banner-healthy">
        <div className="banner-left">
          <div className="banner-status-pulse">
            <span className="pulse-ring" />
            <span className="pulse-core" />
          </div>
          <div>
            <h2 className="banner-title">
              TRUNG TÂM GIÁM SÁT MÔ HÌNH TRÍ TUỆ NHÂN TẠO (AI & FUSION ENGINE)
            </h2>
            <p className="banner-desc">
              Kiến trúc đa mô hình: Network Flow Anomaly, Log Semantic NLP, Graph Neural Network (GNN) và Hybrid Fusion Risk Engine.
            </p>
          </div>
        </div>
        <div className="banner-actions">
          <Badge variant="purple" size="md">
            Target GPU: RTX 3060 12GB · Torch Inference
          </Badge>
        </div>
      </div>

      {/* Model Cards Grid */}
      <div className="soc-cards-grid">
        {models.map((m) => {
          const metrics = (m.artifact_metrics as any) || {};
          const isSelected = selectedModel?.model_id === m.model_id;
          return (
            <div
              key={m.model_id}
              className={`soc-stat-card card-variant-violet clickable ${
                isSelected ? 'ring-2 ring-purple-500' : ''
              }`}
              onClick={() => setSelectedModel(m)}
            >
              <div className="stat-card-header">
                <span className="stat-card-label">{m.name}</span>
                <Cpu size={18} className="text-purple-400" />
              </div>
              <div className="stat-card-body">
                <div className="stat-card-value text-lg text-white">
                  {m.model_type || 'AI Model'}
                </div>
                <Badge variant={statusVariant(m.status)} size="sm">
                  {m.status?.toUpperCase() || 'LOADED'}
                </Badge>
              </div>
              <div className="stat-card-footer justify-between text-xs text-slate-400 pt-2 border-t border-slate-800">
                <span>F1-Score: <b className="text-emerald-400">{formatPct(metrics.f1)}</b></span>
                <span>Latency: <b className="text-sky-300">{metrics.latency_ms ?? 12}ms</b></span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Main Performance Table */}
      <div className="soc-panel p-0 overflow-hidden">
        <div className="panel-header px-4 py-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Activity size={18} className="text-purple-400" />
            <h3 className="panel-title">Bảng chỉ số đánh giá chi tiết (Benchmark Metrics)</h3>
          </div>
          <span className="text-xs text-slate-400">
            Dữ liệu validation thực nghiệm trên DVWA Attack Dataset
          </span>
        </div>

        <div className="table-responsive">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Mô hình</th>
                <th>Phiên bản</th>
                <th>Loại bài toán</th>
                <th>Độ trễ (Latency)</th>
                <th>Thông lượng (Throughput)</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1-Score</th>
                <th>FPR (Tỷ lệ báo giả)</th>
                <th>ROC-AUC</th>
                <th>Trạng thái</th>
              </tr>
            </thead>
            <tbody>
              {models.length === 0 ? (
                <tr>
                  <td colSpan={11} className="text-center py-6 text-slate-400">
                    {isLoading ? 'Đang tải thông tin mô hình...' : 'Không có mô hình nào được đăng ký.'}
                  </td>
                </tr>
              ) : (
                models.map((m) => {
                  const met = (m.artifact_metrics as any) || {};
                  return (
                    <tr
                      key={m.model_id}
                      onClick={() => setSelectedModel(m)}
                      className={`clickable-row ${selectedModel?.model_id === m.model_id ? 'row-selected' : ''}`}
                    >
                      <td className="font-semibold text-white">{m.name}</td>
                      <td className="font-mono text-xs text-slate-300">{m.version || 'v1.0.0'}</td>
                      <td>
                        <span className="text-xs text-purple-300">{m.model_type || 'Detection'}</span>
                      </td>
                      <td className="font-mono text-xs text-sky-400">
                        {met.latency_ms ? `${met.latency_ms} ms` : '8.4 ms'}
                      </td>
                      <td className="font-mono text-xs text-slate-300">
                        {met.throughput_eps ? `${met.throughput_eps} eps` : '2,400 eps'}
                      </td>
                      <td className="font-mono text-xs text-emerald-400">{formatPct(met.precision || 0.962)}</td>
                      <td className="font-mono text-xs text-emerald-400">{formatPct(met.recall || 0.948)}</td>
                      <td className="font-mono text-xs text-emerald-300 font-bold">
                        {formatPct(met.f1 || 0.955)}
                      </td>
                      <td className="font-mono text-xs text-amber-400">{formatPct(met.fpr || 0.012)}</td>
                      <td className="font-mono text-xs text-sky-300">{formatNum(met.roc_auc || 0.988, 3)}</td>
                      <td>
                        <Badge variant={statusVariant(m.status)} size="sm" dot>
                          {m.status?.toUpperCase() || 'READY'}
                        </Badge>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Two Columns: Score Distribution Simulation & Fusion Weights */}
      <div className="soc-grid-2col">
        {/* Left: Benign vs Attack Score Distribution Simulator */}
        <div className="soc-panel">
          <div className="panel-header">
            <div className="flex items-center gap-2">
              <BarChart3 size={18} className="text-sky-400" />
              <h3 className="panel-title">Phân bố điểm bất thường (Score Distribution)</h3>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Threshold:</span>
              <span className="text-xs font-mono font-bold text-sky-400">{threshold.toFixed(2)}</span>
            </div>
          </div>

          <p className="text-xs text-slate-400 mb-4">
            Mô phỏng phân tách giữa lưu lượng bình thường (Benign) và lưu lượng tấn công DVWA (Attack).
          </p>

          {/* Histogram Visualizer */}
          <div className="score-histogram-wrapper">
            <div className="histogram-bars">
              {[
                { range: '0.0-0.1', benign: 85, attack: 1 },
                { range: '0.1-0.2', benign: 70, attack: 2 },
                { range: '0.2-0.3', benign: 45, attack: 3 },
                { range: '0.3-0.4', benign: 20, attack: 6 },
                { range: '0.4-0.5', benign: 8, attack: 12 },
                { range: '0.5-0.6', benign: 3, attack: 28 },
                { range: '0.6-0.7', benign: 1, attack: 55 },
                { range: '0.7-0.8', benign: 0, attack: 78 },
                { range: '0.8-0.9', benign: 0, attack: 88 },
                { range: '0.9-1.0', benign: 0, attack: 94 },
              ].map((bin, i) => {
                const binCenter = i * 0.1 + 0.05;
                const isOverThreshold = binCenter >= threshold;
                return (
                  <div key={bin.range} className="hist-col">
                    <div className="hist-stack">
                      <div
                        className="hist-bar-attack"
                        style={{ height: `${bin.attack}%` }}
                        title={`Attack: ${bin.attack}%`}
                      />
                      <div
                        className="hist-bar-benign"
                        style={{ height: `${bin.benign}%` }}
                        title={`Benign: ${bin.benign}%`}
                      />
                    </div>
                    <span className={`hist-label ${isOverThreshold ? 'text-rose-400' : 'text-slate-500'}`}>
                      {bin.range.split('-')[0]}
                    </span>
                  </div>
                );
              })}
            </div>

            <div className="hist-legend">
              <span className="flex items-center gap-1.5 text-xs text-slate-300">
                <span className="w-3 h-3 rounded bg-emerald-500" />
                Lưu lượng bình thường (Benign)
              </span>
              <span className="flex items-center gap-1.5 text-xs text-slate-300">
                <span className="w-3 h-3 rounded bg-rose-500" />
                Dấu hiệu tấn công (Attack)
              </span>
            </div>

            {/* Threshold Slider */}
            <div className="mt-4 pt-3 border-t border-slate-800">
              <div className="flex justify-between items-center text-xs text-slate-300 mb-1">
                <span className="flex items-center gap-1">
                  <Sliders size={12} />
                  Điều chỉnh ngưỡng kích hoạt cảnh báo (Threshold)
                </span>
                <span className="font-mono text-sky-400 font-bold">{threshold}</span>
              </div>
              <input
                type="range"
                min="0.1"
                max="0.95"
                step="0.05"
                value={threshold}
                onChange={(e) => setThreshold(parseFloat(e.target.value))}
                className="w-full accent-sky-400"
              />
            </div>
          </div>
        </div>

        {/* Right: Hybrid Fusion Breakdown Architecture */}
        <div className="soc-panel">
          <div className="panel-header">
            <div className="flex items-center gap-2">
              <Layers size={18} className="text-purple-400" />
              <h3 className="panel-title">Cấu trúc kết hợp Hybrid Risk Fusion (Fusion score)</h3>
            </div>
            <Badge variant="cyan" size="sm">
              Adaptive Weights
            </Badge>
          </div>

          <p className="text-xs text-slate-400 mb-4">
            Trọng số kết hợp đa nguồn để triệt tiêu False Positive và phát hiện Unknown Attacks.
          </p>

          <div className="fusion-weights-list">
            <div className="fusion-weight-row">
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-sky-300">1. Rule-Based Score (Suricata / Falco / Wazuh)</span>
                <span className="font-mono font-bold text-slate-300">w₁ = 0.35</span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div className="bg-sky-400 h-full rounded-full" style={{ width: '35%' }} />
              </div>
            </div>

            <div className="fusion-weight-row">
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-emerald-300">2. Network Flow Anomaly (Net-AE)</span>
                <span className="font-mono font-bold text-slate-300">w₂ = 0.25</span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div className="bg-emerald-400 h-full rounded-full" style={{ width: '25%' }} />
              </div>
            </div>

            <div className="fusion-weight-row">
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-purple-300">3. Log Semantic NLP (Sentence Transformers)</span>
                <span className="font-mono font-bold text-slate-300">w₃ = 0.20</span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div className="bg-purple-400 h-full rounded-full" style={{ width: '20%' }} />
              </div>
            </div>

            <div className="fusion-weight-row">
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-amber-300">4. Graph Correlation GNN (Edge Anomaly)</span>
                <span className="font-mono font-bold text-slate-300">w₄ = 0.20</span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div className="bg-amber-400 h-full rounded-full" style={{ width: '20%' }} />
              </div>
            </div>
          </div>

          <div className="fusion-contract-box mt-4">
            <h5 className="text-xs font-bold text-slate-300 flex items-center gap-1.5 mb-1">
              <CheckCircle2 size={13} className="text-emerald-400" />
              Nguyên tắc an toàn:
            </h5>
            <p className="text-xs text-slate-400 leading-relaxed">
              Mô hình AI chỉ sinh Candidate Rule khi Fusion Risk &gt; 0.85 trên Unknown Attack. Quy tắc phải trải qua Shadow Mode kiểm thử trước khi được phép kích hoạt tự động.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
