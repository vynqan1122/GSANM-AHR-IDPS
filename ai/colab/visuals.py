"""Measured static figures for Colab training runs; no generated metric values.

EDA uses only the training partition. CSV/JSON companions keep figures auditable.
PNG is for notebook/Word; SVG is for scalable report export.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.calibration import calibration_curve
from sklearn.metrics import (ConfusionMatrixDisplay, confusion_matrix,
                             precision_recall_curve, roc_curve, auc,
                             average_precision_score)

COLORS = ['#0072B2', '#D55E00', '#009E73', '#CC79A7', '#E69F00', '#56B4E9', '#6F4E37', '#555555']


class Figures:
    def __init__(self, output):
        self.root = Path(output)
        self.folder = self.root / 'figures'
        self.folder.mkdir(parents=True, exist_ok=True)
        index = self.root / 'figures-index.json'
        self.items = json.loads(index.read_text(encoding='utf-8')) if index.exists() else []

    def save(self, fig, name, caption):
        fig.text(.01, .005, caption, fontsize=8, color='#444444', wrap=True)
        fig.tight_layout(rect=(0, .05, 1, 1))
        item = {'name': name, 'caption': caption, 'files': {}}
        for extension in ('png', 'svg'):
            path = self.folder / f'{name}.{extension}'
            fig.savefig(path, dpi=180, bbox_inches='tight', facecolor='white')
            item['files'][path.relative_to(self.root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        plt.close(fig)
        self.items = [x for x in self.items if x['name'] != name] + [item]
        (self.root / 'figures-index.json').write_text(json.dumps(self.items, indent=2), encoding='utf-8')


def dataset_figures(output, x, y, splits, names, stages, raw_labels=None,
                    selected_labels=None, missing=None):
    """Labels/counts describe the dataset; feature EDA is training-only, bounded."""
    out = Path(output)
    plot = Figures(out)
    stats = {'stages': stages, 'split_counts': {
        k: {'benign': int(np.sum(y[ix] == 0)), 'attack': int(np.sum(y[ix] == 1))}
        for k, ix in splits.items()}, 'eda_partition': 'train', 'eda_sample_cap': 5000}
    (out / 'preprocessing.json').write_text(json.dumps(stats, indent=2), encoding='utf-8')
    pd.DataFrame(list(stages.items()), columns=['stage', 'rows']).to_csv(out / 'preprocessing.csv', index=False)
    fig, ax = plt.subplots(figsize=(10, max(4, .5 * len(stages))))
    ax.barh(list(stages), list(stages.values()), color=COLORS[0])
    ax.invert_yaxis()
    ax.set(title='Preprocessing audit: measured row counts', xlabel='Rows')
    for i, n in enumerate(stages.values()): ax.text(n, i, f' {n:,}', va='center', fontsize=9)
    ax.margins(x=.22)
    plot.save(fig, '01_preprocessing', 'Stages may include exclusions; read preprocessing.csv for the exact count at each step.')

    if raw_labels is None: raw_labels = {'benign': int(sum(y == 0)), 'attack': int(sum(y == 1))}
    if selected_labels is None: selected_labels = raw_labels
    labels = sorted(set(raw_labels) | set(selected_labels))
    fig, axes = plt.subplots(1, 2, figsize=(14, max(4, .32 * len(labels))))
    for ax, data, title in zip(axes, (raw_labels, selected_labels), ('Labels before selection', 'Labels after selection')):
        values = [int(data.get(label, 0)) for label in labels]
        ax.barh(labels, values, color=COLORS[0])
        ax.set(title=title, xlabel='Rows (log scale)')
        ax.set_xscale('symlog', linthresh=1)
        for i, n in enumerate(values): ax.text(max(1, n), i, f' {n:,}', va='center', fontsize=8)
        ax.margins(x=.2)
    plot.save(fig, '02_class_distribution', 'Original labels retained for dataset review; classifiers predict binary benign/attack.')
    pd.DataFrame({'label': labels, 'before': [raw_labels.get(k, 0) for k in labels],
                  'after': [selected_labels.get(k, 0) for k in labels]}).to_csv(out / 'label-counts.csv', index=False)

    fig, ax = plt.subplots(figsize=(8, 4))
    keys = list(splits)
    benign = [stats['split_counts'][k]['benign'] for k in keys]
    attack = [stats['split_counts'][k]['attack'] for k in keys]
    ax.bar(keys, benign, label='Benign', color=COLORS[0])
    ax.bar(keys, attack, bottom=benign, label='Attack', color=COLORS[1])
    for i, (b, a) in enumerate(zip(benign, attack)): ax.text(i, b+a, f'{b+a:,}', ha='center', va='bottom')
    ax.margins(y=.15)
    ax.set(title='Class counts in train / validation / test', ylabel='Rows')
    ax.legend()
    plot.save(fig, '03_split_counts', 'Test remains held out from fitting and training-loss monitoring.')

    train_ix = np.asarray(splits['train'])
    rng = np.random.default_rng(42)
    chosen = rng.choice(train_ix, min(5000, len(train_ix)), replace=False)
    frame = pd.DataFrame(np.asarray(x)[chosen], columns=names)
    frame.describe().T.to_csv(out / 'train-feature-summary.csv')
    variances = frame.var().sort_values(ascending=False)
    cols = list(variances[variances > 0].index[:12])
    if cols:
        corr = frame[cols].corr().fillna(0)
        corr.to_csv(out / 'train-feature-correlation.csv')
        fig, ax = plt.subplots(figsize=(11, 9))
        mesh = ax.imshow(corr, vmin=-1, vmax=1, cmap='RdBu_r')
        ax.set_xticks(range(len(cols)), cols, rotation=65, ha='right', fontsize=8)
        ax.set_yticks(range(len(cols)), cols, fontsize=8)
        ax.set_title('Training feature correlation (up to 12 nonconstant features)')
        fig.colorbar(mesh, ax=ax, label='Pearson correlation')
        plot.save(fig, '04_feature_correlation', f'Training-only deterministic sample, n={len(frame):,}; raw variance selects displayed columns.')
        fig, axes = plt.subplots(2, 3, figsize=(13, 7))
        sample_y = y[chosen]
        for ax, col in zip(axes.flat, cols[:6]):
            values = np.sign(frame[col]) * np.log1p(np.abs(frame[col]))
            for label, color in ((0, COLORS[0]), (1, COLORS[1])):
                ax.hist(values[sample_y == label], bins=30, alpha=.55, density=True,
                        color=color, label='Attack' if label else 'Benign') if np.any(sample_y == label) else None
            ax.set(title=col, xlabel='sign(x) × log(1 + |x|)', ylabel='Density')
        for ax in list(axes.flat)[min(6, len(cols)):]: ax.set_visible(False)
        axes.flat[0].legend()
        plot.save(fig, '05_feature_distributions', f'Training-only sample, n={len(frame):,}; signed log transform is for visualization only.')

    if missing:
        values = pd.Series(missing, dtype=float).sort_values(ascending=False).head(20)
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh(values.index, values.values, color=COLORS[1]); ax.invert_yaxis()
        ax.set(title='Missing / nonfinite selected features before imputation', xlabel='Cells')
        plot.save(fig, '06_missing_values', 'NaN, numeric conversion failures and infinity counted before fillna(0); see missing-values.csv.')
        pd.Series(missing, name='missing_cells').to_csv(out / 'missing-values.csv')


def history_figures(output, histories):
    out = Path(output)
    (out / 'training-history.json').write_text(json.dumps(histories, indent=2), encoding='utf-8')
    plot = Figures(out)
    for name, history in histories.items():
        fig, ax = plt.subplots(figsize=(9, 5))
        curves = 0
        for partition, measures in history.items():
            for metric, values in measures.items():
                if metric not in {'logloss', 'loss'} or not values: continue
                ax.plot(np.arange(1, len(values)+1), values, label=f'{partition}: {metric}')
                curves += 1
        if not curves:
            plt.close(fig); continue
        ax.set(title=f'{name}: recorded optimization loss', xlabel='Boosting round / MLP epoch', ylabel='Loss')
        ax.grid(alpha=.2); ax.legend()
        plot.save(fig, 'loss_' + name.replace('/', '_'),
                  'Measured training history. MLP loss is its training objective (with regularization); no fabricated validation curve.')
        if any('error' in measures for measures in history.values()):
            fig, axes = plt.subplots(1, 2, figsize=(12, 4))
            for partition, measures in history.items():
                if 'error' in measures:
                    axes[0].plot(np.arange(1,len(measures['error'])+1),1-np.asarray(measures['error']),label=partition)
                if 'auc' in measures:
                    axes[1].plot(np.arange(1,len(measures['auc'])+1),measures['auc'],label=partition)
            for ax, metric in zip(axes, ('Accuracy at threshold 0.5', 'ROC-AUC')):
                ax.set(title=f'{name}: {metric}',xlabel='Boosting round',ylabel=metric,ylim=(0,1.02))
                ax.grid(alpha=.2);ax.legend()
            plot.save(fig, 'learning_' + name.replace('/', '_'),
                      'Measured train/validation metrics by boosting round. Test is never used to monitor training.')


def evaluation_figures(output, y, scores, thresholds, results, booster=None, feature_labels=None):
    plot = Figures(output)
    results = list(results)
    pd.DataFrame(results).to_csv(Path(output) / 'evaluation-metrics.csv', index=False)
    fig, axes = plt.subplots(1, 2, figsize=(13, max(4, .45*len(results))))
    for ax, metric in zip(axes, ('f1', 'fpr')):
        ax.barh([r['model'] for r in results], [r[metric] for r in results], color=COLORS[0 if metric == 'f1' else 1])
        ax.set(xlim=(0, 1.08), title=f'Held-out test: {metric.upper()}')
        for i, r in enumerate(results): ax.text(r[metric], i, f' {r[metric]:.3f}', va='center', fontsize=8)
    plot.save(fig, '07_model_comparison', 'Same held-out test per run. Models can use different representations; see algorithm contracts.')

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig_cal, cal_ax = plt.subplots(figsize=(8, 5))
    for i, (name, values) in enumerate(scores.items()):
        values = np.asarray(values)
        threshold = thresholds[name]
        fig_cm, cm_ax = plt.subplots(figsize=(6, 5))
        cm = confusion_matrix(y, values >= threshold, labels=[0, 1])
        ConfusionMatrixDisplay(cm, display_labels=['Benign', 'Attack']).plot(ax=cm_ax, colorbar=False, cmap='Blues', values_format='d')
        cm_ax.set_title(f'{name}: threshold={threshold:g}')
        plot.save(fig_cm, f'cm_{name}', 'Held-out test. Rows: actual class; columns: predicted class. Counts, not percentages.')
        color = COLORS[i % len(COLORS)]
        if len(set(y)) == 2:
            fpr, tpr, _ = roc_curve(y, values)
            precision, recall, _ = precision_recall_curve(y, values)
            axes[0].plot(fpr, tpr, color=color, label=f'{name} AUC={auc(fpr,tpr):.3f}')
            axes[1].plot(recall, precision, color=color, label=f'{name} AP={average_precision_score(y,values):.3f}')
            frac, mean = calibration_curve(y, values, n_bins=10)
            cal_ax.plot(mean, frac, marker='o', color=color, label=name)
        fig_s, s_ax = plt.subplots(figsize=(8, 4))
        for label, color_s in ((0, COLORS[0]), (1, COLORS[1])):
            s_ax.hist(values[np.asarray(y) == label], bins=np.linspace(0, 1, 26), alpha=.6,
                      color=color_s, label='Attack' if label else 'Benign')
        s_ax.axvline(threshold, color='#333333', linestyle='--', label=f'Deployed threshold {threshold:g}')
        s_ax.set(title=f'{name}: test score distribution', xlabel='Score', ylabel='Rows'); s_ax.legend()
        plot.save(fig_s, f'scores_{name}', 'Scores are risk estimates; hybrid/anomaly scores are not guaranteed calibrated probabilities.')
    axes[0].plot([0, 1], [0, 1], '--', color='#777777')
    axes[0].set(title='Held-out test ROC', xlabel='False positive rate', ylabel='True positive rate', xlim=(0,1), ylim=(0,1.02))
    axes[1].axhline(float(np.mean(y)), linestyle='--', color='#777777', label='Attack prevalence')
    axes[1].set(title='Held-out test Precision–Recall', xlabel='Recall', ylabel='Precision', xlim=(0,1), ylim=(0,1.02))
    for ax in axes: ax.legend(fontsize=7)
    plot.save(fig, '08_roc_pr', 'PR is useful for rare attacks. AP is average precision, not trapezoidal PR area.')
    cal_ax.plot([0,1], [0,1], '--', color='#777777')
    cal_ax.set(title='Held-out test reliability', xlabel='Mean predicted score', ylabel='Observed attack fraction', xlim=(0,1), ylim=(0,1))
    cal_ax.legend(fontsize=7)
    plot.save(fig_cal, '09_calibration', 'Diagnostic only: this plot does not fit a calibrator or change decision thresholds.')
    if booster is not None:
        importance = booster.get_score(importance_type='gain')
        names = feature_labels or {}
        values = pd.Series({names.get(k, k): v for k, v in importance.items()}, dtype=float).sort_values().tail(20)
        if len(values):
            fig, ax = plt.subplots(figsize=(10, max(4, .3*len(values))))
            ax.barh(values.index, values.values, color=COLORS[0])
            ax.set(title='Network XGBoost: feature importance', xlabel='Average split gain')
            plot.save(fig, '10_feature_importance', 'Gain describes fitted tree splits; it is not causal attribution or a SHAP explanation.')
            values.to_csv(Path(output) / 'feature-importance.csv', header=['gain'])


def show_run(output, names=None):
    """Display a bounded gallery in Colab; every generated image remains on Drive."""
    from IPython.display import Image, display, Markdown
    out = Path(output)
    metrics_path = out / 'evaluation-metrics.csv'
    if metrics_path.exists(): display(pd.read_csv(metrics_path))
    items = json.loads((out / 'figures-index.json').read_text(encoding='utf-8'))
    chosen = [i for i in items if names is None or i['name'] in names]
    for item in chosen:
        display(Markdown(f"**{item['name']}** — {item['caption']}"))
        display(Image(filename=str(out/'figures'/f"{item['name']}.png"), width=1000))
    print(f'All {len(items)} PNG/SVG pairs:', out/'figures')


def preview_csv(folder, max_rows=5000):
    """Bounded raw preview before training; never load all CSVs into notebook RAM."""
    files = sorted(Path(folder).rglob('*.csv'))
    if not files: raise ValueError('No CSV files found')
    print('CSV files:', len(files), '| Preview only:', files[0].name)
    frame = pd.read_csv(files[0], nrows=max_rows, encoding_errors='replace', low_memory=False)
    from IPython.display import display
    display(frame.head(8))
    display(frame.describe(include='all').T)
    print('Preview rows:', len(frame), 'Columns:', len(frame.columns), '| This is not the full dataset distribution.')
