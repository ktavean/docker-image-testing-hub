import { Package, AlertTriangle, AlertOctagon, Info, ShieldCheck, Layers, HardDrive, Trash2, FileDown } from 'lucide-react'

const VERDICT_STYLES = {
  PASS:     { color: 'var(--accent)', bg: 'var(--accent-glow)',         border: 'var(--accent-dim)',         icon: ShieldCheck,    label: 'PASS' },
  INFO:     { color: '#4aa3e6',       bg: 'rgba(74,163,230,0.10)',     border: 'rgba(74,163,230,0.30)',     icon: Info,           label: 'INFO' },
  WARNING:  { color: 'var(--amber)',  bg: 'rgba(224,152,46,0.10)',     border: 'rgba(224,152,46,0.30)',     icon: AlertTriangle,  label: 'WARNING' },
  CRITICAL: { color: 'var(--red)',    bg: 'rgba(229,72,77,0.12)',      border: 'rgba(229,72,77,0.35)',      icon: AlertOctagon,   label: 'CRITICAL' },
}

const OVERALL_STYLES = {
  APPROVED:        { color: 'var(--accent)', bg: 'var(--accent-glow)',     border: 'var(--accent-dim)',     icon: ShieldCheck,   label: 'EFFICIENT' },
  WARNING:         { color: 'var(--amber)',  bg: 'rgba(224,152,46,.10)',   border: 'rgba(224,152,46,.30)',  icon: AlertTriangle, label: 'BLOATED' },
  POLICY_REJECTED: { color: 'var(--red)',    bg: 'rgba(229,72,77,.12)',    border: 'rgba(229,72,77,.35)',   icon: AlertOctagon,  label: 'WASTEFUL' },
  PENDING:         { color: 'var(--text-dim)', bg: 'var(--surface-2)',     border: 'var(--border)',         icon: Info,          label: 'PENDING' },
}

const CATEGORY_ICONS = {
  image_size:       HardDrive,
  layer_efficiency: Layers,
  wasted_space:     Trash2,
}

function humanSize(bytes) {
  if (!bytes && bytes !== 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB']
  let n = bytes
  for (const u of units) {
    if (n < 1024) return `${n.toFixed(1)} ${u}`
    n /= 1024
  }
  return `${n.toFixed(1)} TB`
}

function CategoryRow({ id, cat }) {
  const v = VERDICT_STYLES[cat.verdict] || VERDICT_STYLES.PASS
  const Icon = CATEGORY_ICONS[id] || Info
  const VIcon = v.icon

  return (
    <div className="img-cat-row" style={{ borderColor: v.border, background: v.bg }}>
      <div className="img-cat-row-icon" style={{ color: v.color }}>
        <Icon size={16} strokeWidth={1.5} />
      </div>
      <div className="img-cat-row-main">
        <div className="img-cat-row-label">{cat.label}</div>
        <div className="img-cat-row-desc">{cat.description}</div>
      </div>
      <div className="img-cat-row-metric">{cat.metric}</div>
      <div className="img-cat-row-verdict" style={{ color: v.color, borderColor: v.border }}>
        <VIcon size={11} strokeWidth={2} />
        {v.label}
      </div>
    </div>
  )
}

export default function ImageResultPanel({ summary, scan }) {
  if (!summary) return null

  const overall = OVERALL_STYLES[summary.verdict] || OVERALL_STYLES.PENDING
  const OIcon   = overall.icon
  const img     = summary.image_summary || {}
  const cats    = summary.categories   || {}
  const topWaste = img.top_waste_files || []
  const scanId  = scan?.id || null

  // caut evenimentul SBOM emis de backend din stream_trivy_for_image_input
  // la scanarile de imagine, el duce JSON-ul CycloneDX inline
  const sbomEvent = (scan?.events || []).find(
    e => e.tool === 'sbom' && e.type === 'result' && e.content,
  )

  const downloadReport = async () => {
    if (!scan) return
    try {
      const res = await fetch('/api/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(scan),
      })
      if (!res.ok) throw new Error(`Report failed: ${res.status}`)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `dhh-image-report-${(scanId || 'scan').slice(0,8)}.txt`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      console.error('Report download failed:', e)
    }
  }

  const downloadSbom = () => {
    if (!sbomEvent) return
    const blob = new Blob([sbomEvent.content], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `dhh-sbom-${(scanId || 'scan').slice(0,8)}.cdx.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="img-panel">
      {/* Top: overall verdict ribbon */}
      <div className="img-verdict-bar" style={{ background: overall.bg, borderColor: overall.border }}>
        <div className="img-verdict-icon" style={{ color: overall.color }}>
          <OIcon size={22} strokeWidth={1.75} />
        </div>
        <div className="img-verdict-text">
          <div className="img-verdict-label" style={{ color: overall.color }}>{overall.label}</div>
          <div className="img-verdict-sub">Image layer efficiency analysis · {summary.total_findings ?? 0} issue(s)</div>
        </div>
        {scan && (
          <div className="img-action-btns">
            {sbomEvent && (
              <button className="img-report-btn" onClick={downloadSbom}
                      title={`Download CycloneDX SBOM — ${sbomEvent.components_count} components`}>
                <FileDown size={12}/> SBOM <span className="img-action-pill">{sbomEvent.components_count}</span>
              </button>
            )}
            <button className="img-report-btn" onClick={downloadReport}>
              <FileDown size={12}/> Report
            </button>
          </div>
        )}
      </div>

      {/* Headline numbers */}
      <div className="img-stats">
        <div className="img-stat">
          <div className="img-stat-label">Total Size</div>
          <div className="img-stat-value">{humanSize(img.size_bytes)}</div>
          <div className="img-stat-foot">{img.layer_count || 0} layer(s)</div>
        </div>
        <div className="img-stat">
          <div className="img-stat-label">Efficiency</div>
          <div className="img-stat-value">{((img.efficiency ?? 1) * 100).toFixed(1)}%</div>
          <div className="img-stat-foot">{img.efficiency < 1 ? 'duplicated layer data' : 'no duplication'}</div>
        </div>
        <div className="img-stat">
          <div className="img-stat-label">Wasted</div>
          <div className="img-stat-value">{humanSize(img.wasted_bytes)}</div>
          <div className="img-stat-foot">
            {img.size_bytes > 0
              ? `${((img.wasted_bytes / img.size_bytes) * 100).toFixed(1)}% of total`
              : 'no data'}
          </div>
        </div>
      </div>

      {/* Category breakdown */}
      <div className="img-cats">
        {Object.entries(cats).map(([id, cat]) => (
          <CategoryRow key={id} id={id} cat={cat} />
        ))}
      </div>

      {/* Top wasted-space files */}
      {topWaste.length > 0 && (
        <div className="img-waste">
          <div className="img-waste-header">
            <Trash2 size={11} />
            <span>TOP WASTED-SPACE FILES</span>
          </div>
          {topWaste.map((w, i) => (
            <div key={i} className="img-waste-row">
              <Package size={12} style={{ color: 'var(--amber)', flexShrink: 0 }} />
              <span className="img-waste-path">{w.path}</span>
              <span className="img-waste-size">{humanSize(w.size)}</span>
              <span className="img-waste-count">×{w.count} layers</span>
            </div>
          ))}
        </div>
      )}

      <style>{`
        .img-panel {
          display: flex; flex-direction: column; gap: 14px;
          border: 1px solid var(--border); border-radius: var(--radius-lg);
          background: var(--surface); padding: 16px;
        }
        .img-verdict-bar {
          display: flex; align-items: center; gap: 12px;
          padding: 12px 14px;
          border: 1px solid;
          border-radius: var(--radius);
        }
        .img-verdict-icon { display: flex; }
        .img-verdict-text { flex: 1; min-width: 0; }
        .img-verdict-label {
          font-family: var(--font-display);
          font-size: 18px; font-weight: 700;
          letter-spacing: 0.08em;
        }
        .img-verdict-sub {
          font-family: var(--font-mono); font-size: 11px;
          color: var(--text-muted); margin-top: 2px;
        }
        .img-report-btn {
          display: inline-flex; align-items: center; gap: 5px;
          font-family: var(--font-mono); font-size: 11px; font-weight: 600;
          background: var(--surface-2);
          border: 1px solid var(--border-bright);
          color: var(--text-muted);
          padding: 5px 10px; border-radius: 3px;
          cursor: pointer; transition: all .15s;
        }
        .img-report-btn:hover { color: var(--accent); border-color: var(--accent-dim); }
        .img-action-btns {
          display: inline-flex; gap: 6px; align-items: center;
        }
        .img-action-pill {
          display: inline-flex; align-items: center; justify-content: center;
          background: var(--accent-glow); color: var(--accent);
          font-size: 9.5px; font-weight: 700;
          padding: 1px 5px; border-radius: 2px;
          margin-left: 2px;
        }

        .img-stats {
          display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;
        }
        .img-stat {
          padding: 12px 14px; background: var(--surface-2);
          border: 1px solid var(--border); border-radius: var(--radius);
          display: flex; flex-direction: column; gap: 4px;
        }
        .img-stat-label {
          font-family: var(--font-mono); font-size: 9px;
          letter-spacing: 0.12em; color: var(--text-dim);
          text-transform: uppercase;
        }
        .img-stat-value {
          font-family: var(--font-display); font-size: 22px;
          font-weight: 700; color: var(--text);
          line-height: 1;
        }
        .img-stat-foot {
          font-family: var(--font-mono); font-size: 10px;
          color: var(--text-muted);
        }

        .img-cats {
          display: flex; flex-direction: column; gap: 6px;
        }
        .img-cat-row {
          display: grid;
          grid-template-columns: auto 1fr auto auto;
          align-items: center;
          gap: 12px;
          padding: 10px 12px;
          border: 1px solid; border-radius: var(--radius);
        }
        .img-cat-row-icon { display: flex; }
        .img-cat-row-label {
          font-family: var(--font-mono); font-size: 12px;
          font-weight: 600; color: var(--text);
        }
        .img-cat-row-desc {
          font-family: var(--font-mono); font-size: 10px;
          color: var(--text-dim); margin-top: 2px;
        }
        .img-cat-row-metric {
          font-family: var(--font-mono); font-size: 11px;
          color: var(--text-muted);
          white-space: nowrap;
        }
        .img-cat-row-verdict {
          display: inline-flex; align-items: center; gap: 4px;
          font-family: var(--font-mono); font-size: 10px;
          font-weight: 600; letter-spacing: 0.06em;
          padding: 3px 8px; border-radius: 3px;
          border: 1px solid;
          background: color-mix(in srgb, currentColor 6%, transparent);
        }

        .img-waste {
          border: 1px solid var(--border);
          border-radius: var(--radius);
          background: var(--surface-2);
          overflow: hidden;
        }
        .img-waste-header {
          display: flex; align-items: center; gap: 6px;
          padding: 8px 12px; border-bottom: 1px solid var(--border);
          font-family: var(--font-mono); font-size: 10px;
          font-weight: 600; color: var(--text-muted);
          letter-spacing: 0.1em;
        }
        .img-waste-row {
          display: flex; align-items: center; gap: 8px;
          padding: 7px 12px; border-bottom: 1px solid var(--border);
          font-family: var(--font-mono); font-size: 11px;
        }
        .img-waste-row:last-child { border-bottom: none; }
        .img-waste-path {
          flex: 1; color: var(--text);
          overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
        }
        .img-waste-size { color: var(--amber); white-space: nowrap; }
        .img-waste-count {
          color: var(--text-dim); font-size: 10px;
          white-space: nowrap;
        }

        @media (max-width: 600px) {
          .img-stats { grid-template-columns: 1fr; }
          .img-cat-row {
            grid-template-columns: auto 1fr auto;
          }
          .img-cat-row-metric { grid-column: 2 / -1; font-size: 10px; }
        }
      `}</style>
    </div>
  )
}
