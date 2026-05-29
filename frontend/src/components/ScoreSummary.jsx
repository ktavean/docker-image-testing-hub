import { ShieldAlert, ShieldCheck, ShieldX, FileDown, FileCode, AlertTriangle, AlertOctagon, Info } from 'lucide-react'

const VERDICT_STYLES = {
  PASS:     { color: 'var(--accent)',     bg: 'var(--accent-glow)',           border: 'var(--accent-dim)',         icon: ShieldCheck,    label: 'PASS' },
  INFO:     { color: '#4aa3e6',           bg: 'rgba(74,163,230,0.10)',       border: 'rgba(74,163,230,0.30)',     icon: Info,           label: 'INFO' },
  WARNING:  { color: 'var(--amber)',      bg: 'rgba(224,152,46,0.10)',       border: 'rgba(224,152,46,0.30)',     icon: AlertTriangle,  label: 'WARNING' },
  CRITICAL: { color: 'var(--red)',        bg: 'rgba(229,72,77,0.12)',        border: 'rgba(229,72,77,0.35)',      icon: AlertOctagon,   label: 'CRITICAL' },
}

function CategoryRow({ cat }) {
  const v = VERDICT_STYLES[cat.verdict] || VERDICT_STYLES.PASS
  const Icon = v.icon
  // construiesc un rezumat scurt de severitati, ex. "2 critical · 5 high"
  const sevs = cat.severities || {}
  const sevOrder = ['critical', 'high', 'medium', 'low', 'error', 'warning', 'info', 'style']
  const sevPills = sevOrder.filter(s => sevs[s]).map(s => `${sevs[s]} ${s}`).join(' · ')

  return (
    <div className="cat-row" style={{borderColor: v.border, background: v.bg}}>
      <div className="cat-row-icon" style={{color: v.color}}>
        <Icon size={14} />
      </div>
      <div className="cat-row-main">
        <div className="cat-row-label">{cat.label}</div>
        <div className="cat-row-desc">{cat.description}</div>
      </div>
      <div className="cat-row-meta">
        <div className="cat-row-count" style={{color: v.color}}>{cat.count}</div>
        <div className="cat-row-verdict" style={{color: v.color, borderColor: v.border}}>{v.label}</div>
      </div>
      {sevPills && (
        <div className="cat-row-sevs">{sevPills}</div>
      )}
      <style>{`
        .cat-row {
          display: grid;
          grid-template-columns: 18px 1fr auto;
          grid-template-rows: auto auto;
          gap: 4px 10px;
          padding: 8px 12px;
          border: 1px solid;
          border-radius: 4px;
          align-items: center;
        }
        .cat-row-icon { grid-row: 1 / span 2; align-self: center; }
        .cat-row-main { display: flex; flex-direction: column; gap: 1px; }
        .cat-row-label { font-family: var(--font-display); font-size: 12.5px; font-weight: 600; color: var(--text); letter-spacing: 0.02em; }
        .cat-row-desc { font-size: 10.5px; color: var(--text-dim); font-family: var(--font-mono); }
        .cat-row-meta { display: flex; align-items: center; gap: 8px; }
        .cat-row-count { font-family: var(--font-mono); font-size: 18px; font-weight: 700; line-height: 1; }
        .cat-row-verdict {
          font-family: var(--font-mono); font-size: 9.5px; font-weight: 700;
          padding: 2px 6px; border: 1px solid; border-radius: 2px;
          letter-spacing: 0.06em;
        }
        .cat-row-sevs {
          grid-column: 2 / span 2;
          font-family: var(--font-mono); font-size: 10px;
          color: var(--text-muted);
        }
      `}</style>
    </div>
  )
}

function PolicyBadge({ policy }) {
  if (!policy || policy === 'PENDING') return null
  if (policy === 'POLICY_REJECTED') {
    return (
      <div className="policy-badge rejected">
        <ShieldX size={13} /> POLICY REJECTED
        <style>{`
          .policy-badge { display:inline-flex; align-items:center; gap:6px; font-family:var(--font-mono); font-size:11px; font-weight:700; letter-spacing:0.06em; padding:5px 12px; border-radius:3px; }
          .policy-badge.rejected { color:var(--red); background:rgba(229,72,77,0.12); border:1px solid rgba(229,72,77,0.35); }
        `}</style>
      </div>
    )
  }
  if (policy === 'WARNING') {
    return (
      <div className="policy-badge warn">
        <AlertTriangle size={13} /> NEEDS REVIEW
        <style>{`
          .policy-badge { display:inline-flex; align-items:center; gap:6px; font-family:var(--font-mono); font-size:11px; font-weight:700; letter-spacing:0.06em; padding:5px 12px; border-radius:3px; }
          .policy-badge.warn { color:var(--amber); background:rgba(224,152,46,0.12); border:1px solid rgba(224,152,46,0.35); }
        `}</style>
      </div>
    )
  }
  return (
    <div className="policy-badge approved">
      <ShieldCheck size={13} /> APPROVED
      <style>{`
        .policy-badge { display:inline-flex; align-items:center; gap:6px; font-family:var(--font-mono); font-size:11px; font-weight:700; letter-spacing:0.06em; padding:5px 12px; border-radius:3px; }
        .policy-badge.approved { color:var(--accent); background:var(--accent-glow); border:1px solid var(--accent-dim); }
      `}</style>
    </div>
  )
}

export default function ScoreSummary({ summary, scan }) {
  if (!summary) return null

  const total      = summary.total ?? summary.total_findings ?? 0
  const clean      = total === 0
  const files      = summary.files || []
  const verdict    = summary.verdict ?? null
  const categories = summary.summary?.categories ?? null
  const scanId     = scan?.id || null

  // ordonez categoriile, cele critice primele
  const CATEGORY_ORDER = ['secrets', 'critical_misconfig', 'cve_base_image', 'cve_packages', 'best_practices', 'code_quality']

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
      a.download = `dhh-report-${(scanId || 'scan').slice(0,8)}.txt`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      console.error('Report download failed:', e)
    }
  }

  // scanarile combinate (Dockerfile + arhiva/referinta) emit si un eveniment SBOM
  // ImageResultPanel se ocupa de cele doar-imagine; ramura asta trateaza cazul
  // combinat, cand panoul vizibil e ScoreSummary
  const sbomEvent = (scan?.events || []).find(
    e => e.tool === 'sbom' && e.type === 'result' && e.content,
  )
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
    <div className="score-wrap">
      <div className="score-top-row">
        <div className="score-total">
          {clean
            ? <><ShieldCheck size={22} style={{color:'var(--accent)'}} /><span style={{color:'var(--accent)'}}>Clean</span></>
            : <><ShieldAlert size={22} style={{color:'var(--amber)'}} /><span style={{color:'var(--amber)'}}>{total} Findings</span></>}
        </div>
        <div className="score-actions">
          <PolicyBadge policy={verdict} />
          {scan && sbomEvent && (
            <button className="report-btn" onClick={downloadSbom}
                    title={`Download CycloneDX SBOM — ${sbomEvent.components_count} components`}>
              <FileDown size={12} /> SBOM
              <span className="sbom-count-pill">{sbomEvent.components_count}</span>
            </button>
          )}
          {scan && (
            <button className="report-btn" onClick={downloadReport}>
              <FileDown size={12} /> Report
            </button>
          )}
        </div>
      </div>

      {categories && (
        <div className="cat-section">
          <div className="cat-header">VERDICT BY CATEGORY</div>
          <div className="cat-list">
            {CATEGORY_ORDER.map(catId => (
              categories[catId] ? <CategoryRow key={catId} cat={categories[catId]} /> : null
            ))}
          </div>
        </div>
      )}

      {files.length > 1 && (
        <div className="per-file">
          <div className="per-file-header">PER-FILE BREAKDOWN</div>
          {files.map((f, i) => (
            <div key={i} className="per-file-row">
              <FileCode size={11} style={{color: f.kind==='compose' ? 'var(--amber)' : 'var(--accent)', flexShrink:0}} />
              <span className="per-file-name">{f.file}</span>
              <span className={`per-file-kind kind-${f.kind}`}>{f.kind}</span>
              <span className="per-file-count">{f.total} issue{f.total!==1?'s':''}</span>
            </div>
          ))}
        </div>
      )}

      <style>{`
        .score-wrap { border:1px solid var(--border); border-radius:var(--radius-lg); background:var(--surface); padding:16px; display:flex; flex-direction:column; gap:14px; }
        .score-top-row { display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap; }
        .score-actions { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
        .score-total { display:flex; align-items:center; gap:8px; font-family:var(--font-display); font-size:22px; font-weight:700; letter-spacing:0.04em; }
        .report-btn { display:inline-flex; align-items:center; gap:5px; font-family:var(--font-mono); font-size:11px; background:var(--surface-2); border:1px solid var(--border-bright); color:var(--text-muted); padding:5px 10px; border-radius:3px; text-decoration:none; font-weight:600; transition:all .15s; cursor:pointer; }
        .report-btn:hover { color:var(--accent); border-color:var(--accent-dim); }
        .sbom-count-pill { display:inline-flex; align-items:center; justify-content:center; background:var(--accent-glow); color:var(--accent); font-size:9.5px; font-weight:700; padding:1px 5px; border-radius:2px; margin-left:2px; }
        .cat-section { display:flex; flex-direction:column; gap:6px; }
        .cat-header { font-family:var(--font-mono); font-size:10px; letter-spacing:0.1em; color:var(--text-muted); }
        .cat-list { display:flex; flex-direction:column; gap:4px; }
        .per-file { border-top:1px solid var(--border); padding-top:10px; display:flex; flex-direction:column; gap:4px; }
        .per-file-header { font-family:var(--font-mono); font-size:10px; letter-spacing:0.1em; color:var(--text-muted); margin-bottom:4px; }
        .per-file-row { display:flex; align-items:center; gap:7px; padding:5px 8px; background:var(--surface-2); border-radius:3px; font-family:var(--font-mono); font-size:11.5px; }
        .per-file-name { flex:1; color:var(--text); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
        .per-file-kind { font-size:9px; padding:1px 5px; border-radius:2px; letter-spacing:.05em; text-transform:uppercase; }
        .per-file-kind.kind-dockerfile { color:var(--accent); background:var(--accent-glow); }
        .per-file-kind.kind-compose { color:var(--amber); background:rgba(224,152,46,.12); }
        .per-file-count { font-size:11px; color:var(--text-muted); }
      `}</style>
    </div>
  )
}
