import { useState } from 'react'
import { Clock, FileCode, Package, Trash2, X } from 'lucide-react'

function SeverityBadge({ count, color, label }) {
  return (
    <span className="sev-badge" style={{ '--c': color }}>
      {count} {label}
      <style>{`
        .sev-badge { font-family:var(--font-mono); font-size:10px; color:var(--c); background:color-mix(in srgb, var(--c) 12%, transparent); border:1px solid color-mix(in srgb, var(--c) 30%, transparent); padding:2px 7px; border-radius:3px; white-space:nowrap; }
      `}</style>
    </span>
  )
}

export default function ScanHistory({
  history,
  activeScanId,
  onSelectScan,
  onDeleteScan,
  onClearAll,
}) {
  const [confirmingClear, setConfirmingClear] = useState(false)

  const formatDate = (iso) => {
    if (!iso) return '—'
    try {
      // backendul da date ISO in UTC fara Z la final; il adaug eu, ca
      // constructorul Date sa nu le interpreteze ca ora locala
      const d = new Date(iso + (iso.endsWith('Z') ? '' : 'Z'))
      return d.toLocaleString(undefined, {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
      })
    } catch { return iso }
  }

  const totalIssues = (s) =>
    (s.hadolint_issues || 0) + (s.trivy_issues || 0) +
    (s.package_issues || 0) + (s.cis_issues || 0)

  const handleDeleteClick = (e, id) => {
    // opresc clickul sa ajunga la handlerul onSelect al randului
    e.stopPropagation()
    if (onDeleteScan) onDeleteScan(id)
  }

  // confirmare in doua clickuri: primul il armeaza, al doilea in 3s chiar
  // sterge; asa evit un modal pentru o actiune distructiva dar reversibila
  const handleClearClick = () => {
    if (!confirmingClear) {
      setConfirmingClear(true)
      setTimeout(() => setConfirmingClear(false), 3000)
      return
    }
    setConfirmingClear(false)
    if (onClearAll) onClearAll()
  }

  return (
    <div className="history-wrap">
      <div className="history-header">
        <Clock size={13} />
        <span>SCAN HISTORY</span>
        <span className="history-count">{history.length}</span>
        {history.length > 0 && (
          <button
            className={`history-clear ${confirmingClear ? 'confirming' : ''}`}
            onClick={handleClearClick}
            title={confirmingClear ? 'Click again to confirm' : 'Clear all history'}
          >
            <Trash2 size={11} />
            {confirmingClear ? 'Confirm?' : 'Clear'}
          </button>
        )}
      </div>

      <div className="history-list">
        {history.length === 0 && (
          <div className="history-empty">
            No scans yet.<br/>
            <span className="history-empty-sub">History is kept in this browser only.</span>
          </div>
        )}

        {history.map(scan => {
          const isImage = scan.job_kind === 'image'
          const Icon   = isImage ? Package : FileCode
          return (
            <div key={scan.id}
              className={`history-item ${activeScanId === scan.id ? 'active' : ''}`}
              onClick={() => onSelectScan(scan.id)}
              role="button" tabIndex={0}
              onKeyDown={(e) => e.key === 'Enter' && onSelectScan(scan.id)}>
              <div className="history-item-top">
                <Icon size={12} style={{ color: isImage ? 'var(--amber)' : 'var(--accent)', flexShrink: 0 }} />
                <span className="history-filename">{scan.filename || scan.label}</span>
                <span className={`history-kind kind-${isImage ? 'image' : 'src'}`}>
                  {isImage ? 'image' : 'src'}
                </span>
                <span className={`history-status ${scan.job_status}`}>{scan.job_status}</span>
                <button
                  className="history-del"
                  onClick={(e) => handleDeleteClick(e, scan.id)}
                  title="Delete this scan from history"
                >
                  <X size={11} />
                </button>
              </div>
              <div className="history-item-bottom">
                <span className="history-date">{formatDate(scan.created_at)}</span>
                <div className="history-badges">
                  {isImage ? (
                    scan.total_findings > 0 ? (
                      <SeverityBadge count={scan.total_findings} color="#2ba39c" label="ISSUES" />
                    ) : scan.job_status === 'completed' ? (
                      <span style={{ fontSize: 10, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>
                        ✓ efficient
                      </span>
                    ) : null
                  ) : (
                    <>
                      {scan.hadolint_issues > 0 && <SeverityBadge count={scan.hadolint_issues} color="#4aa3e6" label="HL" />}
                      {scan.trivy_issues    > 0 && <SeverityBadge count={scan.trivy_issues}    color="#2ba39c" label="TV" />}
                      {scan.package_issues  > 0 && <SeverityBadge count={scan.package_issues}  color="#e08a30" label="PKG" />}
                      {scan.cis_issues      > 0 && <SeverityBadge count={scan.cis_issues}      color="#2fa86a" label="CIS" />}
                      {totalIssues(scan) === 0 && scan.job_status === 'completed' && (
                        <span style={{ fontSize: 10, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>✓ clean</span>
                      )}
                    </>
                  )}
                </div>
              </div>
            </div>
          )
        })}
      </div>

      <style>{`
        .history-wrap { border:1px solid var(--border); border-radius:var(--radius-lg); overflow:hidden; background:var(--surface); }
        .history-header { display:flex; align-items:center; gap:7px; padding:10px 14px; background:var(--surface-2); border-bottom:1px solid var(--border); font-family:var(--font-mono); font-size:10px; font-weight:600; color:var(--text-muted); letter-spacing:0.1em; }
        .history-count { color: var(--accent); }
        .history-clear {
          margin-left: auto;
          display: inline-flex; align-items: center; gap: 4px;
          background: none; border: 1px solid var(--border-bright);
          color: var(--text-muted);
          font-family: var(--font-mono); font-size: 10px;
          padding: 2px 7px; border-radius: 3px;
          cursor: pointer; transition: all .15s;
          letter-spacing: .04em;
        }
        .history-clear:hover { color: var(--red); border-color: rgba(229,72,77,.35); }
        .history-clear.confirming {
          color: var(--red); border-color: var(--red);
          background: rgba(229,72,77,.10);
        }

        .history-list { max-height:420px; overflow-y:auto; }
        .history-empty {
          padding:28px 16px; text-align:center;
          color:var(--text-dim);
          font-family:var(--font-mono); font-size:11px; line-height:1.6;
        }
        .history-empty-sub { color: var(--text-dim); opacity:.65; font-size: 10px; }
        .history-item {
          display: block;
          width:100%; text-align:left;
          background:none; border:none;
          border-bottom:1px solid var(--border);
          padding:10px 14px;
          cursor:pointer; transition:background .15s;
          color:var(--text);
        }
        .history-item:last-child { border-bottom:none; }
        .history-item:hover { background:var(--surface-2); }
        .history-item.active { background:var(--surface-3); box-shadow: inset 2px 0 0 var(--accent); }
        .history-item-top { display:flex; align-items:center; gap:6px; margin-bottom:5px; }
        .history-filename { font-family:var(--font-mono); font-size:12px; font-weight:500; flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
        .history-kind {
          font-family:var(--font-mono); font-size:9px;
          letter-spacing:.08em; padding:1px 5px; border-radius:2px;
          text-transform:uppercase; font-weight:600;
          border:1px solid;
        }
        .history-kind.kind-src   { color: var(--accent); border-color: var(--accent-dim); background: var(--accent-glow); }
        .history-kind.kind-image { color: var(--amber);  border-color: rgba(224,152,46,.3); background: rgba(224,152,46,.10); }
        .history-status { font-family:var(--font-mono); font-size:9px; letter-spacing:.08em; padding:2px 6px; border-radius:2px; text-transform:uppercase; font-weight:600; }
        .history-status.done,.history-status.completed { color:var(--accent); background:var(--accent-glow); }
        .history-status.running { color:var(--amber); background:rgba(224,152,46,.12); }
        .history-status.error,.history-status.failed { color:var(--red); background:rgba(229,72,77,.12); }
        .history-status.cancelled { color:var(--text-dim); background:var(--surface-2); }
        .history-del {
          background: none; border: none; padding: 2px;
          color: var(--text-dim); cursor: pointer;
          display: flex; align-items: center; opacity: 0;
          transition: opacity .15s, color .15s;
        }
        .history-item:hover .history-del { opacity: 0.65; }
        .history-del:hover { opacity: 1 !important; color: var(--red); }

        .history-item-bottom { display:flex; align-items:center; justify-content:space-between; gap:8px; }
        .history-date { font-family:var(--font-mono); font-size:10px; color:var(--text-dim); }
        .history-badges { display:flex; gap:4px; flex-wrap:wrap; }
      `}</style>
    </div>
  )
}
