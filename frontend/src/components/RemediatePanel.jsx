import { useState, useEffect } from 'react'
import { Wrench, Eye, CheckCircle2, AlertCircle, Download, ChevronDown, ChevronRight } from 'lucide-react'

const CONFIDENCE_COLORS = { HIGH: '#2fa86a', MEDIUM: '#e0982e', LOW: '#6a8198' }

function DiffBlock({ diff }) {
  const [open, setOpen] = useState(false)
  if (!diff) return null
  return (
    <div className="diff-wrap">
      <button className="diff-toggle" onClick={() => setOpen(o => !o)}>
        {open ? <ChevronDown size={11}/> : <ChevronRight size={11}/>}
        {open ? 'Hide diff' : 'Show diff'}
      </button>
      {open && (
        <pre className="diff-content">
          {diff.split('\n').map((line, i) => {
            let color = 'var(--text-muted)'
            if (line.startsWith('+') && !line.startsWith('+++')) color = 'var(--accent)'
            if (line.startsWith('-') && !line.startsWith('---')) color = 'var(--red)'
            if (line.startsWith('@@')) color = 'var(--blue)'
            return <span key={i} style={{color, display:'block'}}>{line}</span>
          })}
        </pre>
      )}
      <style>{`
        .diff-toggle { background:none; border:none; color:var(--text-dim); font-family:var(--font-mono); font-size:11px; cursor:pointer; display:flex; align-items:center; gap:4px; padding:4px 0; transition:color .15s; }
        .diff-toggle:hover { color:var(--text); }
        .diff-content { font-family:var(--font-mono); font-size:11px; line-height:1.6; padding:8px 12px; background:var(--terminal-bg); border-radius:3px; overflow:auto; max-height:240px; white-space:pre; }
      `}</style>
    </div>
  )
}

// RemediatePanel
// API fara stare: backendul nu mai tine inregistrarile scanarilor, asa ca trimit
// continutul fisierului din scanarea activa (citit din localStorage) direct la
// /api/remediate/preview si /api/remediate/apply
// props:
//   scan      inregistrarea scanarii active din localStorage (sau null)
//   disabled  true cat timp ruleaza alta scanare
export default function RemediatePanel({ scan, disabled }) {
  // masina de stari a panoului:
  //   inactiv -> incarcare previzualizare -> previzualizare -> incarcare aplicare -> gata
  //                     ↓                                  ↓
  //                   eroare  ←——————————————————————————— eroare
  const [phase,     setPhase]     = useState('idle')
  const [preview,   setPreview]   = useState(null)
  const [result,    setResult]    = useState(null)
  // approved: { [nume_fisier]: Set<fix_id> }; folosesc Set ca sa comut in O(1)
  // si ca numaratoarea selectiei sa nu mai aiba nevoie de eliminarea duplicatelor
  const [approved,  setApproved]  = useState({})
  const [error,     setError]     = useState(null)

  const scanId = scan?.id || null
  // construiesc lista de fisiere din inregistrarea scanarii; aceasta, salvata
  // in localStorage, contine continutul original incarcat de utilizator, exact
  // ce-i trebuie backendului fara stare ca sa calculeze reparatiile
  const filesForApi = (scan?.files || []).map(f => ({
    name:    f.name,
    kind:    f.kind,
    content: f.content ?? null,
  }))
  const hasContent = filesForApi.some(f => (f.kind === 'dockerfile' || f.kind === 'compose') && f.content != null)

  // resetez tot cand se schimba scanarea activa (utilizatorul a ales alta
  // scanare din istoric sau a pornit una noua)
  useEffect(() => {
    setPhase('idle')
    setPreview(null)
    setResult(null)
    setApproved({})
    setError(null)
  }, [scanId])

  const fetchPreview = async () => {
    if (!hasContent) return
    setPhase('loading-preview')
    setError(null)
    try {
      const res = await fetch('/api/remediate/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ files: filesForApi }),
      })
      if (!res.ok) throw new Error(await res.text())
      const data = await res.json()
      // bifez implicit reparatiile de incredere ridicata; utilizatorul le poate
      // debifa si poate bifa pe cele de incredere scazuta/medie daca vrea
      const init = {}
      for (const f of data.files) {
        init[f.file] = new Set(
          f.proposed_fixes.filter(fx => fx.confidence === 'HIGH').map(fx => fx.fix_id)
        )
      }
      setApproved(init)
      setPreview(data)
      setPhase('preview')
    } catch (e) { setError(e.message); setPhase('error') }
  }

  const toggleFix = (filename, fix_id) => {
    // fiecare apel trebuie sa produca un obiect approved nou SI un Set nou, altfel
    // React nu observa schimbarea (compara Set-ul dupa referinta)
    setApproved(prev => {
      const next = { ...prev, [filename]: new Set(prev[filename] || []) }
      next[filename].has(fix_id) ? next[filename].delete(fix_id) : next[filename].add(fix_id)
      return next
    })
  }

  const handleApply = async () => {
    setPhase('loading-apply')
    setError(null)
    const fixes = {}
    for (const [fname, ids] of Object.entries(approved)) fixes[fname] = [...ids]
    try {
      const res = await fetch('/api/remediate/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ files: filesForApi, fixes }),
      })
      if (!res.ok) throw new Error(await res.text())
      setResult(await res.json())
      setPhase('done')
    } catch (e) { setError(e.message); setPhase('error') }
  }

  const handleDownload = (fileIndex) => {
    if (!result || !result.files || !result.files[fileIndex]) return
    const f = result.files[fileIndex]
    const blob = new Blob([f.fixed_dockerfile], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${f.file}.hardened`
    a.click()
    URL.revokeObjectURL(url)
  }

  const totalSelected = Object.values(approved).reduce((s, ids) => s + ids.size, 0)

  return (
    <div className="rem-wrap">
      <div className="rem-header"><Wrench size={13} /><span>AUTO-REMEDIATE</span></div>
      <div className="rem-body">
        <p className="rem-desc">Preview proposed fixes with confidence levels before applying.</p>

        {phase === 'idle' && (
          <button className="rem-btn" onClick={fetchPreview} disabled={!hasContent || disabled}>
            <Eye size={14}/> Preview fixes
          </button>
        )}
        {phase === 'loading-preview' && (
          <button className="rem-btn" disabled><div className="btn-spinner"/> Analysing...</button>
        )}

        {phase === 'preview' && preview && (
          <div className="preview-wrap">
            {preview.files.length === 0 ? (
              <div className="rem-empty">
                <AlertCircle size={13}/> No Dockerfiles to remediate in this scan.
                {preview.skipped && preview.skipped.length > 0 && (
                  <div className="rem-skipped-note">
                    Skipped {preview.skipped.length} {preview.skipped.length === 1 ? 'file' : 'files'} (not Dockerfiles): {preview.skipped.map(s => s.file).join(', ')}
                  </div>
                )}
              </div>
            ) : (
              <>
                {preview.skipped && preview.skipped.length > 0 && (
                  <div className="rem-skipped-banner">
                    <AlertCircle size={11}/>
                    Skipping {preview.skipped.length} non-Dockerfile {preview.skipped.length === 1 ? 'file' : 'files'}: {preview.skipped.map(s => s.file).join(', ')}
                  </div>
                )}
                {preview.files.map(f => (
                  <div key={f.file} className="preview-file">
                    <div className="preview-file-name">{f.file}</div>
                    {f.proposed_fixes.length === 0 && <p className="no-fixes">No applicable fixes found.</p>}
                    {f.proposed_fixes.map(fx => {
                      const selected = (approved[f.file] || new Set()).has(fx.fix_id)
                      return (
                        <div key={fx.fix_id} className={`fix-card ${selected ? 'selected' : ''}`}
                             onClick={() => toggleFix(f.file, fx.fix_id)}>
                          <div className="fix-card-top">
                            <input type="checkbox" readOnly checked={selected} style={{accentColor:'var(--accent)', cursor:'pointer'}}/>
                            <span className="fix-rule">{fx.rule}</span>
                            <span className="fix-conf" style={{color: CONFIDENCE_COLORS[fx.confidence]}}>{fx.confidence}</span>
                          </div>
                          <p className="fix-desc">{fx.description}</p>
                          <DiffBlock diff={fx.diff} />
                        </div>
                      )
                    })}
                  </div>
                ))}
                <button className="rem-btn apply-btn" onClick={handleApply} disabled={totalSelected === 0}>
                  <CheckCircle2 size={14}/> Apply {totalSelected} selected fix{totalSelected !== 1 ? 'es' : ''}
                </button>
              </>
            )}
          </div>
        )}

        {phase === 'loading-apply' && (
          <button className="rem-btn" disabled><div className="btn-spinner"/> Applying fixes...</button>
        )}

        {phase === 'done' && result && (
          <div className="rem-result">
            <div className="rem-result-header">
              <CheckCircle2 size={14} style={{color:'var(--accent)'}}/>
              <span>{result.total_fixes} fix{result.total_fixes!==1?'es':''} across {result.file_count} file{result.file_count!==1?'s':''}</span>
            </div>
            {result.files?.map((f, i) => (
              <div key={i} className="rem-file-block">
                <div className="rem-file-header">
                  <span>{f.file} — {f.fix_count} fix{f.fix_count!==1?'es':''}</span>
                  {f.fix_count > 0 && (
                    <button className="download-btn" onClick={() => handleDownload(i)}>
                      <Download size={11}/> Download
                    </button>
                  )}
                </div>
                <ul className="rem-fixes">
                  {f.fixes_applied.length === 0
                    ? <li className="rem-fix-item" style={{color:'var(--text-dim)'}}>No fixes applied</li>
                    : f.fixes_applied.map((fix, j) => (
                        <li key={j} className="rem-fix-item"><span className="fix-dot">▸</span>{fix}</li>
                      ))}
                </ul>
              </div>
            ))}
            {result.skipped && result.skipped.length > 0 && (
              <div className="rem-file-block">
                <div className="rem-file-header" style={{color:'var(--amber)'}}>
                  Skipped {result.skipped.length} non-Dockerfile {result.skipped.length === 1 ? 'file' : 'files'}
                </div>
                <ul className="rem-fixes">
                  {result.skipped.map((s, j) => (
                    <li key={j} className="rem-fix-item" style={{color:'var(--text-dim)'}}>
                      <span className="fix-dot" style={{color:'var(--amber)'}}>○</span>
                      {s.file} ({s.kind})
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {phase === 'error' && <div className="rem-error"><AlertCircle size={13}/><span>{error || 'Failed'}</span></div>}
        {!hasContent && <p className="rem-hint">Run a scan first to enable remediation.</p>}
      </div>

      <style>{`
        .rem-wrap { border:1px solid var(--border); border-radius:var(--radius-lg); overflow:hidden; background:var(--surface); }
        .rem-header { display:flex; align-items:center; gap:7px; padding:10px 14px; background:var(--surface-2); border-bottom:1px solid var(--border); font-family:var(--font-mono); font-size:10px; font-weight:600; color:var(--text-muted); letter-spacing:.1em; }
        .rem-body { padding:16px; display:flex; flex-direction:column; gap:12px; }
        .rem-desc { font-size:12.5px; color:var(--text-muted); line-height:1.6; }
        .rem-btn { display:flex; align-items:center; gap:8px; padding:10px 20px; font-family:var(--font-display); font-size:14px; font-weight:600; letter-spacing:.05em; border-radius:var(--radius); border:1.5px solid var(--accent-dim); background:transparent; color:var(--accent); cursor:pointer; transition:all .2s; }
        .rem-btn:hover:not(:disabled) { background:var(--accent-glow); border-color:var(--accent); }
        .rem-btn:disabled { opacity:.4; cursor:not-allowed; }
        .apply-btn { width:100%; justify-content:center; margin-top:8px; }
        .btn-spinner { width:14px; height:14px; border:2px solid var(--border-bright); border-top-color:var(--accent); border-radius:50%; animation:spin .8s linear infinite; }
        @keyframes spin { to { transform:rotate(360deg); } }
        .preview-wrap { display:flex; flex-direction:column; gap:8px; }
        .preview-file { border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; }
        .preview-file-name { padding:6px 12px; background:var(--surface-2); border-bottom:1px solid var(--border); font-family:var(--font-mono); font-size:11px; color:var(--accent); }
        .no-fixes { font-family:var(--font-mono); font-size:11px; color:var(--text-dim); padding:10px 12px; }
        .fix-card { padding:10px 12px; border-bottom:1px solid var(--border); cursor:pointer; transition:background .15s; user-select:none; }
        .fix-card:last-child { border-bottom:none; }
        .fix-card:hover { background:var(--surface-2); }
        .fix-card.selected { background:rgba(36,150,237,0.04); }
        .fix-card-top { display:flex; align-items:center; gap:8px; margin-bottom:4px; }
        .fix-rule { font-family:var(--font-mono); font-size:11px; font-weight:700; color:var(--text); }
        .fix-conf { font-family:var(--font-mono); font-size:10px; font-weight:700; letter-spacing:.06em; margin-left:auto; }
        .fix-desc { font-size:12px; color:var(--text-muted); line-height:1.5; margin-bottom:4px; }
        .rem-result { border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; }
        .rem-result-header { display:flex; align-items:center; gap:8px; padding:8px 14px; background:var(--surface-2); font-family:var(--font-mono); font-size:12px; color:var(--accent); border-bottom:1px solid var(--border); }
        .download-btn { margin-left:auto; display:flex; align-items:center; gap:5px; font-family:var(--font-mono); font-size:11px; background:var(--accent-glow); border:1px solid var(--accent-dim); color:var(--accent); padding:4px 10px; border-radius:3px; cursor:pointer; transition:all .15s; font-weight:600; }
        .download-btn:hover { background:var(--accent); color:var(--bg); }
        .rem-file-block { border-bottom:1px solid var(--border); }
        .rem-file-block:last-child { border-bottom:none; }
        .rem-file-header { padding:7px 14px; background:var(--surface-2); border-bottom:1px solid var(--border); font-family:var(--font-mono); font-size:11px; color:var(--text); display:flex; align-items:center; justify-content:space-between; gap:8px; }
        .rem-fixes { list-style:none; padding:8px 14px; background:var(--terminal-bg); margin:0; }
        .rem-fix-item { display:flex; gap:8px; font-family:var(--font-mono); font-size:11.5px; color:var(--text); padding:2px 0; }
        .fix-dot { color:var(--accent); flex-shrink:0; }
        .rem-error { display:flex; align-items:center; gap:7px; font-family:var(--font-mono); font-size:12px; color:var(--red); }
        .rem-hint { font-size:11.5px; color:var(--text-dim); font-family:var(--font-mono); }
        .rem-empty {
          display:flex; flex-direction:column; gap:8px;
          padding:14px; background:var(--surface-2);
          border:1px solid var(--border); border-radius:var(--radius);
          font-family:var(--font-mono); font-size:12px; color:var(--text-muted);
        }
        .rem-empty > :first-child { display:flex; align-items:center; gap:7px; }
        .rem-skipped-note {
          font-size:11px; color:var(--text-dim);
          padding-left:20px; line-height:1.5;
        }
        .rem-skipped-banner {
          display:flex; align-items:center; gap:6px;
          padding:7px 10px; background:rgba(224,152,46,0.08);
          border:1px solid rgba(224,152,46,0.25); border-radius:3px;
          font-family:var(--font-mono); font-size:11px; color:var(--amber);
          margin-bottom:4px;
        }
      `}</style>
    </div>
  )
}
