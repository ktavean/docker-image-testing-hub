import { useState, useCallback, useEffect } from 'react'
import UploadZone from './components/UploadZone'
import LiveConsole from './components/LiveConsole'
import ScanHistory from './components/ScanHistory'
import RemediatePanel from './components/RemediatePanel'
import ScoreSummary from './components/ScoreSummary'
import ImageResultPanel from './components/ImageResultPanel'
import { Shield } from 'lucide-react'
import { loadHistory, appendScan, getScan, deleteScan, clearHistory } from './lib/localStore'

export default function App() {
  const [logs,          setLogs]          = useState([])
  const [scanning,      setScanning]      = useState(false)
  const [currentScanId, setCurrentScanId] = useState(null)
  const [summary,       setSummary]       = useState(null)
  const [jobKind,       setJobKind]       = useState('dockerfile_compose')
  // inregistrarea completa a scanarii (activa sau din istoric)
  // folosita de RemediatePanel si pentru descarcarea raportului -> backendul
  // e stateless, nu are baza de date => are nevoie de continutul fisierelor on-demand
  const [activeScan,    setActiveScan]    = useState(null)
  // lista istoric scanare; incarcata o data la montare, apoi actualizata local
  // cand se termina o scanare sau cand utilizatorul sterge o intrare
  const [history,       setHistory]       = useState([])

  // incarc din localStorage la prima randare a DOMului
  useEffect(() => { setHistory(loadHistory()) }, [])

  // ascult streamul de la /api/jobs/{id}/stream si adaug evenimentele in interfata pe masura ce le primesc
  // rezultatul complet vine in evenimentul de la final -> nu dau un GET separat
  // salvez in localStorage doar la final => reload in timpul scanarii pierde tot
  const consumeStream = useCallback(async (job_id, kind) => {
    setCurrentScanId(job_id)
    setJobKind(kind)
    setActiveScan(null)
    try {
      const streamRes = await fetch(`/api/jobs/${job_id}/stream`)
      if (!streamRes.ok) throw new Error(`Stream failed: ${streamRes.status}`)

      // citesc streamul si parsez SSE; EventSource nu suporta POST,
      // si oricum vreau control pe reconectare si anulare
      const reader  = streamRes.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        // un fragment poate taia un mesaj JSON in doua, asa ca adaug mesajul in buffer,
        // impart pe linii noi si pastrez ultima linie (posibil incompleta) pentru
        // iteratia urmatoare
        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() ?? ''

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          const raw = line.slice(6).trim()
          if (!raw) continue
          try {
            const event = JSON.parse(raw)

            // eveniment de sumar intermediar; scanerul il emite spre final cu
            // contoarele per instrument; apare doar la scanarile de sursa
            if (event.type === 'summary' && kind === 'dockerfile_compose') {
              setSummary({
                hadolint: event.hadolint, trivy: event.trivy,
                package:  event.package,  cis:   event.cis,
                files:    event.files || [], total: event.total ?? 0,
              })
              setLogs(prev => [...prev, event])
              continue
            }

            // evenimentul final; event.scan contine rezultatul complet trimis de
            // backend, aceeasi forma pe care o salvez in localStorage
            if (event.type === 'finish') {
              const scan = event.scan
              if (scan) {
                // salvez scanarile completed/failed/cancelled; skip daca starea
                // lipseste cumva (desi nu cred ca o sa se intample)
                if (scan.job_status) {
                  appendScan(scan)
                  setHistory(loadHistory())
                }
                setActiveScan(scan)

                // joburile de imagine n-au event de sumar separat in flow,
                // asa ca aici construiesc datele pentru panou din rezultatul final
                if (kind === 'image') {
                  setSummary({
                    verdict:        scan.verdict,
                    total_findings: scan.total_findings,
                    ...(scan.summary || {}),
                  })
                } else {
                  // la scanarile de sursa pastrez numarul de probleme per scanner din
                  // summaryul anterior si adaug peste verdictul si punctajul final
                  setSummary(prev => ({
                    ...(prev || {}),
                    verdict:        scan.verdict,
                    total_findings: scan.total_findings,
                    summary:        scan.summary,
                  }))
                }
              }
              continue
            }

            setLogs(prev => [...prev, event])
          } catch {
            // daca e vreo linie JSON stricata, o sar in loc sa opresc tot flowul
          }
        }
      }
    } catch (e) {
      setLogs(prev => [...prev, { tool: 'system', type: 'error', message: `✗ ${e.message}` }])
    } finally {
      setScanning(false)
    }
  }, [])

  // POST scan Dockerfile / Compose
  const handleScan = useCallback(async (filesArr, selection, imageInput = null) => {
    setScanning(true); setLogs([]); setSummary(null); setCurrentScanId(null)

    const formData = new FormData()
    const arr = Array.isArray(filesArr) ? filesArr : [filesArr]
    for (const f of arr) formData.append('files', f, f.name)
    if (selection) formData.append('scanners', JSON.stringify(selection))

    // scanare combinata cu imaginea construita (daca a fost uploadata)
    if (imageInput) {
      if (imageInput.kind === 'tarball' && imageInput.file) {
        formData.append('image_tarball', imageInput.file, imageInput.file.name)
      } else if (imageInput.kind === 'ref' && imageInput.ref) {
        formData.append('image_ref', imageInput.ref)
      }
    }

    try {
      const submitRes = await fetch('/api/jobs', { method: 'POST', body: formData })
      if (!submitRes.ok) {
        const err = await submitRes.json().catch(() => ({}))
        throw new Error(err.detail || `Submit failed: ${submitRes.status}`)
      }
      const { job_id, kind } = await submitRes.json()
      // serverul imi spune ce pipeline a ales: 'dockerfile_compose', 'combined'
      // sau 'image'. folosesc asta ca sa stiu ce sa afisez mai departe
      await consumeStream(job_id, kind || 'dockerfile_compose')
    } catch (e) {
      setLogs(prev => [...prev, { tool: 'system', type: 'error', message: `✗ ${e.message}` }])
      setScanning(false)
    }
  }, [consumeStream])

  // incarc o scanare veche din localStorage si o afisez
  // reconstruiesc panoul de sumar de la zero, fiindca nu e salvat separat;
  // singurul lucru salvat e scanarea in sine
  const handleSelectHistoryScan = useCallback((scanId) => {
    const scan = getScan(scanId)
    if (!scan) return
    setCurrentScanId(scanId)
    setJobKind(scan.job_kind || 'dockerfile_compose')
    setLogs(scan.events || [])
    setActiveScan(scan)

    if (scan.job_kind === 'image') {
      setSummary({
        verdict:        scan.verdict,
        total_findings: scan.total_findings,
        ...(scan.summary || {}),
      })
    } else {
      // iau numarul de evenimente per instrument din summary daca exista in
      // loguri; daca nu, folosesc totalurile de pe scanarea salvata ca backup
      const summaryEvent = (scan.events || []).find(e => e.type === 'summary')
      setSummary({
        hadolint:       summaryEvent?.hadolint ?? scan.hadolint_issues ?? 0,
        trivy:          summaryEvent?.trivy    ?? scan.trivy_issues    ?? 0,
        package:        summaryEvent?.package  ?? scan.package_issues  ?? 0,
        cis:            summaryEvent?.cis      ?? scan.cis_issues      ?? 0,
        files:          summaryEvent?.files    ?? [],
        total:          summaryEvent?.total    ?? 0,
        verdict:        scan.verdict,
        total_findings: scan.total_findings,
        summary:        scan.summary,
      })
    }
  }, [])

  const handleDeleteHistoryScan = useCallback((scanId) => {
    deleteScan(scanId)
    setHistory(loadHistory())
    if (currentScanId === scanId) {
      setCurrentScanId(null); setActiveScan(null)
      setSummary(null); setLogs([])
    }
  }, [currentScanId])

  const handleClearHistory = useCallback(() => {
    clearHistory()
    setHistory([])
    setCurrentScanId(null); setActiveScan(null)
    setSummary(null); setLogs([])
  }, [])

  const handleCancel = useCallback(async () => {
    if (!currentScanId) return
    try {
      await fetch(`/api/jobs/${currentScanId}/cancel`, { method: 'POST' })
    } catch (e) { console.error('cancel failed', e) }
  }, [currentScanId])

  return (
    <div className="app">
      <header className="header">
        <div className="header-inner">
          <div className="logo">
            <Shield size={20} strokeWidth={1.5} />
            <span className="logo-text">DOCKER<span className="logo-accent">IMAGES HUB</span></span>
            <span className="logo-sub">Testing Suite</span>
          </div>
          <div className="header-right">
            <span className="tool-tag">hadolint</span>
            <span className="tool-tag">trivy</span>
            <span className="tool-tag">osv</span>
            <span className="tool-tag">nvd</span>
            <span className="tool-tag">cis</span>
            <span className="tool-tag">dive</span>
          </div>
        </div>
      </header>

      <main className="main">
        <div className="left-col">
          <UploadZone
            onScan={handleScan}
            scanning={scanning}
          />
          {summary && (
            jobKind === 'image'
              ? <ImageResultPanel summary={summary} scan={activeScan}/>
              : <ScoreSummary summary={summary} scan={activeScan}/>
          )}
          <LiveConsole
            logs={logs}
            scanning={scanning}
            scanId={currentScanId}
            onCancel={handleCancel}
          />
        </div>
        <div className="right-col">
          <ScanHistory
            history={history}
            activeScanId={currentScanId}
            onSelectScan={handleSelectHistoryScan}
            onDeleteScan={handleDeleteHistoryScan}
            onClearAll={handleClearHistory}
          />
          {/* remedierea e doar pentru Dockerfile; o ascund la joburile de imagine */}
          {jobKind !== 'image' && (
            <RemediatePanel scan={activeScan} disabled={scanning}/>
          )}
        </div>
      </main>

      <style>{`
        .app { min-height:100vh; display:flex; flex-direction:column; background:var(--bg); }
        .header { border-bottom:1px solid var(--border); background:var(--surface); position:sticky; top:0; z-index:10; }
        .header-inner { max-width:1280px; margin:0 auto; padding:0 24px; height:56px; display:flex; align-items:center; justify-content:space-between; }
        .logo { display:flex; align-items:baseline; gap:10px; color:var(--accent); }
        .logo > svg { align-self:center; }                  /* iconita ramane centrata vertical fata de text */
        .logo-text { font-family:var(--font-display); font-size:22px; font-weight:700; letter-spacing:.1em; color:var(--text); line-height:1; }
        .logo-accent { color:var(--accent); }
        .logo-sub { font-family:var(--font-mono); font-size:10px; color:var(--text-dim); letter-spacing:.1em; border-left:1px solid var(--border-bright); padding-left:10px; margin-left:4px; line-height:1; text-indent:.1em; }
        .header-right { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
        .tool-tag { font-family:var(--font-mono); font-size:10px; color:var(--text-dim); border:1px solid var(--border); padding:3px 9px; border-radius:3px; letter-spacing:.05em; }
        .main { flex:1; max-width:1280px; margin:0 auto; width:100%; padding:28px 24px; display:grid; grid-template-columns:1fr 340px; gap:20px; align-items:start; }
        .left-col { display:flex; flex-direction:column; gap:16px; }
        .right-col { display:flex; flex-direction:column; gap:16px; position:sticky; top:72px; }
        @media (max-width:900px) { .main { grid-template-columns:1fr; } .right-col { position:static; } }
      `}</style>
    </div>
  )
}
