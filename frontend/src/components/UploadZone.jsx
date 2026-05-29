import { useState, useRef, useCallback, useMemo } from 'react'
import { Upload, FileCode, AlertCircle, X, Settings, Package, Globe } from 'lucide-react'

function classifyFile(name) {
  const n = name.toLowerCase()
  if (n.startsWith('dockerfile') || n.endsWith('.dockerfile')) return 'dockerfile'
  if (n.startsWith('docker-compose') && (n.endsWith('.yml') || n.endsWith('.yaml'))) return 'compose'
  if (n === 'compose.yml' || n === 'compose.yaml') return 'compose'
  return 'unknown'
}

function isTarball(name) {
  const n = name.toLowerCase()
  return n.endsWith('.tar') || n.endsWith('.tar.gz') || n.endsWith('.tgz')
}

// matricea de aplicabilitate; fiecare scaner declara ce tipuri de intrare poate
// analiza, plus motivul pentru care e sarit altfel; o folosesc ca sa estompez
// scannerele neaplicabile in interfata, cu un tooltip care explica de ce
//
// "Trivy Image CVEs" e impartit in doua intrari, cu disponibilitate diferita:
//   - trivy_image_base   : aduce imaginea din FROM declarata in Dockerfile
//                          (inainte de construire, fara artefact construit)
//   - trivy_image_built  : scaneaza imaginea chiar construita de utilizator, fie
//                          incarcata ca arhiva docker-archive, fie adusa
//                          dintr-o referinta de registru (dupa construire)
const SCANNERS = [
  { id: 'hadolint',     label: 'Hadolint',          desc: 'Dockerfile linter & best-practices checks',
    appliesTo: ['dockerfile'],
    skipReason: 'Hadolint lints Dockerfile text — no Dockerfile in this scan.' },
  { id: 'trivy_config', label: 'Trivy Misconfig',   desc: 'Dockerfile/Compose misconfiguration detection',
    appliesTo: ['dockerfile', 'compose'],
    skipReason: 'Trivy config scans Dockerfile/compose source — no source file in this scan.' },
  { id: 'trivy_secret', label: 'Trivy Secrets',     desc: 'Hardcoded API keys, tokens, passwords',
    appliesTo: ['dockerfile', 'compose'],
    skipReason: 'Trivy secret scanning runs against source files — no source file in this scan.' },
  { id: 'trivy_image_base',  label: 'Trivy — base image', desc: 'Pulls the FROM image declared in the Dockerfile and scans it for CVEs (pre-build)',
    appliesTo: ['dockerfile'],
    skipReason: 'Pre-build scan of the FROM image — needs a Dockerfile to know which base to pull.',
    // imaginea de baza e un subset strict al imaginii construite; orice CVE
    // gasit scanand baza apare si scanand arhiva/referinta; cand utilizatorul
    // da una dintre ele, marchez scanerul ca redundant in loc sa-l rulez de doua ori
    redundantWhen: (kinds) => kinds.has('tarball') || kinds.has('ref'),
    redundantReason: 'Skipped — the supplied built image already includes the base layers; CVEs are caught by Trivy — built image.' },
  { id: 'trivy_image_built', label: 'Trivy — built image', desc: 'Scans the supplied built image (tarball or registry reference) for CVEs',
    appliesTo: ['tarball', 'ref'],
    skipReason: 'Post-build scan — add a tarball (.tar/.tar.gz) or paste a registry reference to enable.' },
  { id: 'package',      label: 'Package CVEs',      desc: 'OSV.dev with NVD fallback for declared packages',
    appliesTo: ['dockerfile'],
    skipReason: 'Reads packages declared in RUN apt/apk/pip/npm install — needs a Dockerfile.' },
  { id: 'cis',          label: 'CIS Advisor',       desc: 'CIS Docker Benchmark — Ch. 4 (Dockerfile) + Ch. 5 (compose)',
    appliesTo: ['dockerfile', 'compose'],
    skipReason: 'CIS Chapter 4 needs a Dockerfile; Chapter 5 needs a compose YAML.' },
  { id: 'dive',         label: 'Dive (layer analysis)', desc: 'Layer efficiency, wasted space, image size',
    appliesTo: ['tarball', 'ref'],
    skipReason: 'Inspects built-image layers — add a tarball or registry reference to enable.' },
]

const DEFAULT_SELECTION = SCANNERS.reduce((acc, s) => ({ ...acc, [s.id]: true }), {})


export default function UploadZone({ onScan, scanning }) {
  const [dragging, setDragging] = useState(false)
  const [error,    setError]    = useState(null)
  const [files,    setFiles]    = useState([])         // fisiere dockerfile/compose
  const [tarball,  setTarball]  = useState(null)       // arhiva de imagine optionala
  const [imageRef, setImageRef] = useState('')         // referinta de registru optionala
  const [selection, setSelection] = useState(DEFAULT_SELECTION)
  const fileRef = useRef()

  // stare derivata
  const allSelected  = Object.values(selection).every(Boolean)
  const noneSelected = Object.values(selection).every(v => !v)
  const enabledCount = Object.values(selection).filter(Boolean).length
  const hasAnyInput  = files.length > 0 || tarball || imageRef.trim().length > 0

  // ce tipuri de intrare exista acum; de aici porneste matricea de aplicabilitate
  const inputKinds = useMemo(() => {
    const kinds = new Set()
    for (const f of files) kinds.add(classifyFile(f.name))
    if (tarball) kinds.add('tarball')
    if (imageRef.trim()) kinds.add('ref')
    return kinds
  }, [files, tarball, imageRef])

  const scannerApplicability = useMemo(() => {
    const out = {}
    for (const s of SCANNERS) {
      if (inputKinds.size === 0) {
        out[s.id] = null                                  // neutru, inca n-a incarcat nimic
        continue
      }
      // intai verific redundanta: un scaner poate fi aplicabil dar inutil
      // fiindca alt scaner il acopera deja
      if (s.redundantWhen && s.redundantWhen(inputKinds)) {
        out[s.id] = 'redundant'
        continue
      }
      out[s.id] = s.appliesTo.some(k => inputKinds.has(k))
    }
    return out
  }, [inputKinds])

  // lucrul cu fisierele
  const addFiles = useCallback((newFiles) => {
    setError(null)
    const valid = [], invalid = []
    let tarballPicked = null
    for (const f of newFiles) {
      if (isTarball(f.name)) {
        if (f.size > 500 * 1024 * 1024) {
          invalid.push(`${f.name} (tarball exceeds 500 MB)`)
          continue
        }
        tarballPicked = f
        continue
      }
      const kind = classifyFile(f.name)
      if (kind === 'unknown') invalid.push(f.name)
      else valid.push(f)
    }
    if (invalid.length) setError(`Skipped: ${invalid.join(', ')}`)
    if (tarballPicked) setTarball(tarballPicked)
    setFiles(prev => {
      const seen = new Set(prev.map(f => f.name))
      const merged = [...prev]
      for (const f of valid) if (!seen.has(f.name)) { merged.push(f); seen.add(f.name) }
      return merged
    })
  }, [])

  const removeFile     = (i) => setFiles(prev => prev.filter((_, idx) => idx !== i))
  const clearTarball   = ()  => setTarball(null)

  const onDrop = (e) => {
    e.preventDefault(); setDragging(false)
    if (scanning) return
    addFiles(Array.from(e.dataTransfer.files))
  }
  const onInputChange = (e) => { addFiles(Array.from(e.target.files)); e.target.value = '' }

  // selectarea scannerelor
  const toggleScanner = (id) => setSelection(prev => ({ ...prev, [id]: !prev[id] }))
  const toggleAll = () => {
    const newVal = !allSelected
    setSelection(SCANNERS.reduce((acc, s) => ({ ...acc, [s.id]: newVal }), {}))
  }

  // frontendul foloseste `trivy_image_base` (Dockerfile, inainte de construire) si
  // `trivy_image_built` (dupa construire, arhiva/referinta) ca doua intrari distincte,
  // dar backendul are un singur flag `trivy_image` pentru aducerea imaginii de baza
  // le mapez inapoi pe ID-urile backendului la iesire si fortez pe off orice scaner
  // marcat redundant; utilizatorul nu poate reactiva unul redundant din interfata,
  // dar raman defensiv in caz ca selectia a fost setata inainte sa apara redundanta
  const mapSelectionForBackend = (sel) => {
    const out = {}
    for (const [k, v] of Object.entries(sel)) {
      const effective = scannerApplicability[k] === 'redundant' ? false : v
      if (k === 'trivy_image_base')  out['trivy_image'] = effective
      else if (k === 'trivy_image_built' || k === 'dive') continue   // nu fac parte din flagurile de mod sursa
      else out[k] = effective
    }
    return out
  }

  // trimiterea
  const handleScanClick = () => {
    if (!hasAnyInput || scanning || noneSelected) return
    const imageInput = tarball
      ? { kind: 'tarball', file: tarball }
      : imageRef.trim()
        ? { kind: 'ref', ref: imageRef.trim() }
        : null
    onScan(files, mapSelectionForBackend(selection), imageInput)
    setFiles([])
    setTarball(null)
    setImageRef('')
  }

  // ajutoare pentru etichetele din interfata
  const submitLabel = () => {
    if (noneSelected) return 'Select at least one scanner'
    if (!hasAnyInput)  return 'Add files or a registry reference'
    const parts = []
    if (files.length > 0) parts.push(`${files.length} file${files.length !== 1 ? 's' : ''}`)
    if (tarball)          parts.push('tarball')
    if (imageRef.trim())  parts.push('image ref')
    return `Start scan (${parts.join(' + ')}, ${enabledCount} scanner${enabledCount !== 1 ? 's' : ''})`
  }

  return (
    <div>
      {/* ───────── Step 1: add files ───────── */}
      <div className="step-header">
        <span className="step-num">STEP 1</span>
        <span className="step-label">Add files</span>
      </div>

      <div
        className={`upload-zone ${dragging ? 'dragging' : ''} ${scanning ? 'disabled' : ''}`}
        onDragOver={(e) => { e.preventDefault(); if (!scanning) setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => !scanning && fileRef.current?.click()}
        role="button" tabIndex={scanning ? -1 : 0}
        onKeyDown={(e) => e.key === 'Enter' && !scanning && fileRef.current?.click()}
      >
        <input ref={fileRef} type="file" hidden multiple accept="*" onChange={onInputChange}/>
        <div className="upload-icon">
          {scanning ? <div className="spinner"/> : <FileCode size={32} strokeWidth={1.5}/>}
        </div>
        <div className="upload-title">
          {scanning   ? 'Scanning...' :
           dragging   ? 'Drop files here' :
           hasAnyInput ? 'Add more files' : 'Upload files'}
        </div>
        <div className="upload-subtitle">
          Dockerfile · docker-compose.yml · .tar(.gz) of a built image
        </div>
      </div>

      {/* Files list — everything together: source + tarball */}
      {(files.length > 0 || tarball) && (
        <div className="file-list">
          <div className="file-list-header">
            <span>{files.length + (tarball ? 1 : 0)} item{(files.length + (tarball ? 1 : 0)) !== 1 ? 's' : ''} ready</span>
          </div>
          {files.map((f, i) => {
            const kind = classifyFile(f.name)
            return (
              <div key={f.name} className="file-row">
                <FileCode size={12} style={{ color: kind === 'compose' ? 'var(--amber)' : 'var(--accent)' }}/>
                <span className="file-row-name">{f.name}</span>
                <span className={`file-row-kind kind-${kind}`}>{kind}</span>
                <button className="file-row-remove" onClick={() => removeFile(i)} disabled={scanning}>
                  <X size={12}/>
                </button>
              </div>
            )
          })}
          {tarball && (
            <div className="file-row">
              <Package size={12} style={{ color: 'var(--accent)' }}/>
              <span className="file-row-name">{tarball.name}</span>
              <span className="file-row-kind kind-tarball">tarball</span>
              <button className="file-row-remove" onClick={clearTarball} disabled={scanning}>
                <X size={12}/>
              </button>
            </div>
          )}
        </div>
      )}

      {/* Image-reference text input (alternative to a tarball) */}
      <div className="image-ref-zone">
        <div className="image-ref-zone-label">
          <Globe size={11} strokeWidth={1.75}/>
          <span>OR · public image reference</span>
        </div>
        <input
          type="text"
          className="image-ref-input-large"
          placeholder="docker.io/library/nginx:1.27-alpine"
          value={imageRef}
          onChange={(e) => setImageRef(e.target.value)}
          disabled={scanning || !!tarball}
        />
        {tarball && (
          <div className="image-ref-zone-hint">
            Tarball already selected — clear it to enable a registry reference.
          </div>
        )}
      </div>

      {error && <div className="upload-error"><AlertCircle size={14}/>{error}</div>}

      {/* ───────── Step 2: select scanners ───────── */}
      <div className="step-header" style={{ marginTop: 18 }}>
        <span className="step-num">STEP 2</span>
        <span className="step-label">Select scanners</span>
      </div>

      <div className="tool-selector">
        <div className="tool-selector-header">
          <Settings size={12} />
          <span>{enabledCount}/{SCANNERS.length} enabled</span>
          <button className="tool-selector-toggle-all" onClick={toggleAll} disabled={scanning}>
            {allSelected ? 'None' : 'All'}
          </button>
        </div>
        <div className="tool-selector-grid">
          {SCANNERS.map(s => {
            const checked      = selection[s.id]
            const applicable   = scannerApplicability[s.id]
            const isSkipped    = applicable === false
            const isRedundant  = applicable === 'redundant'
            const isDisabled   = isSkipped || isRedundant
            const reason       = isRedundant ? s.redundantReason : s.skipReason
            const tag          = isRedundant ? '· redundant' : (isSkipped ? '· skipped' : '')
            return (
              <label
                key={s.id}
                className={`tool-card ${checked && !isDisabled ? 'checked' : ''} ${scanning ? 'disabled' : ''} ${isDisabled ? 'not-applicable' : ''} ${isRedundant ? 'redundant' : ''}`}
                title={isDisabled ? reason : s.desc}
              >
                <input type="checkbox"
                       checked={checked && !isDisabled}
                       onChange={() => toggleScanner(s.id)}
                       disabled={scanning || isDisabled}/>
                <div className="tool-card-content">
                  <div className="tool-card-label">
                    {s.label}
                    {tag && <span className={`tool-card-skipped${isRedundant ? ' redundant' : ''}`}> {tag}</span>}
                  </div>
                  <div className="tool-card-desc">
                    {isDisabled ? reason : s.desc}
                  </div>
                </div>
              </label>
            )
          })}
        </div>
      </div>

      {/* ───────── Step 3: run ───────── */}
      <button
        className="scan-btn"
        style={{ marginTop: 14 }}
        onClick={handleScanClick}
        disabled={!hasAnyInput || scanning || noneSelected}
      >
        <Upload size={14}/>
        {submitLabel()}
      </button>

      <style>{`
        .step-header {
          display: flex; align-items: center; gap: 10px;
          margin-bottom: 8px;
          justify-content: center;
        }
        .step-num {
          display: inline-flex; align-items: center; justify-content: center;
          font-family: var(--font-mono); font-size: 10px; font-weight: 700;
          line-height: 1;
          letter-spacing: 0.10em; color: var(--accent);
          /* Compensate the trailing letter-spacing — without it the text
             visually sits left of center because letter-spacing adds
             space after every char including the last one. */
          text-indent: 0.10em;
          background: var(--accent-glow); border: 1px solid var(--accent-dim);
          padding: 4px 7px; border-radius: 3px;
        }
        .step-label {
          font-family: var(--font-display); font-size: 13px; font-weight: 600;
          letter-spacing: 0.06em; color: var(--text);
          line-height: 1;
        }

        .upload-zone {
          border: 1.5px dashed var(--border-bright);
          border-radius: var(--radius-lg);
          padding: 32px 28px; text-align: center;
          cursor: pointer; transition: all 0.2s ease;
          background: var(--surface);
          position: relative; overflow: hidden;
          margin-bottom: 14px;
        }
        .upload-zone::before {
          content: ''; position: absolute; inset: 0;
          background: radial-gradient(ellipse at 50% 0%, var(--accent-glow) 0%, transparent 70%);
          opacity: 0; transition: opacity 0.3s;
        }
        .upload-zone:hover::before, .upload-zone.dragging::before { opacity: 1; }
        .upload-zone:hover, .upload-zone.dragging {
          border-color: var(--accent-dim); transform: translateY(-1px);
        }
        .upload-zone.disabled { cursor: not-allowed; opacity: 0.7; }
        .upload-icon { color: var(--accent); margin-bottom: 12px; display: flex; justify-content: center; }
        .upload-title {
          font-family: var(--font-display); font-size: 17px; font-weight: 600;
          letter-spacing: 0.05em; color: var(--text); margin-bottom: 4px;
        }
        .upload-subtitle {
          font-family: var(--font-mono); font-size: 11px; color: var(--text-dim);
        }

        .file-list {
          background: var(--surface); border-radius: var(--radius);
          padding: 8px 12px; margin-bottom: 14px;
          border: 1px solid var(--border);
        }
        .file-list-header {
          font-family: var(--font-mono); font-size: 10px; font-weight: 600;
          letter-spacing: 0.08em; color: var(--text-dim);
          padding-bottom: 6px;
          border-bottom: 1px solid var(--border);
          margin-bottom: 4px;
        }
        .file-row {
          display: flex; align-items: center; gap: 8px;
          padding: 6px 0; font-size: 12px;
        }
        .file-row-name {
          font-family: var(--font-mono); color: var(--text);
          flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
        }
        .file-row-kind {
          font-family: var(--font-mono); font-size: 9.5px; font-weight: 600;
          letter-spacing: 0.06em; padding: 1px 6px; border-radius: 3px;
          background: var(--surface-2); color: var(--text-dim);
          text-transform: uppercase;
        }
        .kind-dockerfile { color: var(--accent); background: rgba(36,150,237,0.10); }
        .kind-compose    { color: var(--amber);  background: rgba(245,166,35,0.10); }
        .kind-tarball    { color: var(--accent); background: rgba(36,150,237,0.10); }
        .file-row-remove {
          background: transparent; border: none; cursor: pointer;
          color: var(--text-dim); padding: 2px; display: flex;
        }
        .file-row-remove:hover:not(:disabled) { color: var(--accent); }

        .image-ref-zone {
          margin-bottom: 14px; padding: 10px 12px;
          background: var(--surface);
          border: 1px solid var(--border); border-radius: var(--radius);
        }
        .image-ref-zone-label {
          display: flex; align-items: center; gap: 6px;
          font-family: var(--font-mono); font-size: 10.5px;
          letter-spacing: 0.08em; color: var(--text-dim);
          margin-bottom: 6px;
        }
        .image-ref-input-large {
          width: 100%; box-sizing: border-box;
          background: var(--surface-2); border: 1px solid var(--border);
          border-radius: var(--radius); padding: 7px 10px;
          font-family: var(--font-mono); font-size: 12px;
          color: var(--text); outline: none;
        }
        .image-ref-input-large:focus { border-color: var(--accent-dim); }
        .image-ref-input-large:disabled {
          opacity: 0.55; cursor: not-allowed;
        }
        .image-ref-input-large::placeholder { color: var(--text-dim); }
        .image-ref-zone-hint {
          margin-top: 6px;
          font-family: var(--font-mono); font-size: 10px; color: var(--text-dim);
        }

        .tool-selector {
          background: var(--surface); border-radius: var(--radius);
          padding: 0; margin-bottom: 8px;
          border: 1px solid var(--border);
        }
        .tool-selector-header {
          display: flex; align-items: center; gap: 8px;
          padding: 8px 12px;
          border-bottom: 1px solid var(--border);
          font-family: var(--font-mono); font-size: 10.5px;
          letter-spacing: 0.08em; color: var(--text-dim);
        }
        .tool-selector-toggle-all {
          margin-left: auto; padding: 2px 8px;
          background: var(--surface-2); border: 1px solid var(--border);
          color: var(--text-dim); cursor: pointer;
          font-family: var(--font-mono); font-size: 10px;
          border-radius: 3px; transition: all 0.15s;
        }
        .tool-selector-toggle-all:hover:not(:disabled) { color: var(--accent); border-color: var(--accent-dim); }

        .tool-selector-grid {
          display: grid; grid-template-columns: repeat(2, 1fr);
          gap: 1px; background: var(--border); padding: 1px;
        }
        .tool-card {
          display: flex; gap: 8px; padding: 10px 12px;
          background: var(--surface); cursor: pointer;
          transition: background 0.15s; align-items: flex-start;
        }
        .tool-card:hover:not(.disabled):not(.not-applicable) { background: var(--surface-2); }
        .tool-card.checked {
          background: rgba(36,150,237,0.04);
          box-shadow: inset 2px 0 0 var(--accent);
        }
        .tool-card.disabled { cursor: not-allowed; opacity: 0.6; }
        .tool-card.not-applicable {
          opacity: 0.45; cursor: not-allowed;
          background: var(--surface); box-shadow: none;
        }
        .tool-card.not-applicable:hover { background: var(--surface); }
        .tool-card.not-applicable input { cursor: not-allowed; }
        .tool-card.not-applicable .tool-card-label { color: var(--text-dim); }
        .tool-card-skipped {
          font-family: var(--font-mono); font-size: 10px;
          color: var(--amber); font-weight: 500;
          margin-left: 2px;
        }
        .tool-card-skipped.redundant { color: var(--accent); }
        .tool-card input[type="checkbox"] {
          margin-top: 2px; accent-color: var(--accent);
          cursor: pointer; flex-shrink: 0;
        }
        .tool-card.disabled input { cursor: not-allowed; }
        .tool-card-label {
          font-family: var(--font-mono); font-size: 12px; font-weight: 600;
          color: var(--text); margin-bottom: 2px;
        }
        .tool-card.checked .tool-card-label { color: var(--accent); }
        .tool-card-desc { font-size: 10.5px; color: var(--text-dim); line-height: 1.4; }

        .scan-btn {
          width: 100%; display: inline-flex; align-items: center; justify-content: center;
          gap: 10px; padding: 12px 20px;
          background: var(--accent); color: var(--background);
          border: none; border-radius: var(--radius);
          font-family: var(--font-display); font-size: 13px; font-weight: 600;
          letter-spacing: 0.06em;
          cursor: pointer; transition: all 0.15s;
        }
        .scan-btn:hover:not(:disabled) {
          filter: brightness(1.10); transform: translateY(-1px);
        }
        .scan-btn:disabled {
          opacity: 0.45; cursor: not-allowed;
        }

        .upload-error {
          display: flex; align-items: center; gap: 8px;
          margin-bottom: 12px; padding: 8px 12px;
          background: rgba(228,77,77,0.08);
          border: 1px solid rgba(228,77,77,0.3);
          border-radius: var(--radius);
          font-family: var(--font-mono); font-size: 11px;
          color: var(--red);
        }

        .spinner {
          width: 24px; height: 24px;
          border: 2px solid var(--border);
          border-top-color: var(--accent);
          border-radius: 50%;
          animation: spin 0.8s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}
