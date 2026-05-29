import { useEffect, useRef } from 'react'
import { Terminal, ChevronRight, Square } from 'lucide-react'

const LEVEL_COLORS = {
  error: '#e5484d',
  warning: '#e0982e',
  info: '#4aa3e6',
  style: '#8593a8',
  ignore: '#6a8198',
  start: '#2fa86a',
  done: '#2fa86a',
  summary: '#2fa86a',
  issue: null, // se stabileste dupa campul level
}

const TOOL_COLORS = {
  hadolint: '#4aa3e6',
  trivy: '#2ba39c',
  package: '#e08a30',
  osv: '#e08a30',
  nvd: '#d4762a',
  'trivy-image': '#3fb8b0',
  'trivy-secret': '#e5484d',
  cis: '#2fa86a',
  'compose-advisor': '#2fa86a',
  system: '#2496ed',
}

function LogLine({ event }) {
  const toolColor = TOOL_COLORS[event.tool] || '#c9d6e3'
  const typeColor = LEVEL_COLORS[event.type] || (event.level ? LEVEL_COLORS[event.level] : '#c9d6e3')
  const msgColor = event.type === 'issue'
    ? (LEVEL_COLORS[event.level] || '#c9d6e3')
    : typeColor || '#c9d6e3'

  // randare speciala pentru liniile din blocul de sumar (fara eticheta de instrument, culoare accent)
  const summaryTypes = new Set([
    'summary_divider', 'summary_header', 'summary_file',
    'summary_item', 'summary_total', 'file_start', 'file_summary'
  ])
  const isSummaryLine = summaryTypes.has(event.type)

  if (isSummaryLine) {
    let color = 'var(--accent)'
    if (event.type === 'summary_divider') color = 'var(--accent-dim)'
    else if (event.type === 'summary_item') color = 'var(--text)'
    else if (event.type === 'summary_file') color = 'var(--text)'
    else if (event.type === 'file_summary') color = 'var(--text-muted)'
    else if (event.type === 'file_start') color = 'var(--accent)'
    return (
      <div className={`log-line ${event.type}`}>
        <span className="log-msg-summary" style={{ color }}>{event.message}</span>
        <style>{`
          .log-line {
            font-family: var(--font-mono);
            font-size: 12.5px;
            line-height: 1.7;
            padding: 1px 0;
            animation: fadeIn 0.15s ease;
          }
          .log-line.summary_header {
            font-weight: 700;
            font-size: 13px;
            letter-spacing: 0.04em;
            padding-top: 4px;
          }
          .log-line.summary_total {
            font-weight: 700;
            padding: 4px 0;
          }
          .log-line.file_start {
            padding-top: 12px;
            font-weight: 600;
          }
          .log-msg-summary { white-space: pre; }
          @keyframes fadeIn { from { opacity: 0; transform: translateX(-4px); } to { opacity: 1; } }
        `}</style>
      </div>
    )
  }

  return (
    <div className={`log-line ${event.type}`}>
      {event.type !== 'summary' && (
        <span className="log-tool" style={{ color: toolColor }}>
          [{event.tool?.toUpperCase()?.padEnd(8)}]
        </span>
      )}
      {event.type === 'summary' && (
        <span className="log-separator">{'─'.repeat(4)} </span>
      )}
      <span className="log-msg" style={{ color: msgColor }}>
        {event.message}
      </span>
      <style>{`
        .log-line {
          display: flex;
          align-items: baseline;
          gap: 10px;
          padding: 2px 0;
          font-family: var(--font-mono);
          font-size: 12.5px;
          line-height: 1.7;
          animation: fadeIn 0.15s ease;
        }
        .log-line.start { padding-top: 10px; }
        .log-line.summary {
          padding: 8px 0 4px;
          font-weight: 700;
          font-size: 13px;
          letter-spacing: 0.03em;
        }
        .log-tool {
          flex-shrink: 0;
          font-weight: 500;
          letter-spacing: 0.03em;
          font-size: 11px;
        }
        .log-separator {
          color: var(--text-dim);
          flex-shrink: 0;
        }
        .log-msg { word-break: break-word; }
        @keyframes fadeIn { from { opacity: 0; transform: translateX(-4px); } to { opacity: 1; } }
      `}</style>
    </div>
  )
}

export default function LiveConsole({ logs, scanning, scanId, onCancel }) {
  const bottomRef = useRef()
  const containerRef = useRef()

  // derulez automat la cel mai nou eveniment cand se schimba jurnalul
  // derularea lina arata mai bine decat un salt; asta acopera si montarea
  // initiala fiindca ref-ul e populat la prima randare cand logs.length > 0
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const isEmpty = logs.length === 0

  return (
    <div className="console-wrap">
      <div className="console-header">
        <Terminal size={14} />
        <span className="console-title">SCAN OUTPUT</span>
        {scanId && <span className="console-scan-id">scan #{scanId}</span>}
        {scanning && <span className="console-badge">● LIVE</span>}
        {scanning && onCancel && (
          <button className="stop-btn" onClick={onCancel} title="Stop scan">
            <Square size={11} fill="currentColor" /> Stop
          </button>
        )}
      </div>

      <div className="console-body" ref={containerRef}>
        {isEmpty ? (
          <div className="console-empty">
            <ChevronRight size={14} style={{ color: 'var(--text-dim)' }} />
            <span>Waiting for scan...</span>
          </div>
        ) : (
          <>
            {logs.map((event, i) => (
              <LogLine key={i} event={event} />
            ))}
          </>
        )}
        <div ref={bottomRef} />
      </div>

      <style>{`
        .console-wrap {
          border-radius: var(--radius-lg);
          overflow: hidden;
          border: 1px solid var(--border);
          display: flex;
          flex-direction: column;
        }
        .console-header {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 10px 16px;
          background: var(--surface-2);
          border-bottom: 1px solid var(--border);
          font-family: var(--font-mono);
          font-size: 11px;
          color: var(--text-muted);
          letter-spacing: 0.1em;
        }
        .console-title { font-weight: 600; color: var(--text); }
        .console-scan-id { margin-left: auto; color: var(--text-dim); }
        .console-badge {
          color: var(--accent);
          font-weight: 700;
          animation: pulse 1.5s ease-in-out infinite;
        }
        .stop-btn {
          margin-left: 8px;
          display: inline-flex;
          align-items: center;
          gap: 5px;
          background: transparent;
          border: 1px solid var(--red, #e5484d);
          color: var(--red, #e5484d);
          font-family: var(--font-mono);
          font-size: 10px;
          font-weight: 600;
          letter-spacing: 0.05em;
          padding: 3px 9px;
          border-radius: 3px;
          cursor: pointer;
          transition: all 0.15s;
        }
        .stop-btn:hover {
          background: var(--red, #e5484d);
          color: var(--bg);
        }
        .console-body {
          background: var(--terminal-bg);
          padding: 16px 20px;
          min-height: 280px;
          max-height: 440px;
          overflow-y: auto;
          font-family: var(--font-mono);
        }
        .console-empty {
          display: flex;
          align-items: center;
          gap: 6px;
          color: var(--text-dim);
          font-family: var(--font-mono);
          font-size: 12px;
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>
    </div>
  )
}
