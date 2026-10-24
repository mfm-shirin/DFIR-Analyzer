
import { useCallback, useEffect, useState } from 'react'
import './App.css'

type Finding = {
  type: string
  severity: string
  pid: number | null
  process_name: string | null
  description: string
}

type AnalysisReport = {
  analysis_timestamp: string
  collection_path: string
  total_processes: number
  findings_count: number
  findings: Finding[]
}

type AnalysisResponse = {
  status: string
  report: AnalysisReport
  report_file: string
}

type IntegrityResponse = {
  collection: string
  status: 'verified' | 'failed' | 'incomplete' | 'error'
  message: string
  total_files: number
  verified_files: number
  modified_files: string[]
  missing_files: string[]
  results: {
    filename: string
    status: string
    sha256?: string
    expected_sha256?: string
    actual_sha256?: string
  }[]
}

function App() {
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [apiError, setApiError] = useState('')
  const [collecting, setCollecting] = useState(false)
  const [integrity, setIntegrity] = useState<IntegrityResponse | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [integrityError, setIntegrityError] = useState('')
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState('')

  const fetchAnalysis = useCallback(async () => {
    setLoading(true)
    setApiError('')

    try {
      const response = await fetch(
        'http://127.0.0.1:8000/api/analysis/latest',
      )

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`)
      }

      const data: AnalysisResponse = await response.json()
      setAnalysis(data)
    } catch (error) {
      setApiError(
        error instanceof Error
          ? error.message
          : 'Unable to connect to the DFIR Analyzer API.',
      )
    } finally {
      setLoading(false)
    }
  }, [])

const verifyIntegrity = useCallback(async () => {
  setVerifying(true)
  setIntegrityError('')

  try {
    const response = await fetch(
      'http://127.0.0.1:8000/api/integrity/latest',
    )

    if (!response.ok) {
      throw new Error(`Integrity request failed: ${response.status}`)
    }

    const data: IntegrityResponse = await response.json()
    setIntegrity(data)
  } catch (error) {
    setIntegrityError(
      error instanceof Error
        ? error.message
        : 'Unable to verify evidence integrity.',
    )
    setIntegrity(null)
  } finally {
    setVerifying(false)
  }
}, [])

  useEffect(() => {
    void fetchAnalysis()
  }, [fetchAnalysis])

  const startCollection = useCallback(async () => {
  setCollecting(true)
  setApiError('')

  try {
    const response = await fetch(
      'http://127.0.0.1:8000/api/collection/start',
      {
        method: 'POST',
      },
    )

    if (!response.ok) {
      throw new Error(`Collection request failed: ${response.status}`)
    }

    const data: AnalysisResponse = await response.json()
    setAnalysis(data)

    await verifyIntegrity()

  } catch (error) {
    setApiError(
      error instanceof Error
        ? error.message
        : 'Unable to start evidence collection.',
    )
  } finally {
    setCollecting(false)
  }
}, [verifyIntegrity])

const report = analysis?.report
const collectionName = report?.collection_path.split(/[\\/]/).pop()
const exportPdf = useCallback(async () => {
  setExporting(true)
  setExportError('')

  try {
    const response = await fetch(
      'http://127.0.0.1:8000/api/reports/latest/pdf',
    )

    if (!response.ok) {
      throw new Error(`PDF export failed: ${response.status}`)
    }

    const blob = await response.blob()
    const url = URL.createObjectURL(blob)

    const link = document.createElement('a')
    link.href = url
    link.download = `DFIR_Report_${collectionName ?? 'latest'}.pdf`

    document.body.appendChild(link)
    link.click()
    link.remove()

    URL.revokeObjectURL(url)
  } catch (error) {
    setExportError(
      error instanceof Error
        ? error.message
        : 'Unable to export the PDF report.',
    )
  } finally {
    setExporting(false)
  }
}, [collectionName])

  return (
    <div className="workbench">
      <aside className="rail">
        <div className="rail-brand">
          D<span>F</span>
        </div>

        <nav className="rail-nav">
          <a className="rail-link selected" href="#" title="Overview">
            ◈
          </a>
          <a className="rail-link" href="#" title="Investigations">
            ▤
          </a>
          <a className="rail-link" href="#" title="Evidence">
            ◉
          </a>
          <a className="rail-link" href="#" title="Timeline">
            ◷
          </a>
          <a className="rail-link" href="#" title="Reports">
            ▧
          </a>
        </nav>

        <div className="rail-bottom">
          <div className="rail-avatar">DF</div>
        </div>
      </aside>

      <main className="workspace">
        <header className="app-header">
          <div className="header-path">
            <span>DFIR ANALYZER</span>
            <span className="path-separator">/</span>
            <span>WORKSPACE</span>
          </div>

          <div className="header-status">
            <span className="status-indicator"></span>
            LOCAL WORKSTATION
          </div>
        </header>

        <div className="case-bar">
          <div className="case-reference">
            <span className="case-label">ACTIVE ANALYSIS</span>
            <strong>DFIR-2026-001</strong>
          </div>

          <div className="case-description">
            <span>Running Process Examination</span>
            <span className="case-type">PROCESS ANALYSIS</span>
          </div>

          <div className="case-state">
            <span className="state-marker"></span>
            {loading ? 'ANALYSING' : report ? 'REPORT READY' : 'OFFLINE'}
          </div>
        </div>

        <section className="workbench-content">
          <div className="page-heading">
            <div>
              <p className="section-kicker">INVESTIGATION WORKSPACE</p>
              <h1>Case overview</h1>
              <p className="heading-description">
                Examine collected artifacts and review forensic analysis results.
              </p>
            </div>

           <div className="heading-actions">
            <button
              className="quiet-button"
              onClick={() => void fetchAnalysis()}
              disabled={loading || collecting}
            >
              {loading ? 'Loading...' : '↻ Refresh analysis'}
            </button>

            <button
              className="primary-button"
              onClick={() => void startCollection()}
              disabled={collecting || loading}
            >
              {collecting ? 'Collecting & analysing...' : '＋ Collect & Analyse'}
            </button>

            <button
              className="quiet-button"
              onClick={() => void exportPdf()}
              disabled={exporting || loading || collecting}
            >
              {exporting ? 'Exporting PDF...' : '↓ Export PDF'}
            </button>

          </div>
          {exportError && (
            <p className="integrity-error" role="alert">
              {exportError}
            </p>
          )}

          </div>

          {apiError && (
            <section className="panel" role="alert">
              <div className="panel-heading">
                <div>
                  <span className="panel-index">API CONNECTION</span>
                  <h2>Unable to load analysis</h2>
                </div>
              </div>
              <p>{apiError}</p>
              <p>
                Make sure the FastAPI server is running at
                {' '}http://127.0.0.1:8000.
              </p>
              <button
                className="quiet-button"
                onClick={() => void fetchAnalysis()}
              >
                Try again
              </button>
            </section>
          )}

          <section className="case-metrics" aria-label="Analysis summary">
            <div className="metric">
              <span>Processes examined</span>
              <strong>{loading ? '—' : report?.total_processes ?? '—'}</strong>
              <small>From the selected collection</small>
            </div>

            <div className="metric">
              <span>Total findings</span>
              <strong>{loading ? '—' : report?.findings_count ?? '—'}</strong>
              <small>Indicators requiring review</small>
            </div>

            <div className="metric">
              <span>Low severity</span>
              <strong>
                {loading
                  ? '—'
                  : report?.findings.filter(
                      (finding) => finding.severity.toLowerCase() === 'low',
                    ).length ?? '—'}
              </strong>
              <small>Low-severity indicators</small>
            </div>

            <div className="metric">
              <span>Analysis status</span>
              <strong className="metric-status">
                {loading ? 'RUNNING' : report ? 'COMPLETE' : 'UNAVAILABLE'}
              </strong>
              <small>Latest process analysis</small>
            </div>
          </section>

          <section className="panel timeline-panel">
            <div className="panel-heading">
              <div>
                <span className="panel-index">01 / ANALYSIS</span>
                <h2>Process findings</h2>
              </div>

              <span className="panel-meta">
                {report?.findings_count ?? 0} FINDINGS
              </span>
            </div>

            {loading ? (
              <p>Loading forensic findings...</p>
            ) : report && report.findings.length > 0 ? (
              <div className="evidence-table">
                <div className="evidence-row evidence-head">
                  <span>PROCESS</span>
                  <span>PID</span>
                  <span>SEVERITY</span>
                </div>

                {report.findings.map((finding, index) => (
                  <div className="evidence-row" key={`${finding.pid}-${index}`}>
                    <span>
                      <strong>
                        {finding.process_name ?? 'Unknown process'}
                      </strong>
                      <small>{finding.description}</small>
                    </span>

                    <span>{finding.pid ?? 'N/A'}</span>

                    <span className="integrity-pending">
                      {finding.severity.toUpperCase()}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p>
                {report
                  ? 'No findings were reported for this collection.'
                  : 'Analysis data is not available.'}
              </p>
            )}

            <div className="timeline-footer">
              <span>
                <span className="legend-dot"></span>
                Forensic indicators
              </span>
              <span>
                Findings are indicators for investigation, not proof of malicious
                activity.
              </span>
            </div>
          </section>
<section className="panel integrity-panel">
  <div className="panel-heading">
    <div>
      <span className="panel-index">02 / EVIDENCE INTEGRITY</span>
      <h2>Integrity verification</h2>
    </div>

    <button
      className="quiet-button"
      onClick={() => void verifyIntegrity()}
      disabled={verifying || collecting}
    >
      {verifying ? 'Verifying...' : '↻ Verify integrity'}
    </button>
  </div>

  {integrityError && (
    <p className="integrity-error" role="alert">
      {integrityError}
    </p>
  )}

  {integrity ? (
    <>
      <div className="integrity-summary">
        <div>
          <span>Verification status</span>
          <strong
            className={`integrity-status integrity-${integrity.status}`}
          >
            {integrity.status.toUpperCase()}
          </strong>
        </div>

        <div>
          <span>Files verified</span>
          <strong>
            {integrity.verified_files} / {integrity.total_files}
          </strong>
        </div>

        <div>
          <span>Modified files</span>
          <strong>{integrity.modified_files.length}</strong>
        </div>

        <div>
          <span>Missing files</span>
          <strong>{integrity.missing_files.length}</strong>
        </div>
      </div>

      <p className="integrity-message">{integrity.message}</p>

      <div className="evidence-table">
        <div className="evidence-row evidence-head">
          <span>FILE</span>
          <span>STATUS</span>
        </div>

        {integrity.results.map((file, index) => (
          <div className="evidence-row" key={`${file.filename}-${index}`}>
            <span>
              <strong>{file.filename}</strong>
              {file.status === 'modified' && file.expected_sha256 && (
                <small>
                  Expected SHA-256: {file.expected_sha256}
                </small>
              )}
              {file.status === 'modified' && file.actual_sha256 && (
                <small>
                  Actual SHA-256: {file.actual_sha256}
                </small>
              )}
            </span>

            <span
              className={`integrity-status integrity-${file.status}`}
            >
              {file.status.toUpperCase()}
            </span>
          </div>
        ))}
      </div>
    </>
  ) : (
    <p>
      {verifying
        ? 'Verifying evidence files against the collection manifest...'
        : 'Run integrity verification to check whether the collected evidence has changed.'}
    </p>
  )}
</section>
          <div className="details-grid">
            <section className="panel evidence-panel">
              <div className="panel-heading">
                <div>
                  <span className="panel-index">02 / COLLECTION</span>
                  <h2>Evidence source</h2>
                </div>
              </div>

              <div className="evidence-table">
                <div className="evidence-row evidence-head">
                  <span>COLLECTION</span>
                  <span>STATUS</span>
                </div>

                <div className="evidence-row">
                  <span>
                    <strong>{collectionName ?? 'No collection selected'}</strong>
                    <small>Running process evidence</small>
                  </span>

                  <span>
                    {report ? 'LOADED' : 'UNAVAILABLE'}
                  </span>
                </div>

                <div className="evidence-row">
                  <span>
                    <strong>Analysis report</strong>
                    <small>{analysis?.report_file ?? 'No report generated'}</small>
                  </span>

                  <span>{report ? 'GENERATED' : 'PENDING'}</span>
                </div>
              </div>
            </section>

            <section className="panel activity-panel">
              <div className="panel-heading">
                <div>
                  <span className="panel-index">03 / REPORT DETAILS</span>
                  <h2>Analysis information</h2>
                </div>
              </div>

              <div className="activity-case-id">
                LATEST ANALYSIS
              </div>

              <div className="audit-list">
                <div className="audit-entry">
                  <span className="audit-line"></span>
                  <div className="audit-content">
                    <small className="audit-time">TIMESTAMP</small>
                    <strong>
                      {report
                        ? new Date(report.analysis_timestamp).toLocaleString()
                        : 'Not available'}
                    </strong>
                    <p>Time the analysis report was generated.</p>
                  </div>
                </div>

                <div className="audit-entry">
                  <span className="audit-line"></span>
                  <div className="audit-content">
                    <small className="audit-time">SOURCE</small>
                    <strong>{collectionName ?? 'No collection'}</strong>
                    <p>Evidence collection used for this report.</p>
                  </div>
                </div>
              </div>

              <div className="activity-status">
                <span className="activity-status-label">STATUS</span>
                <strong>
                  {report ? 'Analysis completed' : 'Awaiting analysis'}
                </strong>
                <p>
                  {report
                    ? 'The latest process analysis report is available.'
                    : 'Connect to the API to retrieve a report.'}
                </p>
              </div>
            </section>
          </div>

          <footer className="workbench-footer">
            <span>
              DFIR ANALYZER <span className="footer-divider">/</span>{' '}
              FORENSIC WORKBENCH
            </span>
            <span>LIVE PROCESS ANALYSIS</span>
          </footer>
        </section>
      </main>
    </div>
  )
}

export default App
