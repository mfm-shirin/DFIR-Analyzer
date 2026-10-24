# DFIR Analyzer

A Digital Forensics and Incident Response (DFIR) tool designed to collect digital evidence, analyse running processes, verify evidence integrity, and generate forensic reports.

## Overview

DFIR Analyzer is a web-based forensic analysis application developed as a Project-Based Learning (PBL) project. It provides a centralised dashboard for collecting system information, analysing processes, verifying evidence integrity using SHA-256 hashes, and exporting analysis reports in PDF format.

The project aims to demonstrate essential digital forensic investigation workflows through a simple and interactive interface.

## Features

- **Evidence Collection:** Collects system metadata and running process information.
- **Process Analysis:** Analyses collected process information and identifies findings.
- **Evidence Integrity Verification:** Uses SHA-256 hashes to verify whether collected evidence has been modified.
- **Integrity Manifest:** Maintains a manifest containing hashes of collected evidence files.
- **Forensic Dashboard:** Displays collection details, analysis results, and integrity verification status.
- **PDF Report Generation:** Generates downloadable forensic analysis reports.
- **Tamper Detection:** Identifies evidence files whose contents differ from their recorded hashes.

## Technology Stack

| Component | Technology |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | Python, FastAPI |
| Evidence Integrity | SHA-256 |
| Report Generation | ReportLab |
| Development Environment | Visual Studio Code |

## Project Structure

```text
DFIR-Analyzer/
├── backend/
│   ├── analyzer.py
│   ├── api.py
│   └── integrity.py
├── collector/
│   └── collector.py
├── frontend/
│   ├── public/
│   └── src/
│       ├── App.tsx
│       ├── App.css
│       ├── index.css
│       └── main.tsx
├── evidence/       # Generated evidence collections (not committed)
├── analysis/       # Generated analysis output (not committed)
└── README.md
```

## Installation and Setup

### Prerequisites

- Python 3.10 or later
- Node.js and npm
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/mfm-shirin/DFIR-Analyzer.git
cd DFIR-Analyzer
```

### 2. Set Up the Backend

Create and activate a Python virtual environment.

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the backend dependencies:

```powershell
pip install fastapi uvicorn reportlab
```

Start the backend server:

```powershell
uvicorn backend.api:app --reload
```

The backend API will be available at:

http://127.0.0.1:8000

### 3. Set Up the Frontend

Open another terminal and navigate to the frontend directory:

```powershell
cd frontend
npm install
npm run dev
```

Open the frontend URL displayed in the terminal, usually:

http://localhost:5173

## Evidence Integrity Verification

DFIR Analyzer uses SHA-256 hashing to verify the integrity of collected evidence.

During evidence collection, hashes are recorded in a manifest. During verification, the hashes of the current evidence files are compared with the recorded values.

If a file has been modified, the integrity verification process can identify the affected file.

## Disclaimer

This project is developed for educational purposes as part of an academic PBL project. It is intended to demonstrate digital forensic concepts and should not be used as a replacement for professional forensic investigation tools or procedures.

Always obtain appropriate authorisation before collecting or analysing data from any system.

## Contributors

Developed as a collaborative academic project.

## License

This project is currently intended for academic use.
