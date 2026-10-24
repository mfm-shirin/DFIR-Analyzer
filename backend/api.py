
from io import BytesIO
from datetime import datetime

from fastapi.responses import StreamingResponse

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.analyzer import (
    ANALYSIS_DIR,
    get_latest_collection,
    analyse_processes,
    save_report,
)

from backend.integrity import verify_collection

from collector.collector import main as collect_evidence

app = FastAPI(
    title="DFIR Analyzer API",
    description="API for collecting and analysing digital forensic evidence.",
    version="1.0.0",
)

# Allow the React development server to communicate with this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
           "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "message": "DFIR Analyzer API is running",
        "status": "online",
    }


@app.get("/api/collections")
def get_collections():
    from pathlib import Path

    evidence_dir = Path(__file__).resolve().parent.parent / "evidence"

    collections = sorted(
        [
            folder.name
            for folder in evidence_dir.glob("collection_*")
            if folder.is_dir()
        ],
        reverse=True,
    )

    return {
        "total_collections": len(collections),
        "collections": collections,
    }


@app.get("/api/analysis/latest")
def get_latest_analysis():
    try:
        collection_path = get_latest_collection()

        report = analyse_processes(collection_path)
        report_path = save_report(report, collection_path)

        return {
            "status": "success",
            "report": report,
            "report_file": report_path.name,
        }

    except (FileNotFoundError, ValueError) as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        )

@app.get("/api/integrity/latest")
def verify_latest_integrity():
    try:
        collection_path = get_latest_collection()
        result = verify_collection(collection_path)

        return {
            "collection": collection_path.name,
            **result,
        }

    except (FileNotFoundError, ValueError) as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        )

@app.get("/api/analysis/reports")
def get_analysis_reports():
    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)

    reports = sorted(
        [
            report.name
            for report in ANALYSIS_DIR.glob("analysis_*.json")
            if report.is_file()
        ],
        reverse=True,
    )

    return {
        "total_reports": len(reports),
        "reports": reports,
    }

@app.post("/api/collection/start")
def start_collection():
    try:
        # Run the existing evidence collector.
        collect_evidence()

        # Analyse the newly created collection.
        collection_path = get_latest_collection()

        report = analyse_processes(collection_path)
        report_path = save_report(report, collection_path)

        return {
            "status": "success",
            "message": "Evidence collection and analysis completed.",
            "collection": collection_path.name,
            "report": report,
            "report_file": report_path.name,
        }

    except (FileNotFoundError, ValueError) as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        )

@app.get("/api/reports/latest/pdf")
def export_latest_pdf_report():
    try:
        collection_path = get_latest_collection()

        # Generate the latest process analysis.
        report = analyse_processes(collection_path)

        # Verify evidence integrity.
        integrity_result = verify_collection(collection_path)

        # Create the PDF in memory.
        buffer = BytesIO()

        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm,
            title="DFIR Analyzer Forensic Report",
            author="DFIR Analyzer",
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            textColor=colors.HexColor("#17324D"),
            alignment=TA_CENTER,
            fontSize=20,
            spaceAfter=8,
        )

        section_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#176B87"),
            spaceBefore=12,
            spaceAfter=6,
        )

        body_style = styles["BodyText"]

        story = []

        story.append(
            Paragraph("DFIR ANALYZER", title_style)
        )

        story.append(
            Paragraph("Digital Forensic Analysis Report", styles["Heading2"])
        )

        story.append(Spacer(1, 8))

        # Report metadata.
        metadata = [
            ["Collection ID", collection_path.name],
            ["Report Generated", datetime.now().strftime("%d %B %Y, %H:%M:%S")],
            ["Analysis Timestamp", str(report.get("analysis_timestamp", "N/A"))],
            ["Processes Examined", str(report.get("total_processes", 0))],
            ["Total Findings", str(report.get("findings_count", 0))],
        ]

        metadata_table = Table(metadata, colWidths=[45 * mm, 115 * mm])

        metadata_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF1F5")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#243746")),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5DF")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )

        story.append(metadata_table)

        # Process findings.
        story.append(
            Paragraph("Process Findings", section_style)
        )

        findings = report.get("findings", [])

        findings_data = [
            [
                Paragraph("<b>Process</b>", body_style),
                Paragraph("<b>PID</b>", body_style),
                Paragraph("<b>Severity</b>", body_style),
                Paragraph("<b>Description</b>", body_style),
            ]
        ]

        for finding in findings:
            findings_data.append(
                [
                    Paragraph(
                        str(finding.get("process_name") or "Unknown"),
                        body_style,
                    ),
                    str(finding.get("pid") or "N/A"),
                    str(finding.get("severity", "N/A")).upper(),
                    Paragraph(
                        str(finding.get("description", "N/A")),
                        body_style,
                    ),
                ]
            )

        if len(findings_data) == 1:
            findings_data.append(
                [
                    Paragraph("No findings reported.", body_style),
                    "",
                    "",
                    "",
                ]
            )

        findings_table = Table(
            findings_data,
            colWidths=[40 * mm, 18 * mm, 25 * mm, 77 * mm],
            repeatRows=1,
        )

        findings_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17324D")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5DF")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                        colors.white,
                        colors.HexColor("#F4F7F9"),
                    ]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )

        story.append(findings_table)

        # Evidence integrity.
        story.append(
            Paragraph("Evidence Integrity Verification", section_style)
        )

        integrity_metadata = [
            ["Verification Status", integrity_result.get("status", "N/A").upper()],
            ["Files Checked", str(integrity_result.get("total_files", 0))],
            ["Files Verified", str(integrity_result.get("verified_files", 0))],
            ["Modified Files", str(len(integrity_result.get("modified_files", [])))],
            ["Missing Files", str(len(integrity_result.get("missing_files", [])))],
        ]

        integrity_table = Table(
            integrity_metadata,
            colWidths=[45 * mm, 115 * mm],
        )

        integrity_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF1F5")),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5DF")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )

        story.append(integrity_table)

        story.append(
            Paragraph("Verified Evidence Files", section_style)
        )

        integrity_files_data = [
            [
                Paragraph("<b>Filename</b>", body_style),
                Paragraph("<b>Status</b>", body_style),
                Paragraph("<b>SHA-256</b>", body_style),
            ]
        ]

        for file_result in integrity_result.get("results", []):
            integrity_files_data.append(
                [
                    Paragraph(
                        str(file_result.get("filename", "Unknown")),
                        body_style,
                    ),
                    str(file_result.get("status", "N/A")).upper(),
                    Paragraph(
                        str(
                            file_result.get("sha256")
                            or file_result.get("actual_sha256")
                            or "N/A"
                        ),
                        body_style,
                    ),
                ]
            )

        integrity_files_table = Table(
            integrity_files_data,
            colWidths=[45 * mm, 25 * mm, 90 * mm],
            repeatRows=1,
        )

        integrity_files_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17324D")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5DF")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                        colors.white,
                        colors.HexColor("#F4F7F9"),
                    ]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )

        story.append(integrity_files_table)

        # Disclaimer.
        story.append(Spacer(1, 14))

        story.append(
            Paragraph(
                "<b>Disclaimer:</b> Findings are forensic indicators "
                "requiring further investigation and are not proof of "
                "malicious activity. Integrity verification compares "
                "current evidence files against hashes recorded in the "
                "collection manifest.",
                body_style,
            )
        )

        document.build(story)

        buffer.seek(0)

        filename = f"DFIR_Report_{collection_path.name}.pdf"

        return StreamingResponse(
            buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            },
        )

    except (FileNotFoundError, ValueError) as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        )