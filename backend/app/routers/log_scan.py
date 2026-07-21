"""
Router for uploading a log file and scanning it for malicious IOCs.

Wire this into your main.py:
    from app.routers import log_scan
    app.include_router(log_scan.router, prefix="/api/logs", tags=["log-scan"])
"""

from datetime import datetime, timezone

from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from fastapi.responses import StreamingResponse

# use a relative import to ensure the module resolves correctly when running
# from the package root
from ..services.log_scanner import get_scanner_report  # see services/log_scanner.py
from ..services.report_generator import generate_report_pdf

router = APIRouter()


@router.post("/scan")
async def scan_log_file(
    file: UploadFile = File(...),
    format: str = Query("json", pattern="^(json|pdf)$", description="'json' or 'pdf'"),
):
    if not file.filename.endswith((".log", ".txt")):
        raise HTTPException(status_code=400, detail="Only .log or .txt files are supported")

    raw_bytes = await file.read()
    try:
        report = get_scanner_report(raw_bytes)
    except FileNotFoundError as e:
        # reference_embeddings.npz hasn't been built yet
        raise HTTPException(status_code=500, detail=str(e))

    if format == "pdf":
        pdf_buffer = generate_report_pdf(report)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        filename = f"ioc-scan-report-{timestamp}.pdf"
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return {
        "summary": report.summary(),
        "total_lines_scanned": report.total_lines_scanned,
        "total_iocs_found": report.total_iocs_found,
        "malicious": [
            {
                "value": item.value,
                "type": item.ioc_type,
                "line": item.line_number,
                "context": item.context,
                "score": round(item.score.malicious_score, 3),
                "explanation": item.explanation,
                "cited_techniques": item.cited_techniques,
                "nearest_matches": [
                    {"text": n.text, "label": n.label, "similarity": round(n.similarity, 3)}
                    for n in item.score.neighbors[:3]
                ],
            }
            for item in report.malicious
        ],
        "suspicious": [
            {
                "value": item.value,
                "type": item.ioc_type,
                "line": item.line_number,
                "context": item.context,
                "score": round(item.score.malicious_score, 3),
                "explanation": item.explanation,
                "cited_techniques": item.cited_techniques,
            }
            for item in report.suspicious
        ],
    }