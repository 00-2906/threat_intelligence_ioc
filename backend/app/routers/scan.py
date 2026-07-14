from fastapi import APIRouter

from app.db import save_scan
from app.models.schemas import ScanRequest, ScanResponse
from app.services import abuseipdb, risk_score, virustotal

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
def scan_ioc(request: ScanRequest) -> ScanResponse:
    """
    Look up an IOC (ip, domain, url, or hash), score it, and log it to
    history. Scoring is rule-based for now (Phase 4) — it gets swapped
    for an unsupervised anomaly detector in Phase 6, but the response
    shape here won't need to change when that happens.
    """
    result = ScanResponse(ioc_type=request.ioc_type, value=request.value)

    try:
        result.virustotal = virustotal.lookup(request.ioc_type.value, request.value)
    except Exception as exc:
        result.errors.append(f"VirusTotal lookup failed: {exc}")

    if request.ioc_type.value == "ip":
        try:
            result.abuseipdb = abuseipdb.get_ip_report(request.value)
        except Exception as exc:
            result.errors.append(f"AbuseIPDB lookup failed: {exc}")

    result.risk_score, result.risk_label = risk_score.compute_risk(result.virustotal, result.abuseipdb)

    save_scan(
        ioc_type=request.ioc_type.value,
        value=request.value,
        risk_score=result.risk_score,
        risk_label=result.risk_label,
        raw_data={"virustotal": result.virustotal, "abuseipdb": result.abuseipdb},
    )

    return result
