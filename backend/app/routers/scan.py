from fastapi import APIRouter

from app.db import save_scan
from app.models.schemas import ScanRequest, ScanResponse
from app.services import abuseipdb, risk_score, virustotal
from app.services.log_scanner import get_scanner
from app.services.llm_reasoner import explain_ioc
from app.rag.integeration import get_technique_context
from embedding.reference_embeddings import score_against_reference
from embedding.ioc_extractor import build_embedding_text, ExtractedIOC

router = APIRouter()


def _resolve_ioc_type(ioc_type: str, value: str) -> str:
    """
    The API's ScanRequest enum only knows the coarse categories
    'ip' | 'domain' | 'url' | 'hash'. But build_embedding_text() (and
    the log-file extractor) expect the SPECIFIC hash type
    ('md5' | 'sha1' | 'sha256'), since that's what the reference set
    and embedding text labels are built around.
    """
    if ioc_type != "hash":
        return ioc_type

    length = len(value.strip())
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    if length == 64:
        return "sha256"

    return "hash"


@router.post("/scan", response_model=ScanResponse)
def scan_ioc(request: ScanRequest) -> ScanResponse:
    """
    Look up an IOC (ip, domain, url, or hash), score it, retrieve RAG
    context if it's risky enough, generate an LLM explanation, and log
    it to history.
    """
    value = request.value.strip()
    result = ScanResponse(ioc_type=request.ioc_type, value=value)

    try:
        result.virustotal = virustotal.lookup(request.ioc_type.value, value)
    except Exception as exc:
        result.errors.append(f"VirusTotal lookup failed: {exc}")

    if request.ioc_type.value == "ip":
        try:
            result.abuseipdb = abuseipdb.get_ip_report(value)
        except Exception as exc:
            result.errors.append(f"AbuseIPDB lookup failed: {exc}")

    # kNN score against our labeled reference set
    scanner = get_scanner()
    resolved_type = _resolve_ioc_type(request.ioc_type.value, value)
    fake_ioc = ExtractedIOC(value=value, ioc_type=resolved_type, context=value, line_number=0)
    embed_text = build_embedding_text(fake_ioc)
    embedding = scanner.embedder.embed_batch([embed_text]).embeddings[0]
    knn = score_against_reference(
        embedding, scanner.ref_embeddings, scanner.ref_labels, scanner.ref_texts
    )

    combined = risk_score.compute_final_risk(
        result.virustotal, result.abuseipdb, knn.malicious_score, knn.verdict
    )
    result.risk_score = combined["final_score"]
    result.risk_label = combined["final_label"]

    # --- RAG + LLM explanation layer ---
    nearest_matches = [
        {"label": n.label, "similarity": n.similarity, "text": n.text}
        for n in knn.neighbors
    ]

    mitre_techniques = get_technique_context({
        "ioc_type": request.ioc_type.value,
        "value": value,
        "risk_score": result.risk_score,
        "risk_label": result.risk_label,
        "virustotal": result.virustotal,
        "abuseipdb": result.abuseipdb,
    })

    explanation = explain_ioc(
        value=value,
        ioc_type=request.ioc_type.value,
        risk_score=result.risk_score,
        risk_label=result.risk_label,
        nearest_matches=nearest_matches,
        mitre_techniques=mitre_techniques,
    )
    result.explanation = explanation.summary
    result.cited_techniques = explanation.cited_techniques
    # --- end RAG + LLM explanation layer ---

    save_scan(
        ioc_type=request.ioc_type.value,
        value=value,
        risk_score=result.risk_score,
        risk_label=result.risk_label,
        raw_data={
            "virustotal": result.virustotal,
            "abuseipdb": result.abuseipdb,
            "knn_score": combined["knn_score"],
            "knn_verdict": combined["knn_verdict"],
            "explanation": result.explanation,
            "cited_techniques": result.cited_techniques,
        },
    )

    return result