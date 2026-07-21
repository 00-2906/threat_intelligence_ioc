"""
Example: how a step-1 Core API scan result (VirusTotal + AbuseIPDB JSON)
feeds into the step-6 ChromaDB RAG layer during step-7 reasoning.

ChromaDB is NOT used to store scan results - Postgres/SQLite does that.
ChromaDB only holds the MITRE ATT&CK technique embeddings. This module
takes a scan result, decides if it's worth a RAG lookup, and if so,
turns the scan JSON into a text query for the retriever.
"""

from app.rag.retriever import get_retriever

# Below this, a clean/low-risk IOC isn't worth a RAG + LLM call.
RAG_LOOKUP_THRESHOLD = 40.0


def build_evidence_text(scan_result: dict) -> str:
    """
    Convert a raw scan_ioc() result into a short natural-language
    description - this is what gets embedded and matched against
    MITRE technique descriptions in ChromaDB.
    """
    ioc_type = scan_result.get("ioc_type", "unknown")
    value = scan_result.get("value", "")
    risk_label = scan_result.get("risk_label", "unknown")

    # .get(key, {}) only falls back to {} when the key is MISSING.
    # For domain/url/hash IOCs, virustotal/abuseipdb are present but
    # explicitly set to None (lookup skipped or failed), so we need
    # an explicit "or {}" to catch that case too.
    virustotal = scan_result.get("virustotal") or {}
    vt_attrs = virustotal.get("data", {}).get("attributes", {})
    stats = vt_attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    as_owner = vt_attrs.get("as_owner", "unknown owner")

    abuseipdb = scan_result.get("abuseipdb") or {}
    abuse_data = abuseipdb.get("data", {})
    abuse_score = abuse_data.get("abuseConfidenceScore", 0)
    usage_type = abuse_data.get("usageType", "unknown usage")
    total_reports = abuse_data.get("totalReports", 0)

    return (
        f"{ioc_type.upper()} {value} flagged as {risk_label}. "
        f"VirusTotal: {malicious} malicious / {suspicious} suspicious "
        f"detections, hosted by {as_owner}. "
        f"AbuseIPDB: abuse confidence {abuse_score}%, {total_reports} "
        f"reports, usage type {usage_type}."
    )


def get_technique_context(scan_result: dict) -> list[dict] | None:
    """
    Main entry point for step 7. Returns a list of matched MITRE
    techniques if the IOC is risky enough to warrant it, otherwise
    None (skip the RAG/LLM call entirely for clean IOCs).
    """
    risk_score = scan_result.get("risk_score", 0)
    if risk_score < RAG_LOOKUP_THRESHOLD:
        return None  # e.g. this CHILL_ZONE example - no lookup needed

    evidence_text = build_evidence_text(scan_result)
    retriever = get_retriever()
    return retriever.find_similar_techniques(evidence_text, n_results=3)


if __name__ == "__main__":
    # Demo with the CHILL_ZONE example - shows the threshold skipping it
    clean_example = {
        "ioc_type": "ip",
        "value": "44.89.6.8",
        "risk_score": 14.5,
        "risk_label": "CHILL_ZONE",
        "virustotal": {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0},
            "as_owner": "University of California, San Diego",
        }}},
        "abuseipdb": {"data": {
            "abuseConfidenceScore": 0, "usageType": "University/College/School",
            "totalReports": 0,
        }},
    }

    print("Evidence text:", build_evidence_text(clean_example))
    result = get_technique_context(clean_example)
    print("RAG lookup triggered:", result is not None)