"""
risk_score.py — Turns raw VirusTotal / AbuseIPDB data into a single
risk score (0-100) with a fun, readable label.

This is Phase 4: a simple RULE-BASED placeholder score. It gets
replaced by a proper unsupervised anomaly detector (Isolation Forest)
in Phase 6 — but the fun labels stick around for the whole project,
because a plain number is boring and this project isn't allowed to be.
"""
from typing import Optional


def _extract_vt_stats(vt_data: Optional[dict]) -> dict:
    """Pull the malicious/suspicious/harmless/undetected counts out of
    a VirusTotal response, regardless of whether it came from an
    ip/domain/hash lookup or a url analysis (slightly different shapes)."""
    if not vt_data:
        return {}
    attrs = vt_data.get("data", {}).get("attributes", {})
    return attrs.get("last_analysis_stats") or attrs.get("stats") or {}


def _vt_score(stats: dict) -> float:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    if total == 0:
        return 0.0
    # suspicious counts as "half a vote" toward maliciousness
    return ((malicious + suspicious * 0.5) / total) * 100


def _abuseipdb_score(abuseipdb_data: Optional[dict]) -> float:
    if not abuseipdb_data:
        return 0.0
    return float(abuseipdb_data.get("data", {}).get("abuseConfidenceScore", 0))


def _reputation_has_data(vt_data: Optional[dict], abuseipdb_data: Optional[dict]) -> bool:
    """True if at least one live threat-intel source actually returned
    scored engine/report data (not just an empty/error response)."""
    vt_stats = _extract_vt_stats(vt_data)
    vt_total = sum(vt_stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    abuse_present = bool(abuseipdb_data and abuseipdb_data.get("data"))
    return vt_total > 0 or abuse_present


def label_for_score(score: float) -> str:
    """The fun part. Feel free to rename these — they're yours."""
    if score < 20:
        return "CHILL_ZONE"
    if score < 50:
        return "SUS_VIBES"
    if score < 80:
        return "DANGER_ZONE"
    return "FULL_VILLAIN_ARC"


def compute_risk(vt_data: Optional[dict], abuseipdb_data: Optional[dict]) -> tuple[float, str]:
    """
    Combine both sources into one score.
    Weighting: mostly trust whichever source is more alarmed, with a
    smaller nudge from the average of both, so one source spiking
    doesn't get fully drowned out by a quiet second source.
    """
    vt_stats = _extract_vt_stats(vt_data)
    vt = _vt_score(vt_stats)
    abuse = _abuseipdb_score(abuseipdb_data)

    combined = max(vt, abuse) * 0.7 + ((vt + abuse) / 2) * 0.3
    combined = round(min(combined, 100.0), 1)

    return combined, label_for_score(combined)


def compute_final_risk(
    vt_data: Optional[dict],
    abuseipdb_data: Optional[dict],
    knn_score: float,
    knn_label: str,
) -> dict:
    """
    Combines live threat-intel reputation (VT + AbuseIPDB) with the
    kNN similarity score against our labeled reference set.

    IMPORTANT: this is a WEIGHTED BLEND, not a max()/veto. Live
    reputation data (VT + AbuseIPDB) is treated as more trustworthy
    than kNN similarity, because:
      - VT/AbuseIPDB are ground-truth reports from real detection engines
      - kNN is a similarity guess against a small, hand-curated reference
        set, and can misfire on IOCs that are lexically/semantically
        close to a malicious example without actually being malicious
        (e.g. private/reserved IPs, which the seed set doesn't cover)

    If reputation data exists (real engine results, not just empty),
    it gets the majority weight. kNN only dominates when reputation
    data is completely unavailable (e.g. API lookup failed).
    """
    reputation_score, reputation_label = compute_risk(vt_data, abuseipdb_data)
    knn_score_pct = knn_score * 100  # kNN score is 0-1, convert to 0-100 scale

    if _reputation_has_data(vt_data, abuseipdb_data):
        # Reputation data exists: trust it heavily. kNN can still nudge
        # the score up (catches things reputation feeds haven't seen
        # yet) but can no longer single-handedly override two clean
        # authoritative sources.
        final_score = reputation_score * 0.75 + knn_score_pct * 0.25
    else:
        # No reputation data at all (e.g. both lookups failed/errored) —
        # fall back to kNN as the only available signal.
        final_score = knn_score_pct

    final_score = round(min(final_score, 100.0), 1)
    final_label = label_for_score(final_score)

    return {
        "final_score": final_score,
        "final_label": final_label,
        "reputation_score": reputation_score,
        "knn_score": round(knn_score_pct, 1),
        "knn_verdict": knn_label,
    }