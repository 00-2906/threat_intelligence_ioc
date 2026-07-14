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


def label_for_score(score: float) -> str:
    """The fun part. Feel free to rename these — they're yours."""
    if score < 20:
        return "😎 Chill Zone"
    if score < 50:
        return "🤔 Sus Vibes"
    if score < 80:
        return "🚨 Danger Zone"
    return "☠️ Full Villain Arc"


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
