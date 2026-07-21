"""
End-to-end log file scanner.

Upload a raw log file -> extract candidate IOCs -> embed them -> score each
against the reference embedding set -> return a ranked report of flagged IOCs.

This is the piece that plugs into your Streamlit upload widget (see
streamlit_upload_snippet.py) or any other frontend.
"""
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Union

# Needed so this module works both when imported through app.main (which
# already inserts the repo root into sys.path) AND when run standalone
# via `python -m app.services.log_scanner` (which does not go through
# main.py, so the repo root is never added otherwise).
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.services.llm_reasoner import explain_ioc
from app.rag.integeration import get_technique_context
from embedding.embedder import IOCEmbedder
from embedding.ioc_extractor import extract_iocs_from_text, build_embedding_text, ExtractedIOC
from embedding.reference_embeddings import (
    load_reference_set,
    score_against_reference,
    ScoreResult,
)

logger = logging.getLogger(__name__)
REPO_ROOT = _REPO_ROOT

# score.malicious_score is 0.0-1.0; explain_ioc / get_technique_context
# expect a 0-100 scale (matching scan.py's combined risk_score). This is
# the single conversion point so both scale consistently.
_SCORE_SCALE = 100.0


@dataclass
class ScannedIOC:
    value: str
    ioc_type: str
    line_number: int
    context: str
    score: ScoreResult
    explanation: str = ""
    cited_techniques: List[str] = field(default_factory=list)


@dataclass
class LogScanReport:
    total_lines_scanned: int
    total_iocs_found: int
    malicious: List[ScannedIOC]
    suspicious: List[ScannedIOC]
    benign: List[ScannedIOC]

    def summary(self) -> str:
        return (
            f"{self.total_iocs_found} IOC(s) found across {self.total_lines_scanned} lines — "
            f"{len(self.malicious)} malicious, {len(self.suspicious)} suspicious, "
            f"{len(self.benign)} benign"
        )


class LogScanner:
    def __init__(self, embedder: IOCEmbedder, reference_set_path: str = str(REPO_ROOT / "reference_embeddings.npz")):
        self.embedder = embedder
        self.ref_embeddings, self.ref_labels, self.ref_texts = load_reference_set(reference_set_path)

    def scan_text(self, raw_text: str, k: int = 5) -> LogScanReport:
        extracted: List[ExtractedIOC] = extract_iocs_from_text(raw_text)
        total_lines = len(raw_text.splitlines())

        if not extracted:
            return LogScanReport(total_lines, 0, [], [], [])

        embed_texts = [build_embedding_text(ioc) for ioc in extracted]
        batch_result = self.embedder.embed_batch(embed_texts)

        # Cache explanations within this single scan run, keyed by
        # (ioc_type, value). The same IOC can legitimately appear on
        # multiple lines (e.g. an IP that shows up in both a firewall
        # block and a DNS log) — no need to spend a separate Gemini
        # call re-explaining something we already explained a moment ago.
        explanation_cache: dict[tuple[str, str], tuple[str, List[str]]] = {}

        malicious, suspicious, benign = [], [], []
        for ioc, emb in zip(extracted, batch_result.embeddings):
            score = score_against_reference(
                emb, self.ref_embeddings, self.ref_labels, self.ref_texts, k=k
            )

            explanation_text = ""
            cited_techniques: List[str] = []

            if score.verdict in ("malicious", "suspicious"):
                cache_key = (ioc.ioc_type, ioc.value)

                if cache_key in explanation_cache:
                    explanation_text, cited_techniques = explanation_cache[cache_key]
                else:
                    risk_score = score.malicious_score * _SCORE_SCALE
                    risk_label = score.verdict.upper()

                    nearest_matches = [
                        {"text": n.text, "label": n.label, "similarity": n.similarity}
                        for n in score.neighbors[:3]
                    ]

                    mitre_techniques = get_technique_context({
                        "ioc_type": ioc.ioc_type,
                        "value": ioc.value,
                        "risk_score": risk_score,
                        "risk_label": risk_label,
                    })

                    # LLM calls can fail independently of the scan itself
                    # (quota exhausted, network blip, etc.) — don't let
                    # that take down the whole log scan. Fall back to a
                    # placeholder and keep going.
                    try:
                        explanation = explain_ioc(
                            value=ioc.value,
                            ioc_type=ioc.ioc_type,
                            risk_score=risk_score,
                            risk_label=risk_label,
                            nearest_matches=nearest_matches,
                            mitre_techniques=mitre_techniques,
                        )
                        explanation_text = explanation.summary
                        cited_techniques = explanation.cited_techniques
                    except Exception as exc:
                        logger.warning(f"LLM explanation failed for {ioc.value}: {exc}")
                        explanation_text = f"(explanation unavailable: {exc})"
                        cited_techniques = []

                    explanation_cache[cache_key] = (explanation_text, cited_techniques)

            scanned = ScannedIOC(
                value=ioc.value,
                ioc_type=ioc.ioc_type,
                line_number=ioc.line_number,
                context=ioc.context,
                score=score,
                explanation=explanation_text,
                cited_techniques=cited_techniques,
            )

            if score.verdict == "malicious":
                malicious.append(scanned)
            elif score.verdict == "suspicious":
                suspicious.append(scanned)
            else:
                benign.append(scanned)

        # Rank malicious/suspicious by score, most confident first
        malicious.sort(key=lambda s: s.score.malicious_score, reverse=True)
        suspicious.sort(key=lambda s: s.score.malicious_score, reverse=True)

        report = LogScanReport(total_lines, len(extracted), malicious, suspicious, benign)
        logger.info(report.summary())
        return report

    def scan_file(self, file_path_or_bytes: Union[str, bytes], k: int = 5) -> LogScanReport:
        """
        Scan a log file from a path or raw bytes (e.g. from a Streamlit
        UploadedFile via `.read()` or `.getvalue()`).
        """
        if isinstance(file_path_or_bytes, (bytes, bytearray)):
            raw_text = file_path_or_bytes.decode("utf-8", errors="replace")
        else:
            with open(file_path_or_bytes, "r", encoding="utf-8", errors="replace") as f:
                raw_text = f.read()
        return self.scan_text(raw_text, k=k)


_scanner_instance: "LogScanner | None" = None


def get_scanner() -> "LogScanner":
    """Lazily initialize a module-level singleton so the model loads once, not per-request."""
    global _scanner_instance
    if _scanner_instance is None:
        embedder = IOCEmbedder(cache_dir=str(REPO_ROOT / "embedding_cache"), use_cache=True)
        embedder.initialize()
        _scanner_instance = LogScanner(embedder, reference_set_path=str(REPO_ROOT / "reference_embeddings.npz"))
    return _scanner_instance


def get_scanner_report(raw_bytes: bytes) -> LogScanReport:
    """Convenience entrypoint used by the FastAPI router."""
    return get_scanner().scan_file(raw_bytes)


if __name__ == "__main__":
    import sys
    import logging as _logging

    _logging.basicConfig(level=_logging.INFO)

    if len(sys.argv) != 2:
        print("Usage: python log_scanner.py <path_to_log_file>")
        sys.exit(1)

    embedder = IOCEmbedder(cache_dir="./embedding_cache", use_cache=True)
    embedder.initialize()

    scanner = LogScanner(embedder, reference_set_path=str(REPO_ROOT / "reference_embeddings.npz"))
    result = scanner.scan_file(sys.argv[1])

    print(result.summary())
    print("\n--- MALICIOUS ---")
    for item in result.malicious:
        print(f"[{item.ioc_type}] {item.value}  score={item.score.malicious_score:.2f}  line={item.line_number}")
        for n in item.score.neighbors[:3]:
            print(f"    nearest: ({n.label}, sim={n.similarity:.2f}) {n.text[:80]}")
        if item.cited_techniques:
            print(f"    ATT&CK: {', '.join(item.cited_techniques)}")

    print("\n--- SUSPICIOUS ---")
    for item in result.suspicious:
        print(f"[{item.ioc_type}] {item.value}  score={item.score.malicious_score:.2f}  line={item.line_number}")