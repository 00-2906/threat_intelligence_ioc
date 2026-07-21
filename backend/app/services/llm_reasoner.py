"""
LLM reasoning layer — takes scored IOCs, their nearest labeled-reference
neighbors (kNN evidence), and any RAG-retrieved MITRE ATT&CK technique
context, and produces structured, plain-English explanations.

IOCs are explained in BATCHES (one LLM call covers many IOCs) rather than
one call per IOC. This is what keeps a 500-IOC report under the free-tier
daily request cap — 500 individual calls will exhaust a 20-request/day
quota almost instantly, but ~20 IOCs per call turns that into ~25 calls.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import List, Optional, TypedDict

from google import genai
from google.genai import errors as genai_errors
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.environ.get("Scanner_api")
if not GEMINI_API_KEY:
    raise RuntimeError(
        "GEMINI_API_KEY is not set. Add Scanner_api=... to your .env file."
    )

_client = genai.Client(api_key=GEMINI_API_KEY)
_MODEL = "gemini-2.5-flash"

_last_call_time = 0.0
_MIN_SECONDS_BETWEEN_CALLS = 13  # keeps you under free-tier per-minute limits

# Free-tier daily cap (currently 20 requests/day/project/model on the
# lite tier, higher but still finite on flash). Once hit, retrying does
# nothing until the quota resets — so we track it in-process and stop
# calling the API entirely for the rest of this run once we've seen a
# 429, instead of wasting time/log-noise on calls we already know will fail.
_quota_exhausted = False

DEFAULT_BATCH_SIZE = 20


class IOCInput(TypedDict, total=False):
    value: str
    ioc_type: str
    risk_score: float
    risk_label: str
    nearest_matches: list
    mitre_techniques: Optional[list]


@dataclass
class Explanation:
    summary: str
    cited_techniques: List[str] = field(default_factory=list)
    degraded: bool = False  # True if this is a fallback (LLM call failed/skipped)


def _throttle() -> None:
    global _last_call_time
    elapsed = time.time() - _last_call_time
    if elapsed < _MIN_SECONDS_BETWEEN_CALLS:
        time.sleep(_MIN_SECONDS_BETWEEN_CALLS - elapsed)


def _format_neighbors(nearest_matches: list[dict]) -> str:
    if not nearest_matches:
        return "(no similar reference IOCs found)"
    return "\n".join(
        f"- ({m['label']}, similarity={m['similarity']:.2f}) {m['text']}"
        for m in nearest_matches
    )


def _format_techniques(mitre_techniques: Optional[list[dict]]) -> str:
    if not mitre_techniques:
        return (
            "(no MITRE ATT&CK techniques retrieved — IOC risk was below "
            "the RAG lookup threshold)"
        )
    lines = []
    for t in mitre_techniques:
        tid = t.get("technique_id") or t.get("id") or "UNKNOWN"
        name = t.get("name") or t.get("title") or "Unnamed technique"
        desc = t.get("text") or t.get("description") or ""
        sim = t.get("similarity") or t.get("score")
        sim_str = f", similarity={sim:.2f}" if isinstance(sim, (int, float)) else ""
        lines.append(f"- [{tid}] {name}{sim_str}: {desc[:200]}")
    return "\n".join(lines)


def _is_quota_error(exc: Exception) -> bool:
    text = str(exc)
    return "RESOURCE_EXHAUSTED" in text or "429" in text


def _chunk(items: list, size: int) -> List[list]:
    return [items[i : i + size] for i in range(0, len(items), size)]


# ---------------------------------------------------------------------------
# Batch path (use this for reports covering many IOCs)
# ---------------------------------------------------------------------------

def explain_iocs_batch(
    iocs: List[IOCInput],
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> List[Explanation]:
    """
    Produce explanations for many IOCs using as few LLM calls as possible.

    iocs: list of dicts with keys: value, ioc_type, risk_score, risk_label,
        nearest_matches, mitre_techniques (optional).
    Returns a list of Explanation objects in the same order as `iocs`.
    """
    global _quota_exhausted

    results: List[Explanation] = [None] * len(iocs)  # type: ignore
    batches = _chunk(list(enumerate(iocs)), batch_size)

    for batch in batches:
        if _quota_exhausted:
            for idx, ioc in batch:
                results[idx] = _quota_fallback(
                    ioc["ioc_type"], ioc["risk_score"], ioc["risk_label"]
                )
            continue

        batch_explanations = _explain_batch_with_retry(batch)
        for (idx, _ioc), explanation in zip(batch, batch_explanations):
            results[idx] = explanation

    return results


def _explain_batch_with_retry(
    batch: List[tuple[int, IOCInput]],
    max_retries: int = 3,
) -> List[Explanation]:
    global _quota_exhausted, _last_call_time

    iocs_only = [ioc for _idx, ioc in batch]
    prompt = _build_batch_prompt(iocs_only)

    for attempt in range(max_retries):
        try:
            _throttle()
            response = _client.models.generate_content(
                model=_MODEL,
                contents=prompt,
            )
            _last_call_time = time.time()
            return _parse_batch_response(response.text.strip(), iocs_only)

        except genai_errors.ServerError as e:
            logger.warning(f"Gemini ServerError on batch attempt {attempt + 1}: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # 1s, 2s, 4s
                continue
            return [_fallback_explanation(i["ioc_type"], i["risk_score"], i["risk_label"]) for i in iocs_only]

        except genai_errors.ClientError as e:
            if _is_quota_error(e):
                logger.error(f"Gemini daily quota exhausted mid-batch: {e}")
                _quota_exhausted = True
                return [_quota_fallback(i["ioc_type"], i["risk_score"], i["risk_label"]) for i in iocs_only]
            logger.error(f"Gemini ClientError on batch: {e}")
            return [_fallback_explanation(i["ioc_type"], i["risk_score"], i["risk_label"]) for i in iocs_only]

        except Exception as e:
            logger.error(f"Unexpected error in batch explain: {type(e).__name__}: {e}")
            return [_fallback_explanation(i["ioc_type"], i["risk_score"], i["risk_label"]) for i in iocs_only]

    return [_fallback_explanation(i["ioc_type"], i["risk_score"], i["risk_label"]) for i in iocs_only]


def _build_batch_prompt(iocs: List[IOCInput]) -> str:
    items = []
    for i, ioc in enumerate(iocs):
        matches_text = _format_neighbors(ioc.get("nearest_matches", []))
        techniques_text = _format_techniques(ioc.get("mitre_techniques"))
        items.append(
            f"""IOC {i}:
Indicator: {ioc['value']} ({ioc['ioc_type']})
Final risk score: {ioc['risk_score']:.1f}/100 ({ioc['risk_label']})
Most similar known threats (from our labeled reference set):
{matches_text}
Related MITRE ATT&CK techniques (from threat intelligence retrieval):
{techniques_text}"""
        )
    joined = "\n\n".join(items)

    return f"""You are a SOC analyst assistant. For EACH indicator below, write a
3-4 sentence explanation of why it was flagged, for a report a small business
owner with no security background will read.

For each IOC, interpret the evidence — do not just restate the raw numbers.
If MITRE techniques were retrieved for that IOC, name the most relevant
one(s) and explain in plain language what that kind of attack does. If no
techniques were retrieved for that IOC, do not mention MITRE ATT&CK at all
for it — explain the risk based on the reference matches and score instead.

{joined}

Respond with ONLY a JSON array, no markdown code fences, no preamble, no
trailing commentary. One object per IOC above, in the exact same order,
each with exactly these fields:
[{{"index": 0, "summary": "...", "cited_techniques": ["T1566", ...]}}, ...]
Use an empty list for "cited_techniques" if none were cited for that IOC."""


def _parse_batch_response(text: str, iocs: List[IOCInput]) -> List[Explanation]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
        cleaned = cleaned.strip()

    try:
        parsed = json.loads(cleaned)
        if not isinstance(parsed, list):
            raise ValueError("Expected a JSON array")
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Failed to parse batch LLM response as JSON: {e}")
        return [_fallback_explanation(i["ioc_type"], i["risk_score"], i["risk_label"]) for i in iocs]

    by_index = {}
    for item in parsed:
        try:
            idx = int(item.get("index"))
            by_index[idx] = item
        except (TypeError, ValueError):
            continue

    results = []
    for i, ioc in enumerate(iocs):
        item = by_index.get(i)
        if not item or "summary" not in item:
            results.append(
                _fallback_explanation(ioc["ioc_type"], ioc["risk_score"], ioc["risk_label"])
            )
            continue
        cited = item.get("cited_techniques") or []
        if not isinstance(cited, list):
            cited = []
        results.append(
            Explanation(
                summary=str(item["summary"]).strip(),
                cited_techniques=[str(t).strip() for t in cited if str(t).strip()],
                degraded=False,
            )
        )
    return results


# ---------------------------------------------------------------------------
# Single-IOC path (kept for the live /scan endpoint — one lookup at a time,
# batching doesn't help there)
# ---------------------------------------------------------------------------

def explain_ioc(
    value: str,
    ioc_type: str,
    risk_score: float,
    risk_label: str,
    nearest_matches: list[dict],
    mitre_techniques: Optional[list[dict]] = None,
) -> Explanation:
    """
    Produce a structured explanation for a single scored IOC. Use
    explain_iocs_batch() instead when explaining many IOCs at once (e.g.
    building a report) — this per-IOC path burns one API call each and
    will exhaust the daily quota fast on large IOC sets.
    """
    global _quota_exhausted

    if _quota_exhausted:
        logger.info(f"Skipping Gemini call for {value} — daily quota already exhausted this run")
        return _quota_fallback(ioc_type, risk_score, risk_label)

    matches_text = _format_neighbors(nearest_matches)
    techniques_text = _format_techniques(mitre_techniques)

    prompt = f"""You are a SOC analyst assistant. Explain why the following indicator
was flagged, for a report a small business owner with no security background
will read.

Indicator: {value} ({ioc_type})
Final risk score: {risk_score:.1f}/100 ({risk_label})

Most similar known threats (from our labeled reference set):
{matches_text}

Related MITRE ATT&CK techniques (from threat intelligence retrieval):
{techniques_text}

Write a 3-4 sentence explanation. Interpret the evidence — do not just restate
the raw numbers. If MITRE techniques were retrieved, name the most relevant
one(s) and explain in plain language what that kind of attack does. If no
techniques were retrieved, do not mention MITRE ATT&CK at all — explain the
risk based on the reference matches and score instead.
End your response with a line in exactly this format:
CITED_TECHNIQUES: <comma-separated technique IDs you referenced, or NONE>"""

    max_retries = 3
    for attempt in range(max_retries):
        try:
            _throttle()
            response = _client.models.generate_content(
                model=_MODEL,
                contents=prompt,
            )
            global _last_call_time
            _last_call_time = time.time()
            return _parse_response(response.text.strip())

        except genai_errors.ServerError as e:
            logger.warning(f"Gemini ServerError on attempt {attempt + 1} for {value}: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # 1s, 2s, 4s
                continue
            return _fallback_explanation(ioc_type, risk_score, risk_label)

        except genai_errors.ClientError as e:
            if _is_quota_error(e):
                logger.error(f"Gemini daily quota exhausted (on {value}): {e}")
                _quota_exhausted = True  # stop trying for the rest of this process run
                return _quota_fallback(ioc_type, risk_score, risk_label)
            logger.error(f"Gemini ClientError for {value}: {e}")
            return _fallback_explanation(ioc_type, risk_score, risk_label)

        except Exception as e:
            logger.error(f"Unexpected error in explain_ioc for {value}: {type(e).__name__}: {e}")
            return _fallback_explanation(ioc_type, risk_score, risk_label)

    return _fallback_explanation(ioc_type, risk_score, risk_label)


def _parse_response(text: str) -> Explanation:
    cited: List[str] = []
    summary = text
    if "CITED_TECHNIQUES:" in text:
        summary, _, tail = text.rpartition("CITED_TECHNIQUES:")
        summary = summary.strip()
        tail = tail.strip()
        if tail and tail.upper() != "NONE":
            cited = [t.strip() for t in tail.split(",") if t.strip()]
    return Explanation(summary=summary, cited_techniques=cited, degraded=False)


def _fallback_explanation(ioc_type: str, risk_score: float, risk_label: str) -> Explanation:
    return Explanation(
        summary=(
            f"AI explanation temporarily unavailable (service overloaded). "
            f"This {ioc_type} was flagged as {risk_label} with a risk score of "
            f"{risk_score:.1f}/100 based on similarity to known threat patterns."
        ),
        cited_techniques=[],
        degraded=True,
    )


def _quota_fallback(ioc_type: str, risk_score: float, risk_label: str) -> Explanation:
    return Explanation(
        summary=(
            f"AI explanation unavailable: daily API quota reached. "
            f"This {ioc_type} was flagged as {risk_label} with a risk score of "
            f"{risk_score:.1f}/100 based on similarity to known threat patterns."
        ),
        cited_techniques=[],
        degraded=True,
    )