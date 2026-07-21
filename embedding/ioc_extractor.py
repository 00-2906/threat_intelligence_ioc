"""
Extracts candidate IOCs (IPs, domains, URLs, file hashes) from raw log text.

Handles common defanging conventions used in threat intel / SOC logs
(hxxp://, [.], (dot), etc.) before matching, then builds a short context
string per IOC (the source line) suitable for embedding.
"""

import re
from dataclasses import dataclass, field
from typing import List, Set


IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
URL_RE = re.compile(r"\b(?:https?|hxxps?)://[^\s\"'<>\]\)]+", re.IGNORECASE)
# Domain: at least one dot, valid-looking TLD (2-24 alpha chars), not preceded by @ (email) or / (path segment)
DOMAIN_RE = re.compile(
    r"\b(?<![@/])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)

# Tokens that match DOMAIN_RE but are almost never real IOCs — filter these out
COMMON_FALSE_POSITIVES = {
    "e.g.com", "example.com", "localhost.localdomain", "i.e.com",
}
COMMON_FILE_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "css", "js", "html", "py", "log", "txt", "json",
    "xml", "yml", "yaml", "conf", "cfg", "ini",
    "exe", "dll", "ps1", "bat", "sh", "cmd", "msi", "scr", "vbs", "jar",
}


@dataclass
class ExtractedIOC:
    value: str          # the IOC itself, refanged (e.g. "185.220.101.4")
    ioc_type: str        # "ip" | "domain" | "url" | "md5" | "sha1" | "sha256"
    context: str          # the source log line, used to build the embedding text
    line_number: int


def refang(text: str) -> str:
    """Reverse common defanging conventions so regexes can match normally."""
    text = text.replace("hxxp://", "http://").replace("hxxps://", "https://")
    text = text.replace("[.]", ".").replace("(.)", ".").replace("(dot)", ".")
    text = text.replace("[:]", ":")
    return text


def _is_likely_filename(domain_candidate: str) -> bool:
    """Filter out things like 'payload.exe' or 'script.js' that match the domain regex."""
    ext = domain_candidate.rsplit(".", 1)[-1].lower()
    return ext in COMMON_FILE_EXTENSIONS


def extract_iocs_from_text(raw_text: str) -> List[ExtractedIOC]:
    """
    Extract candidate IOCs line-by-line from raw log text.

    Each line becomes the context for any IOC found on it. Hashes are
    matched by decreasing specificity (sha256 > sha1 > md5-length hex)
    to avoid a sha256 also being reported as containing an md5 substring.
    """
    results: List[ExtractedIOC] = []
    seen: Set[str] = set()  # dedupe on (type, value)

    for line_no, raw_line in enumerate(raw_text.splitlines(), start=1):
        if not raw_line.strip():
            continue
        line = refang(raw_line)

        # URLs first (so their domains aren't double-counted separately)
        url_spans = []
        for m in URL_RE.finditer(line):
            url = m.group(0).rstrip(".,;:)")
            key = ("url", url)
            url_spans.append((m.start(), m.end()))
            if key not in seen:
                seen.add(key)
                results.append(ExtractedIOC(url, "url", raw_line.strip(), line_no))

        def _inside_url(pos: int) -> bool:
            return any(s <= pos < e for s, e in url_spans)

        for m in IPV4_RE.finditer(line):
            if _inside_url(m.start()):
                continue
            val = m.group(0)
            key = ("ip", val)
            if key not in seen:
                seen.add(key)
                results.append(ExtractedIOC(val, "ip", raw_line.strip(), line_no))

        for m in SHA256_RE.finditer(line):
            val = m.group(0).lower()
            key = ("sha256", val)
            if key not in seen:
                seen.add(key)
                results.append(ExtractedIOC(val, "sha256", raw_line.strip(), line_no))

        sha256_vals = {r.value for r in results if r.ioc_type == "sha256"}
        for m in SHA1_RE.finditer(line):
            val = m.group(0).lower()
            if val in sha256_vals:
                continue
            key = ("sha1", val)
            if key not in seen:
                seen.add(key)
                results.append(ExtractedIOC(val, "sha1", raw_line.strip(), line_no))

        longer_hashes = sha256_vals | {r.value for r in results if r.ioc_type == "sha1"}
        for m in MD5_RE.finditer(line):
            val = m.group(0).lower()
            if val in longer_hashes:
                continue
            key = ("md5", val)
            if key not in seen:
                seen.add(key)
                results.append(ExtractedIOC(val, "md5", raw_line.strip(), line_no))

        for m in DOMAIN_RE.finditer(line):
            if _inside_url(m.start()):
                continue
            val = m.group(0).lower().rstrip(".")
            if val in COMMON_FALSE_POSITIVES or _is_likely_filename(val):
                continue
            key = ("domain", val)
            if key not in seen:
                seen.add(key)
                results.append(ExtractedIOC(val, "domain", raw_line.strip(), line_no))

    return results


def build_embedding_text(ioc: ExtractedIOC) -> str:
    """
    Build the text string to embed for a given extracted IOC.

    Combines the IOC type + value + surrounding log context, matching the
    style of context strings used when building the reference embedding set
    (see reference_embeddings.py), so both sides live in the same semantic space.
    """
    label = {
        "ip": "IP address",
        "domain": "domain",
        "url": "URL",
        "md5": "MD5 hash",
        "sha1": "SHA1 hash",
        "sha256": "SHA256 hash",
        "hash": "hash",  # fallback for unrecognized hash length (e.g. malformed input from /scan)
    }[ioc.ioc_type]
    return f"{label} {ioc.value} observed in log line: {ioc.context}"