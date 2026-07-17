from typing import List, Tuple, Dict
import re

DEFAULT_CHUNK_LINES = 250
DEFAULT_OVERLAP = 5


def chunk_lines(lines: List[str], chunk_size: int, overlap: int):
    n = len(lines)
    start = 0
    while start < n:
        end = min(start + chunk_size, n)
        yield start + 1, end, lines[start:end]
        if end == n:
            break
        start = max(0, end - overlap)


def extract_key_lines(chunk: List[str], max_items: int = 15) -> List[str]:
    out = []
    fn_re = re.compile(r"^(\s*)(def |class |function |async def |#|//|/\*)")
    todo_re = re.compile(r"TODO|FIXME", re.IGNORECASE)
    for ln in chunk:
        s = ln.strip()
        if not s:
            continue
        if todo_re.search(s):
            out.append(s)
            continue
        if s.startswith("def ") or s.startswith("class ") or s.startswith("function ") or s.startswith("async def "):
            out.append(s)
            continue
        if s.startswith("#") or s.startswith("//"):
            out.append(s)
            continue
        # capture long lines that might be significant
        if len(s) > 120:
            out.append(s[:200] + ("..." if len(s) > 200 else ""))
        if len(out) >= max_items:
            break
    return out


def summarize_text(full_text: str, chunk_lines: int = DEFAULT_CHUNK_LINES, overlap: int = DEFAULT_OVERLAP) -> Dict:
    lines = full_text.splitlines()
    preview = "\n".join(lines[:300])
    chunks = []
    for start, end, chunk in chunk_lines:  # bug: name conflict, fix below
        pass

# Fixing the naming conflict: rename chunking function usage

def summarize_text(full_text: str, chunk_size: int = DEFAULT_CHUNK_LINES, overlap: int = DEFAULT_OVERLAP) -> Dict:
    lines = full_text.splitlines()
    preview = "\n".join(lines[:300])
    chunks = []
    for start, end, chunk in chunk_lines(lines, chunk_size, overlap):
        key_lines = extract_key_lines(chunk, max_items=15)
        summary = "\n".join(key_lines) if key_lines else ("".join(chunk)[:300] + ("..." if len(chunk) > 300 else ""))
        chunks.append({"start": start, "end": end, "summary": summary})
    final_summary_parts = [f"File has {len(lines)} lines and {len(chunks)} chunks."]
    # short structural overview: count functions/classes
    func_count = sum(1 for ln in lines if ln.strip().startswith("def ") or ln.strip().startswith("async def "))
    class_count = sum(1 for ln in lines if ln.strip().startswith("class "))
    todo_count = sum(1 for ln in lines if re.search(r"TODO|FIXME", ln, re.IGNORECASE))
    final_summary_parts.append(f"Detected {func_count} function(s), {class_count} class(es), and {todo_count} TODO/FIXME comment(s).")
    final_summary_parts.append("Per-chunk highlights combined below:\n")
    for c in chunks:
        final_summary_parts.append(f"Lines {c['start']}-{c['end']}: {c['summary'].splitlines()[0] if c['summary'] else '—'}")
    final_summary = "\n".join(final_summary_parts)
    return {"preview": preview, "chunks": chunks, "final_summary": final_summary}
