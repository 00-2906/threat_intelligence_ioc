# IOC Scanner — AI-Powered Threat Intelligence Tool

An IOC (Indicator of Compromise) scanner that doesn't just say "this is malicious" —
it explains *why*, using anomaly detection + retrieval of similar past threat cases +
AI-generated reasoning.

## Current stage: 1–5 (Backend + VirusTotal + AbuseIPDB + CLI script + risk scoring + history)

## Project roadmap
1. ✅ FastAPI backend skeleton + VirusTotal lookup
2. ✅ AbuseIPDB lookup added
3. ✅ CLI batch-scanning script (`scripts/batch_scan.py`)
4. ✅ Rule-based risk score, with fun labels (😎 Chill Zone → ☠️ Full Villain Arc)
5. ✅ SQLite scan history storage (`GET /history`)
6. ⬜ Isolation Forest anomaly scoring (unsupervised, no labeled data needed) — replaces the rule-based score, keeps the fun labels
7. ⬜ RAG layer — ChromaDB (embedded, no server) + sentence-transformers
8. ⬜ Claude API reasoning layer — turns evidence into a plain-English explanation
9. ⬜ Relationship graph — NetworkX + pyvis (maps shared infrastructure between IOCs)
10. ⬜ Streamlit frontend with embedded graph
11. ⬜ PDF report generation + Docker + deployment

Tooling notes: earlier drafts of this project considered Qdrant, Neo4j, and
Next.js. Those were swapped for ChromaDB, NetworkX/pyvis, and Streamlit —
same advanced ideas (RAG, graph correlation), simpler setup (no extra
database servers, no new frontend framework to learn).

## Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env       # then fill in your API keys
uvicorn app.main:app --reload
```

Then open http://127.0.0.1:8000/docs to test the `/scan` endpoint interactively.

## Getting free API keys
- VirusTotal: https://www.virustotal.com/gui/join-us (free tier: 500 requests/day, 4/min)
- AbuseIPDB: https://www.abuseipdb.com/register (free tier: 1000 requests/day)

## Example request

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"ioc_type": "ip", "value": "8.8.8.8"}'
```

## CLI batch scanning script

With the API server running (see Setup above), you can scan a whole list
of IOCs from the command line instead of hitting the API one at a time:

```bash
cd scripts
python batch_scan.py --input sample_iocs.txt --output results.csv
```

This reads `sample_iocs.txt` (format: `type,value` per line), scans each
IOC against your running API, and writes a summary CSV. Useful for
automation — e.g. wiring this into a scheduled task or CI pipeline later.
