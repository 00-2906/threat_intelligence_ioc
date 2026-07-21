"""
IOC Scanner — Streamlit Frontend
---------------------------------
Matches the real backend schemas:

  POST {api_base}/scan
      body: {"ioc_type": "ip"|"domain"|"url"|"hash", "value": "<ioc>"}
      resp: ScanResponse { ioc_type, value, virustotal, abuseipdb,
                            risk_score (0-100), risk_label, explanation,
                            cited_techniques, errors }

  POST {api_base}/api/logs/scan?format=json   (multipart file upload)
      resp: { summary, total_lines_scanned, total_iocs_found,
              malicious: [ {value, type, line, context, score (0-100, confirmed
                             against live backend — NOT 0-1 despite the comment
                             in log_scanner.py), explanation, cited_techniques,
                             nearest_matches} ],
              suspicious: [ {value, type, line, context, score (0-100),
                              explanation, cited_techniques} ] }
      (benign IOCs are not returned by the API)

  POST {api_base}/api/logs/scan?format=pdf    -> raw PDF bytes, for download

Run locally with:
    streamlit run app.py

In production, set the BACKEND_URL environment variable to your deployed
FastAPI backend's URL — the sidebar picks it up automatically.
"""

import streamlit as st
import requests
import pandas as pd
import os

st.set_page_config(page_title="IOC Scanner", page_icon="🛡️", layout="wide")

# ---------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ IOC Scanner")
    st.caption("AI-powered threat intel scoring & explanation")

    default_backend = os.environ.get("BACKEND_URL", "http://127.0.0.1:8000")
    api_base = st.text_input(
        "Backend URL",
        value=default_backend,
        help="Base URL of your FastAPI backend (no trailing slash).",
    ).rstrip("/")

    st.divider()
    mode = st.radio("Mode", ["Single IOC Lookup", "Log File Scan"])

    st.divider()
    st.caption(
        "FastAPI • kNN cosine similarity • VirusTotal + AbuseIPDB • "
        "Gemini (gemini-2.5-flash) reasoning • MITRE ATT&CK context"
    )

# ---------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------
RISK_COLORS = {
    "malicious": "#e74c3c",
    "danger": "#e74c3c",
    "high": "#e74c3c",
    "critical": "#e74c3c",
    "suspicious": "#f39c12",
    "warn": "#f39c12",
    "medium": "#f39c12",
    "caution": "#f39c12",
    "benign": "#2ecc71",
    "chill": "#2ecc71",
    "low": "#2ecc71",
    "clean": "#2ecc71",
    "safe": "#2ecc71",
}
UNKNOWN_COLOR = "#95a5a6"


def risk_color(label: str) -> str:
    """Substring match so custom backend labels (DANGER_ZONE, CHILL_ZONE,
    etc.) still get colored correctly without needing the exact string."""
    normalized = (label or "").strip().lower()
    for keyword, color in RISK_COLORS.items():
        if keyword in normalized:
            return color
    return UNKNOWN_COLOR


def risk_pill(label: str):
    color = risk_color(label)
    st.markdown(
        f"""<div style="display:inline-block;padding:6px 18px;border-radius:999px;
        background:{color}22;border:1.5px solid {color};color:{color};
        font-weight:700;font-size:0.95rem;letter-spacing:0.5px;">
        {(label or 'UNKNOWN').upper()}</div>""",
        unsafe_allow_html=True,
    )


def score_gauge(score, scale_hint: str = "auto"):
    """scale_hint: 'auto' (guess 0-1 vs 0-100), '0-1', or '0-100'."""
    try:
        val = float(score)
    except (TypeError, ValueError):
        val = 0.0
    if scale_hint == "0-1" or (scale_hint == "auto" and 0 <= val <= 1):
        val *= 100
    val = max(0.0, min(100.0, val))
    color = "#2ecc71" if val < 34 else "#f39c12" if val < 67 else "#e74c3c"
    st.progress(val / 100)
    st.markdown(
        f"<span style='color:{color};font-weight:700;font-size:0.9rem;'>{val:.0f} / 100</span>",
        unsafe_allow_html=True,
    )


def render_techniques(cited_techniques):
    if cited_techniques:
        st.markdown("**MITRE ATT&CK techniques cited:**")
        st.write(", ".join(cited_techniques))


# ---------------------------------------------------------------------
# Single IOC Lookup  ->  POST /scan
# ---------------------------------------------------------------------
if mode == "Single IOC Lookup":
    st.header("🔍 Single IOC Lookup")
    st.caption("Scan a file hash (MD5/SHA1/SHA256), IP address, domain, or URL.")

    with st.form("scan_form"):
        c1, c2 = st.columns([1, 3])
        with c1:
            ioc_type = st.selectbox("IOC type", ["ip", "domain", "url", "hash"])
        with c2:
            ioc_value = st.text_input("IOC value", placeholder="e.g. 8.8.8.8 or a SHA256 hash")
        submitted = st.form_submit_button("Scan", use_container_width=True)

    if submitted:
        if not ioc_value.strip():
            st.warning("Enter an IOC value first.")
        else:
            with st.spinner("Scanning... (reputation APIs + kNN scoring + LLM reasoning)"):
                try:
                    resp = requests.post(
                        f"{api_base}/scan",
                        json={"ioc_type": ioc_type, "value": ioc_value.strip()},
                        timeout=60,
                    )
                    resp.raise_for_status()
                    data = resp.json()

                    if data.get("errors"):
                        for err in data["errors"]:
                            st.warning(err)

                    st.success("Scan complete.")

                    col1, col2 = st.columns([1, 2])
                    with col1:
                        st.markdown(f"**IOC:** `{data.get('value')}`")
                        st.markdown(f"**Type:** {data.get('ioc_type')}")
                        risk_pill(data.get("risk_label"))
                    with col2:
                        st.markdown("**Risk Score** (0-100)")
                        score_gauge(data.get("risk_score"), scale_hint="0-100")

                    st.markdown("### 🧠 AI Explanation")
                    st.info(data.get("explanation") or "No explanation returned.")
                    render_techniques(data.get("cited_techniques"))

                    with st.expander("📄 Raw VirusTotal data"):
                        st.json(data.get("virustotal") or {"info": "No data"})
                    with st.expander("📄 Raw AbuseIPDB data"):
                        st.json(data.get("abuseipdb") or {"info": "No data"})
                    with st.expander("🔧 Full raw response"):
                        st.json(data)

                except requests.exceptions.ConnectionError:
                    st.error(f"Could not reach backend at `{api_base}`. Is FastAPI running?")
                except requests.exceptions.HTTPError as e:
                    st.error(f"Backend returned an error: {e} — {resp.text}")
                except Exception as e:
                    st.error(f"Unexpected error: {e}")

# ---------------------------------------------------------------------
# Log File Scan  ->  POST /api/logs/scan
# ---------------------------------------------------------------------
else:
    st.header("📁 Log File Scan")
    st.caption("Upload a .log or .txt file — IOCs are extracted and scanned automatically.")

    uploaded_file = st.file_uploader("Upload log file", type=["log", "txt"])

    if uploaded_file is not None:
        if st.button("Scan Log File", use_container_width=True):
            with st.spinner("Extracting IOCs and scanning... this may take a moment"):
                try:
                    files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "text/plain")}
                    resp = requests.post(
                        f"{api_base}/api/logs/scan",
                        params={"format": "json"},
                        files=files,
                        timeout=180,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    st.session_state["log_result"] = data
                    st.session_state["log_file_bytes"] = uploaded_file.getvalue()
                    st.session_state["log_file_name"] = uploaded_file.name
                except requests.exceptions.ConnectionError:
                    st.error(f"Could not reach backend at `{api_base}`. Is FastAPI running?")
                except requests.exceptions.HTTPError as e:
                    st.error(f"Backend returned an error: {e} — {resp.text}")
                except Exception as e:
                    st.error(f"Unexpected error: {e}")

    data = st.session_state.get("log_result")
    if data:
        st.success(data.get("summary", "Scan complete."))
        m1, m2, m3 = st.columns(3)
        m1.metric("Lines scanned", data.get("total_lines_scanned", 0))
        m2.metric("IOCs found", data.get("total_iocs_found", 0))
        m3.metric(
            "Flagged (malicious + suspicious)",
            len(data.get("malicious", [])) + len(data.get("suspicious", [])),
        )

        # Note: the API only returns malicious + suspicious IOCs, not benign ones.
        malicious = data.get("malicious", [])
        suspicious = data.get("suspicious", [])
        combined = [{**item, "risk_label": "malicious"} for item in malicious] + [
            {**item, "risk_label": "suspicious"} for item in suspicious
        ]

        if not combined:
            st.info("No malicious or suspicious IOCs found in this file. 🎉")
        else:
            table_rows = [
                {
                    "IOC": item["value"],
                    "Type": item["type"],
                    "Line": item["line"],
                    "Risk Label": item["risk_label"].upper(),
                    "Score": round(float(item.get("score", 0)) * 100, 1),
                }
                for item in combined
            ]
            df = pd.DataFrame(table_rows).sort_values("Score", ascending=False)
            st.dataframe(df, use_container_width=True, hide_index=True)

            st.divider()
            st.markdown("### Drill into a specific IOC")
            options = [f"{item['value']} (line {item['line']})" for item in combined]
            selected_idx = st.selectbox(
                "Select an IOC", range(len(options)), format_func=lambda i: options[i]
            )
            item = combined[selected_idx]

            col1, col2 = st.columns([1, 2])
            with col1:
                st.markdown(f"**IOC:** `{item['value']}`")
                st.markdown(f"**Type:** {item['type']}")
                st.markdown(f"**Line:** {item['line']}")
                risk_pill(item["risk_label"])
            with col2:
                st.markdown("**Risk Score**")
                score_gauge(item.get("score"), scale_hint="0-1")

            st.markdown("### 🧠 AI Explanation")
            st.info(item.get("explanation") or "No explanation returned.")
            render_techniques(item.get("cited_techniques"))

            if item.get("context"):
                with st.expander("📄 Log line context"):
                    st.code(item["context"])

            if item.get("nearest_matches"):
                with st.expander("🔎 Nearest reference matches (kNN)"):
                    st.json(item["nearest_matches"])

        st.divider()
        st.markdown("### 📥 PDF Report")
        if st.button("Generate & Download PDF Report"):
            with st.spinner("Generating PDF report..."):
                try:
                    file_bytes = st.session_state["log_file_bytes"]
                    file_name = st.session_state["log_file_name"]
                    pdf_resp = requests.post(
                        f"{api_base}/api/logs/scan",
                        params={"format": "pdf"},
                        files={"file": (file_name, file_bytes, "text/plain")},
                        timeout=180,
                    )
                    pdf_resp.raise_for_status()
                    st.download_button(
                        "Click to save PDF",
                        data=pdf_resp.content,
                        file_name="ioc-scan-report.pdf",
                        mime="application/pdf",
                    )
                except Exception as e:
                    st.error(f"Could not generate PDF: {e}")

st.divider()
st.caption(
    "IOC Scanner — ML risk scoring + LLM explainability + MITRE ATT&CK context "
    "over threat intel indicators."
)