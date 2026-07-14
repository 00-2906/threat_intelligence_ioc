import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

if not VIRUSTOTAL_API_KEY:
    print("[warning] VIRUSTOTAL_API_KEY not set — VirusTotal calls will fail.")
if not ABUSEIPDB_API_KEY:
    print("[warning] ABUSEIPDB_API_KEY not set — AbuseIPDB calls will fail.")
