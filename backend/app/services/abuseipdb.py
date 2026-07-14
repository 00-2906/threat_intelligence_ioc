"""
AbuseIPDB lookups (IP addresses only).
Docs: https://docs.abuseipdb.com/
"""
import requests

from app.config import ABUSEIPDB_API_KEY

BASE_URL = "https://api.abuseipdb.com/api/v2/check"


def get_ip_report(ip: str, max_age_days: int = 90) -> dict:
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": max_age_days}
    resp = requests.get(BASE_URL, headers=headers, params=params, timeout=15)
    resp.raise_for_status()
    return resp.json()
