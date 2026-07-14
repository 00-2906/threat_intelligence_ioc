"""
VirusTotal API v3 lookups.
Docs: https://docs.virustotal.com/reference/overview
"""
import requests

from app.config import VIRUSTOTAL_API_KEY

BASE_URL = "https://www.virustotal.com/api/v3"


def _headers() -> dict:
    return {"x-apikey": VIRUSTOTAL_API_KEY}


def get_ip_report(ip: str) -> dict:
    resp = requests.get(f"{BASE_URL}/ip_addresses/{ip}", headers=_headers(), timeout=15)
    resp.raise_for_status()
    return resp.json()


def get_domain_report(domain: str) -> dict:
    resp = requests.get(f"{BASE_URL}/domains/{domain}", headers=_headers(), timeout=15)
    resp.raise_for_status()
    return resp.json()


def get_hash_report(file_hash: str) -> dict:
    resp = requests.get(f"{BASE_URL}/files/{file_hash}", headers=_headers(), timeout=15)
    resp.raise_for_status()
    return resp.json()


def get_url_report(url: str) -> dict:
    # VirusTotal requires URLs to be submitted, then looked up by a derived ID.
    submit = requests.post(
        f"{BASE_URL}/urls",
        headers=_headers(),
        data={"url": url},
        timeout=15,
    )
    submit.raise_for_status()
    analysis_id = submit.json()["data"]["id"]

    resp = requests.get(f"{BASE_URL}/analyses/{analysis_id}", headers=_headers(), timeout=15)
    resp.raise_for_status()
    return resp.json()


def lookup(ioc_type: str, value: str) -> dict:
    """Route to the right VirusTotal lookup based on IOC type."""
    if ioc_type == "ip":
        return get_ip_report(value)
    if ioc_type == "domain":
        return get_domain_report(value)
    if ioc_type == "hash":
        return get_hash_report(value)
    if ioc_type == "url":
        return get_url_report(value)
    raise ValueError(f"Unsupported ioc_type for VirusTotal: {ioc_type}")
