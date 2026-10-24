"""GitHub Security Advisories（レビュー済みのグローバルアドバイザリ）。"""
from datetime import datetime

from ..models import Vuln

URL = "https://api.github.com/advisories"


def parse(adv: dict) -> Vuln:
    sev = adv.get("cvss_severities") or {}
    cvss = sev.get("cvss_v4") or {}
    if not cvss.get("score"):
        cvss = sev.get("cvss_v3") or adv.get("cvss") or {}
    packages = []
    for v in adv.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        if pkg.get("name"):
            key = f'{pkg.get("ecosystem", "").lower()}:{pkg["name"].lower()}'
            if key not in packages:
                packages.append(key)
    return Vuln(
        id=adv.get("cve_id") or adv["ghsa_id"],
        aliases=[adv["ghsa_id"]] if adv.get("cve_id") else [],
        title=adv.get("summary", ""),
        description=adv.get("description", ""),
        published=adv.get("published_at", ""),
        updated=adv.get("updated_at", ""),
        cvss=cvss.get("score") or None,
        cvss_vector=cvss.get("vector_string") or "",
        severity=(adv.get("severity") or "").lower(),
        packages=packages,
        references=[adv.get("html_url", "")] + (adv.get("references") or [])[:5],
        sources=["ghsa"],
    )


def fetch(fetcher, since: datetime, token: str = "") -> list:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = fetcher.get_json("ghsa", URL, params={
        "type": "reviewed",
        "modified": f">={since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "sort": "updated",
        "direction": "desc",
        "per_page": 100,
    }, headers=headers)
    return [parse(a) for a in data]
