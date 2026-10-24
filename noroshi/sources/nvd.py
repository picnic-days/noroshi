"""NVD CVE API 2.0。"""
from datetime import datetime

from ..models import Vuln

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _cvss(metrics: dict):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key, []):
            data = m.get("cvssData", {})
            if "baseScore" in data:
                return data["baseScore"], data.get("vectorString", ""), data.get("baseSeverity", "")
    return None, "", ""


def _cpes(configurations: list) -> list:
    found = []
    for conf in configurations:
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                # vulnerable: false は「この OS 上で動く場合」などの動作環境なので対象外
                if not match.get("vulnerable", True):
                    continue
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4:
                    vp = f"{parts[3]}:{parts[4]}"
                    if vp not in found:
                        found.append(vp)
    return found


def parse(item: dict) -> Vuln:
    cve = item["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, vector, severity = _cvss(cve.get("metrics", {}))
    refs = cve.get("references", [])
    return Vuln(
        id=cve["id"],
        description=desc,
        published=cve.get("published", ""),
        updated=cve.get("lastModified", ""),
        cvss=score,
        cvss_vector=vector,
        severity=severity.lower(),
        cpes=_cpes(cve.get("configurations", [])),
        references=[r["url"] for r in refs[:10]],
        exploit_ref=any("Exploit" in r.get("tags", []) for r in refs),
        sources=["nvd"],
    )


def fetch(fetcher, since: datetime, until: datetime, api_key: str = "") -> list:
    headers = {"apiKey": api_key} if api_key else None
    vulns, start = [], 0
    while True:
        data = fetcher.get_json("nvd", URL, params={
            "lastModStartDate": _fmt(since),
            "lastModEndDate": _fmt(until),
            "resultsPerPage": PAGE_SIZE,
            "startIndex": start,
        }, headers=headers)
        items = data.get("vulnerabilities", [])
        vulns.extend(parse(i) for i in items)
        start += len(items)
        if fetcher.is_mock or not items or start >= data.get("totalResults", 0):
            return vulns
