"""CVE.org の公式データ（CVEProject/cvelistV5）。NVD より数時間早く新規 CVE を拾う。

deltaLog.json は直近 30 日分の差分を新しい順に並べた 30MB 超のファイルなので、
先頭の必要な分だけ Range で取り、途中で切れた JSON は読めた所までで止める。
"""
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from ..models import Vuln

DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
BYTES_PER_DAY = 1_500_000  # 実測で 1 日あたり約 1.2MB
MIN_BYTES, MAX_BYTES = 200_000, 12_000_000
MAX_RECORDS = 800  # 1 回の実行で取りに行く記録の上限（新規は 1 日約 500 件）
WORKERS = 8


def _iter_entries(text: str):
    """切れているかもしれない JSON 配列から、完全な要素だけを先頭から順に返す。"""
    decoder = json.JSONDecoder()
    i = text.find("[") + 1
    while True:
        while i < len(text) and text[i] in " \t\r\n,":
            i += 1
        try:
            obj, i = decoder.raw_decode(text, i)
        except ValueError:
            return
        yield obj


def new_cve_links(text: str, since: datetime) -> dict:
    """since 以降に新規公開された CVE の ID -> 記録 URL。"""
    cutoff = since.strftime("%Y-%m-%dT%H:%M:%S")
    links = {}
    for entry in _iter_entries(text):
        if entry.get("fetchTime", "") < cutoff:
            break
        for item in entry.get("new", []):
            links.setdefault(item["cveId"], item["githubLink"])
    return links


def _cvss(metrics: list):
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
        for m in metrics:
            data = m.get(key)
            if data and "baseScore" in data:
                return data["baseScore"], data.get("vectorString", ""), data.get("baseSeverity", "")
    return None, "", ""


def _ssvc_exploitation(adps: list) -> str:
    for adp in adps:
        for m in adp.get("metrics", []):
            other = m.get("other", {})
            if other.get("type") == "ssvc":
                for opt in other.get("content", {}).get("options", []):
                    if "Exploitation" in opt:
                        return opt["Exploitation"].lower()
    return ""


def parse(record: dict):
    meta = record.get("cveMetadata", {})
    if meta.get("state") != "PUBLISHED":
        return None
    containers = record.get("containers", {})
    cna = containers.get("cna", {})
    adps = containers.get("adp", [])
    # CNA が CVSS を付けていない場合は CISA などの ADP が補っていることがある
    score, vector, severity = _cvss(cna.get("metrics", []))
    if score is None:
        score, vector, severity = _cvss([m for a in adps for m in a.get("metrics", [])])

    vendor_products, cpes = [], []
    for a in cna.get("affected", []):
        vp = f'{a.get("vendor", "")} {a.get("product", "")}'.strip()
        if vp and vp not in vendor_products:
            vendor_products.append(vp)
        if a.get("packageName") and a["packageName"] not in vendor_products:
            vendor_products.append(a["packageName"])
        for c in a.get("cpes") or []:
            parts = c.split(":")
            if len(parts) > 4 and f"{parts[3]}:{parts[4]}" not in cpes:
                cpes.append(f"{parts[3]}:{parts[4]}")

    refs = cna.get("references", [])
    exploitation = _ssvc_exploitation(adps)
    return Vuln(
        id=meta["cveId"],
        title=cna.get("title", ""),
        description=next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), ""),
        published=meta.get("datePublished", ""),
        updated=meta.get("dateUpdated", ""),
        cvss=score,
        cvss_vector=vector,
        severity=severity.lower(),
        cpes=cpes,
        vendor_products=vendor_products,
        references=[r["url"] for r in refs[:10]],
        exploit_ref=exploitation == "poc" or any("exploit" in r.get("tags", []) for r in refs),
        ssvc_exploitation=exploitation,
        sources=["cve.org"],
    )


def fetch(fetcher, since: datetime, now: datetime) -> list:
    days = (now - since).total_seconds() / 86400
    nbytes = int(min(MAX_BYTES, max(MIN_BYTES, BYTES_PER_DAY * days + MIN_BYTES)))
    links = new_cve_links(fetcher.get_text_range("cvelist_delta", DELTA_LOG_URL, nbytes), since)
    ids = list(links)[:MAX_RECORDS]
    if len(links) > MAX_RECORDS:
        print(f"cve.org: 新規 {len(links)} 件のうち {MAX_RECORDS} 件だけ取得")

    def get(cve_id):
        try:
            return parse(fetcher.get_json("cvelist_record", links[cve_id], mock_key=cve_id) or {})
        except Exception as e:  # 1 件の取得失敗で全体を止めない
            print(f"cve.org: {cve_id} の取得に失敗 ({e})")
            return None

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        return [v for v in pool.map(get, ids) if v]
