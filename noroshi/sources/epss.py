"""FIRST EPSS（今後30日に悪用される確率の予測値）で CVE を補強する。"""
URL = "https://api.first.org/data/v1/epss"
CHUNK = 80  # URL 長の制限に収まる件数


def enrich(fetcher, vulns: list) -> None:
    by_id = {v.id: v for v in vulns if v.id.startswith("CVE-")}
    ids = list(by_id)
    for i in range(0, len(ids), CHUNK):
        data = fetcher.get_json("epss", URL, params={"cve": ",".join(ids[i:i + CHUNK])})
        for row in data.get("data", []):
            v = by_id.get(row.get("cve"))
            if v:
                v.epss = float(row["epss"])
                v.epss_percentile = float(row["percentile"])
