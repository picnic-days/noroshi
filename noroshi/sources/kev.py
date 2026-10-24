"""CISA Known Exploited Vulnerabilities（実際に悪用が確認された脆弱性の一覧）。"""
from ..models import Vuln

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load(fetcher) -> dict:
    """KEV 全件を CVE ID -> Vuln で返す。新着判定と既存 CVE の補強の両方に使う。"""
    data = fetcher.get_json("kev", URL)
    result = {}
    for v in data.get("vulnerabilities", []):
        cve = v["cveID"]
        result[cve] = Vuln(
            id=cve,
            title=v.get("vulnerabilityName", ""),
            description=v.get("shortDescription", ""),
            published=v.get("dateAdded", ""),
            updated=v.get("dateAdded", ""),
            vendor_products=[f'{v.get("vendorProject", "")} {v.get("product", "")}'.strip()],
            references=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
            kev=True,
            kev_date_added=v.get("dateAdded", ""),
            ransomware=v.get("knownRansomwareCampaignUse") == "Known",
            sources=["kev"],
        )
    return result
