"""国内の公的な注意喚起（JPCERT/CC・IPA）。

狼煙がすでに即時通知した CVE についての注意喚起は日次まとめに回し、
まだ知らせていない事案（事前告知や CVE の無い不正アクセスの注意喚起など）は即時通知する。
"""
import re
import xml.etree.ElementTree as ET
from datetime import datetime

from ..models import Vuln

FEEDS = [
    {"id": "jpcert", "name": "JPCERT/CC", "url": "https://www.jpcert.or.jp/rss/jpcert.rdf", "title_prefix": "注意喚起"},
    {"id": "ipa", "name": "IPA", "url": "https://www.ipa.go.jp/security/alert-rss.rdf", "title_prefix": ""},
]
NS = {"rss": "http://purl.org/rss/1.0/", "dc": "http://purl.org/dc/elements/1.1/"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def parse(feed: dict, xml_text: str, since: datetime, notified: set) -> list:
    items = []
    for it in ET.fromstring(xml_text).findall("rss:item", NS):
        title = (it.findtext("rss:title", "", NS) or "").strip()
        link = it.findtext("rss:link", "", NS) or ""
        date = it.findtext("dc:date", "", NS) or ""
        if feed["title_prefix"] and not title.startswith(feed["title_prefix"]):
            continue
        try:
            published = datetime.fromisoformat(date)
        except ValueError:
            continue
        if published < since:
            continue
        cves = CVE_RE.findall(title)
        if "(更新)" in title or (cves and all(c in notified for c in cves)):
            level, score = "medium", 40.0
        else:
            level, score = "critical", 90.0
        slug = link.rstrip("/").rsplit("/", 1)[-1].split(".")[0]
        items.append(Vuln(
            id=f"JP-{feed['id']}-{slug}",
            aliases=cves,
            title=re.sub(r"^注意喚起:\s*", "", title),
            description=f"{feed['name']} の注意喚起",
            published=published.isoformat(),
            updated=published.isoformat(),
            references=[link],
            sources=[feed["id"]],
            category="jp-alert",
            matched=[feed["id"]],
            match_type="jp-alert",
            score=score,
            level=level,
        ))
    return items


def fetch(fetcher, since: datetime, notified: set) -> list:
    items = []
    for feed in FEEDS:
        if fetcher.is_mock and not fetcher.has_mock(f"jp_{feed['id']}", "xml"):
            continue
        try:
            items += parse(feed, fetcher.get_text(f"jp_{feed['id']}", feed["url"], "xml"), since, notified)
        except Exception as e:
            print(f"jp-alert: {feed['name']} の取得に失敗 ({e})")
    return items
