"""認証局（CA）事案。Mozilla の CA Program（Bugzilla）に報告されたものを拾う。

CVE が付かない種類の事件（中間 CA の鍵侵害、ルート証明書の信頼取り消しなど）を補う。
件数の大半は監査遅延や文書不備などの軽微な事案なので、要約と分類タグで 3 段階に振り分ける。
"""
import re
from datetime import datetime

from ..models import Vuln

URL = "https://bugzilla.mozilla.org/rest/bug"
COMPONENTS = ["CA Certificate Compliance", "CA Certificate Root Program"]

# 鍵の侵害やルートの信頼取り消しは、証明書の差し替えが必要になりうるので即時に知らせる
CRITICAL_RE = re.compile(r"key compromise|private key|compromis|distrust|remov\w* .*root|root .*remov", re.I)
# 誤発行や失効遅延は利用者側にも影響しうるので日次まとめに載せる
NOTABLE_TAGS = {"ca-misissuance", "dv-misissuance", "ov-misissuance", "ev-misissuance",
                "leaf-revocation-delay", "ca-revocation-delay", "external", "audit-failure"}
TAG_RE = re.compile(r"\[([a-z_-]+)\]")


def classify(summary: str, whiteboard: str) -> tuple:
    """(level, score) を返す。"""
    if CRITICAL_RE.search(summary):
        return "critical", 90.0
    if NOTABLE_TAGS & set(TAG_RE.findall(whiteboard or "")):
        return "medium", 40.0
    return "low", 10.0


def parse(bug: dict) -> Vuln:
    level, score = classify(bug.get("summary", ""), bug.get("whiteboard", ""))
    url = f"https://bugzilla.mozilla.org/show_bug.cgi?id={bug['id']}"
    return Vuln(
        id=f"MOZ-CA-{bug['id']}",
        title=bug.get("summary", ""),
        description=f"Mozilla CA Program に報告された認証局事案（{bug.get('component', '')}、状態 {bug.get('status', '')}）。"
                    f"分類: {bug.get('whiteboard', '')}",
        published=bug.get("creation_time", ""),
        updated=bug.get("last_change_time", "") or bug.get("creation_time", ""),
        references=[url],
        sources=["mozilla-ca"],
        category="pki",
        matched=["pki"],
        match_type="pki",
        score=score,
        level=level,
    )


def fetch(fetcher, since: datetime) -> list:
    params = [("product", "CA Program")] + [("component", c) for c in COMPONENTS] + [
        ("creation_time", since.strftime("%Y-%m-%dT%H:%M:%SZ")),
        ("include_fields", "id,summary,creation_time,last_change_time,status,whiteboard,component"),
        ("limit", "200"),
    ]
    data = fetcher.get_json("mozilla_ca", URL, params=params)
    return [parse(b) for b in data.get("bugs", [])]
