"""クラウド・SaaS の大規模障害。各社の公式ステータスページを見る。

statuspage / gcp は解決済みの障害も一覧に残るので resolved_at で復旧を判定する。
aws / rss / slack は「いま起きている障害」だけを返すので、一覧から消えたら復旧とみなす。
"""
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from ..models import Vuln

LEVEL_SCORE = {"critical": 90.0, "medium": 40.0, "low": 10.0}
SNAPSHOT_TYPES = {"aws", "rss", "slack"}
STATUSPAGE_LEVEL = {"critical": "critical", "major": "critical", "minor": "medium"}
GCP_LEVEL = {"high": "critical", "medium": "medium", "low": "low"}
SLACK_LEVEL = {"outage": "critical", "incident": "medium", "notice": "low"}
AWS_LEVEL = {"3": "critical", "2": "medium"}  # 3: 障害 / 2: 性能低下 / それ以外: 情報


def _item(provider, incident_id, title, level, started, url, resolved_at=""):
    if resolved_at and level == "critical":
        level = "medium"  # 初めて見た時点で解決済みの短い障害は即時通知しない
    return Vuln(
        id=f"OUT-{provider['id']}-{incident_id}",
        title=f"{provider['name']}: {title}",
        description=f"{provider['name']} の公式ステータスページに掲載された障害",
        published=started,
        updated=resolved_at or started,
        references=[url],
        sources=[f"status:{provider['id']}"],
        category="outage",
        matched=[provider["id"]],
        match_type="status",
        score=LEVEL_SCORE[level],
        level=level,
        resolved_at=resolved_at,
    )


def _statuspage(fetcher, p):
    data = fetcher.get_json(f"status_{p['id']}", f"{p['url']}/api/v2/incidents.json")
    for inc in data.get("incidents", []):
        level = STATUSPAGE_LEVEL.get(inc.get("impact"))
        if level:
            yield _item(p, inc["id"], inc["name"], level, inc["created_at"], inc.get("shortlink") or p["url"],
                        inc.get("resolved_at") or "")


def _gcp(fetcher, p):
    for inc in fetcher.get_json(f"status_{p['id']}", p["url"]):
        level = GCP_LEVEL.get(inc.get("severity"), "low")
        yield _item(p, inc["id"], inc.get("external_desc", "").split("\n")[0][:120], level, inc["begin"],
                    p["page"] + inc.get("uri", ""), inc.get("end") or "")


def _aws(fetcher, p):
    for ev in fetcher.get_json(f"status_{p['id']}", p["url"]) or []:
        level = AWS_LEVEL.get(str(ev.get("status")), "low")
        started = datetime.fromtimestamp(int(ev["date"]), timezone.utc).isoformat()
        event_id = re.sub(r"[^\w-]", "_", ev["arn"].rsplit("/", 1)[-1])[-60:]
        title = f'{ev.get("service_name", "")}（{ev.get("region_name", "")}）{ev.get("summary", "")}'
        yield _item(p, event_id, title, level, started, p["page"])


def _rss(fetcher, p):
    root = ET.fromstring(fetcher.get_text(f"status_{p['id']}", p["url"]))
    for it in root.iter("item"):
        guid = it.findtext("guid") or it.findtext("link") or it.findtext("title")
        started = parsedate_to_datetime(it.findtext("pubDate")).isoformat() if it.findtext("pubDate") else ""
        yield _item(p, re.sub(r"\W", "_", guid)[-60:], it.findtext("title", ""), "critical", started,
                    it.findtext("link") or p["page"])


def _slack(fetcher, p):
    for inc in fetcher.get_json(f"status_{p['id']}", p["url"]).get("active_incidents", []):
        level = SLACK_LEVEL.get(inc.get("type"), "low")
        yield _item(p, inc["id"], inc.get("title", ""), level, inc.get("date_created", ""), inc.get("url") or p["page"])


PARSERS = {"statuspage": _statuspage, "gcp": _gcp, "aws": _aws, "rss": _rss, "slack": _slack}


def _parse_time(s: str):
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def fetch(fetcher, since: datetime, watch: set, providers: list) -> tuple:
    """(障害のリスト, 取得に成功したスナップショット型プロバイダ ID の集合) を返す。

    since 以降に始まった障害と、通知済みで復旧待ちの障害（watch）だけを返す。
    """
    items, snapshot_ok = [], set()
    for p in providers:
        if fetcher.is_mock and not fetcher.has_mock(f"status_{p['id']}"):
            continue
        try:
            found = list(PARSERS[p["type"]](fetcher, p))
        except Exception as e:  # 1 社の取得失敗で全体を止めない
            print(f"status: {p['name']} の取得に失敗 ({e})")
            continue
        if p["type"] in SNAPSHOT_TYPES:
            snapshot_ok.add(p["id"])
        for v in found:
            started = _parse_time(v.published)
            if v.id in watch or (started and started >= since):
                items.append(v)
    return items, snapshot_ok


def recovered(open_outages: dict, items: list, snapshot_ok: set) -> list:
    """通知済みの障害のうち、復旧したものの ID を返す。"""
    by_id = {v.id: v for v in items}
    done = []
    for oid, info in open_outages.items():
        v = by_id.get(oid)
        if (v is not None and v.resolved_at) or (v is None and info.get("provider") in snapshot_ok):
            done.append(oid)
    return done
