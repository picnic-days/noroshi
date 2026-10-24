"""LINE Messaging API で緊急案件をプッシュ通知する（LINE Notify は 2025-03 に終了済み）。"""
PUSH_URL = "https://api.line.me/v2/bot/message/push"
MAX_ITEMS = 5
MAX_CHARS = 5000


def summary(v, limit: int = 100) -> str:
    """タイトルが無ければ説明文の最初の 1 文を使い、長ければ省略記号で切る。"""
    text = v.title or v.description.split(". ")[0].strip()
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def format_message(vulns: list, dashboard_url: str = "") -> str:
    lines = [f"🚨 脆弱性アラート {len(vulns)}件"]
    for v in vulns[:MAX_ITEMS]:
        tags = []
        if v.kev:
            tags.append("KEV")
        if v.ransomware:
            tags.append("ランサム")
        if v.exploit_ref:
            tags.append("PoC")
        if v.x_mentions:
            tags.append(f"X {v.x_mentions}件")
        title = summary(v)
        lines += [
            "",
            f"■ {v.id}  score {v.score:g}",
            f"対象: {', '.join(v.matched) or '監視リスト外(KEV)'}",
            f"CVSS: {v.cvss if v.cvss is not None else '未評価'}  {' / '.join(tags)}".rstrip(),
            title,
            v.references[0] if v.references else "",
        ]
    if len(vulns) > MAX_ITEMS:
        lines.append(f"\nほか {len(vulns) - MAX_ITEMS}件")
    if dashboard_url:
        lines.append(f"\nダッシュボード: {dashboard_url}")
    return "\n".join(l for l in lines if l is not None)[:MAX_CHARS]


def send(fetcher, text: str, token: str, to: str) -> None:
    fetcher.post_json(PUSH_URL, {"to": to, "messages": [{"type": "text", "text": text}]},
                      headers={"Authorization": f"Bearer {token}"})
