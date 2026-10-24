"""LINE Messaging API で緊急案件をプッシュ通知する（LINE Notify は 2025-03 に終了済み）。"""
PUSH_URL = "https://api.line.me/v2/bot/message/push"
MAX_ITEMS = 5
MAX_CHARS = 5000
MAX_BUBBLES = 5  # 1 回の push に入れられる吹き出しの上限（何個でも 1 通と数えられる）


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


def build_messages(vulns: list, dashboard_url: str = "") -> list:
    """一覧の吹き出しに続けて、AI 分析がある案件ごとに吹き出しを 1 つずつ足す。"""
    texts = [format_message(vulns, dashboard_url)]
    for v in vulns:
        if v.ai_analysis and len(texts) < MAX_BUBBLES:
            texts.append(f"🤖 {v.id}\n\n{v.ai_analysis}"[:MAX_CHARS])
    return texts


def send(fetcher, texts: list, token: str, to: str) -> None:
    messages = [{"type": "text", "text": t} for t in texts[:MAX_BUBBLES]]
    fetcher.post_json(PUSH_URL, {"to": to, "messages": messages},
                      headers={"Authorization": f"Bearer {token}"})
