"""LINE Messaging API で緊急案件をプッシュ通知する（LINE Notify は 2025-03 に終了済み）。"""
PUSH_URL = "https://api.line.me/v2/bot/message/push"
MAX_ITEMS = 5
MAX_CHARS = 5000
CATEGORY_LABELS = {
    "pki": "認証局（CA）事案",
    "outage": "クラウド・SaaS 障害",
    "malware": "悪性パッケージ",
    "jp-alert": "国内の注意喚起",
    "ai-news": "AI 企業のセキュリティ発表",
}
MAX_BUBBLES = 5  # 1 回の push に入れられる吹き出しの上限（何個でも 1 通と数えられる）


def summary(v, limit: int = 100) -> str:
    """タイトルが無ければ説明文の最初の 1 文を使い、長ければ省略記号で切る。"""
    text = v.title or v.description.split(". ")[0].strip()
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def format_message(vulns: list) -> str:
    head = "脆弱性アラート" if all(v.category == "vuln" for v in vulns) else "狼煙アラート"
    lines = [f"🚨 {head} {len(vulns)}件"]
    for v in vulns[:MAX_ITEMS]:
        tags = []
        if v.kev:
            tags.append("KEV")
        if v.ssvc_exploitation == "active" and not v.kev:
            tags.append("悪用確認(CISA)")
        if v.ransomware:
            tags.append("ランサム")
        if v.exploit_ref:
            tags.append("PoC")
        if v.x_mentions:
            tags.append(f"X {v.x_mentions}件")
        title = summary(v)
        if v.category in CATEGORY_LABELS:
            kind = f"種別: {CATEGORY_LABELS[v.category]}"
        else:
            kind = f"CVSS: {v.cvss if v.cvss is not None else '未評価'}  {' / '.join(tags)}".rstrip()
        lines += [
            "",
            f"■ {v.id}  score {v.score:g}",
            f"対象: {', '.join(v.matched) or '監視リスト外(KEV)'}",
            kind,
            title,
            v.references[0] if v.references else "",
        ]
    if len(vulns) > MAX_ITEMS:
        lines.append(f"\nほか {len(vulns) - MAX_ITEMS}件")
    return "\n".join(l for l in lines if l is not None)[:MAX_CHARS]


def build_messages(vulns: list) -> list:
    """一覧の吹き出しに続けて、AI 分析ごとに吹き出しを 1 つずつ足す。同じ分析を共有する案件は 1 つにまとめる。"""
    texts = [format_message(vulns)]
    by_analysis = {}
    for v in vulns:
        if v.ai_analysis:
            by_analysis.setdefault(v.ai_analysis, []).append(v.id)
    for analysis, ids in by_analysis.items():
        if len(texts) >= MAX_BUBBLES:
            break
        texts.append(f"🤖 {' / '.join(ids)}\n\n{analysis}"[:MAX_CHARS])
    return texts


def send(fetcher, texts: list, token: str, to: str) -> None:
    messages = [{"type": "text", "text": t} for t in texts[:MAX_BUBBLES]]
    fetcher.post_json(PUSH_URL, {"to": to, "messages": messages},
                      headers={"Authorization": f"Bearer {token}"})
