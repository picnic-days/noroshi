"""1 日 1 回、即時通知に届かなかった中〜高の案件を製品ごとにまとめる。"""
from collections import defaultdict
from datetime import datetime, timedelta, timezone

JST = timezone(timedelta(hours=9))
SEND_HOUR_JST = 9
LEVELS = ("critical", "high", "medium")
MAX_GROUPS = 15
ITEMS_PER_GROUP = 3  # 製品ごとに URL 付きで載せる件数
MAX_CHARS = 5000
CHAR_BUDGET = 4700  # URL の途中で切れないよう、上限より手前で製品の追加をやめる


def due(state: dict, now: datetime) -> bool:
    local = now.astimezone(JST)
    return local.hour >= SEND_HOUR_JST and state.get("digest_sent") != local.date().isoformat()


GROUP_LABELS = {
    "pki": "認証局（CA）事案",
    "outage": "クラウド・SaaS 障害",
    "malware": "悪性パッケージ",
    "jp-alert": "国内の注意喚起",
    "ai-news": "AI 企業のセキュリティ発表",
    "kev": "監視リスト外（KEV 掲載）",
}
MAX_EOL_LINES = 30  # 製品ページの URL 行を含む


def fresh_items(items: list, since: str) -> list:
    """since 以降に初めて見つかった、日次まとめに載せる案件。"""
    return [v for v in items if v.first_seen > since and v.level in LEVELS]


def build(items: list, since: str, now: datetime, names: dict, eol_lines: list = (), summary: str = "") -> str:
    """since 以降に初めて見つかった案件を、製品ごとに件数と代表例でまとめる。summary は AI の要点。"""
    fresh = fresh_items(items, since)
    counts = {lv: sum(1 for v in fresh if v.level == lv) for lv in LEVELS}
    local = now.astimezone(JST)
    lines = [f"📋 狼煙 日次まとめ（{local.month}/{local.day}）",
             f"新着: critical {counts['critical']} / high {counts['high']} / medium {counts['medium']}"]
    if summary:
        lines += ["", "🤖 今日の要点", summary]
    eol_part = []
    if eol_lines:
        eol_part = ["", "🗓 サポート終了の予告"] + list(eol_lines[:MAX_EOL_LINES])
        if len(eol_lines) > MAX_EOL_LINES:
            eol_part.append(f"ほか {len(eol_lines) - MAX_EOL_LINES}件")
    if not fresh:
        return "\n".join(lines + ["", "目立った新着はありません。"] + eol_part)[:MAX_CHARS]

    groups = defaultdict(list)
    for v in fresh:
        key = v.category if v.category != "vuln" else (v.matched[0] if v.matched else "kev")
        groups[key].append(v)
    ordered = sorted(groups.items(), key=lambda kv: max(v.score for v in kv[1]), reverse=True)
    budget = CHAR_BUDGET - len("\n".join(eol_part))
    shown = 0
    for key, vs in ordered[:MAX_GROUPS]:
        vs.sort(key=lambda v: v.score, reverse=True)
        label = GROUP_LABELS.get(key, names.get(key, key))
        by_level = " / ".join(f"{lv} {n}" for lv in LEVELS if (n := sum(1 for v in vs if v.level == lv)))
        block = ["", f"■ {label}  {by_level}（最高 {vs[0].score:g}）"]
        for v in vs[:ITEMS_PER_GROUP]:
            block.append(f"  {v.id} {(v.title or v.description.split('. ')[0])[:60]}")
            if v.url:
                block.append(f"  {v.url}")
        if len(vs) > ITEMS_PER_GROUP:
            block.append(f"  ほか {len(vs) - ITEMS_PER_GROUP}件")
        if len("\n".join(lines + block)) > budget:
            break
        lines += block
        shown += 1
    if len(ordered) > shown:
        lines.append(f"\nほか {len(ordered) - shown} 製品")
    return "\n".join(lines + eol_part)[:MAX_CHARS]
