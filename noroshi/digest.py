"""1 日 1 回、即時通知に届かなかった中〜高の案件を製品ごとにまとめる。"""
from collections import defaultdict
from datetime import datetime, timedelta, timezone

JST = timezone(timedelta(hours=9))
SEND_HOUR_JST = 9
LEVELS = ("critical", "high", "medium")
MAX_GROUPS = 15
MAX_CHARS = 5000


def due(state: dict, now: datetime) -> bool:
    local = now.astimezone(JST)
    return local.hour >= SEND_HOUR_JST and state.get("digest_sent") != local.date().isoformat()


def build(items: list, since: str, now: datetime, names: dict) -> str:
    """since 以降に初めて見つかった案件を、製品ごとに件数と代表例でまとめる。"""
    fresh = [v for v in items if v.first_seen > since and v.level in LEVELS]
    counts = {lv: sum(1 for v in fresh if v.level == lv) for lv in LEVELS}
    local = now.astimezone(JST)
    lines = [f"📋 狼煙 日次まとめ（{local.month}/{local.day}）",
             f"新着: critical {counts['critical']} / high {counts['high']} / medium {counts['medium']}"]
    if not fresh:
        return "\n".join(lines + ["", "目立った新着はありません。"])

    groups = defaultdict(list)
    for v in fresh:
        key = "pki" if v.category == "pki" else (v.matched[0] if v.matched else "kev")
        groups[key].append(v)
    ordered = sorted(groups.items(), key=lambda kv: max(v.score for v in kv[1]), reverse=True)
    for key, vs in ordered[:MAX_GROUPS]:
        vs.sort(key=lambda v: v.score, reverse=True)
        label = {"pki": "認証局（CA）事案", "kev": "監視リスト外（KEV 掲載）"}.get(key, names.get(key, key))
        by_level = " / ".join(f"{lv} {n}" for lv in LEVELS if (n := sum(1 for v in vs if v.level == lv)))
        top = vs[0]
        lines += ["", f"■ {label}  {by_level}（最高 {top.score:g}）",
                  f"  {top.id} {(top.title or top.description.split('. ')[0])[:70]}"]
        if len(vs) > 1:
            lines.append(f"  ほか {len(vs) - 1}件")
    if len(ordered) > MAX_GROUPS:
        lines.append(f"\nほか {len(ordered) - MAX_GROUPS} 製品")
    return "\n".join(lines)[:MAX_CHARS]
