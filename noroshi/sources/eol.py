"""サポート終了（EOL）の予告。endoflife.date から取得し、90・30・7 日前と当日に 1 回ずつ知らせる。"""
from datetime import date

URL = "https://endoflife.date/api/v1/products/{}"
PAGE = "https://endoflife.date/{}"
THRESHOLDS = (0, 7, 30, 90)
STALE_DAYS = 7  # これより前に終了したものは、初回実行でも知らせない


def bucket(days: int):
    """残り日数が属する閾値。範囲外なら None。"""
    if days < -STALE_DAYS or days > THRESHOLDS[-1]:
        return None
    return next(t for t in THRESHOLDS if days <= t)


def upcoming(fetcher, products: list, today: date, notified: dict) -> list:
    """まだ知らせていない予告文の一覧を返し、notified に記録する。製品ごとに endoflife.date のページを添える。"""
    lines = []
    for p in products:
        try:
            releases = fetcher.get_json("eol", URL.format(p["id"]), mock_key=p["id"])
        except Exception as e:
            print(f"eol: {p['name']} の取得に失敗 ({e})")
            continue
        for r in ((releases or {}).get("result") or {}).get("releases", []):
            eol = r.get("eolFrom")
            if not isinstance(eol, str):
                continue
            days = (date.fromisoformat(eol) - today).days
            t = bucket(days)
            key = f"{p['id']}:{r['name']}:{t}"
            if t is None or key in notified:
                continue
            notified[key] = today.isoformat()
            when = f"あと{days}日" if days > 0 else ("本日" if days == 0 else "終了済み")
            lines.append((days, p["id"], f"・{p['name']} {r['name']}: {eol} にサポート終了（{when}）"))
    out, linked = [], set()
    ordered = sorted(lines)
    for i, (_, pid, text) in enumerate(ordered):
        out.append(text)
        # 同じ製品が続く場合は、最後の行の後にだけページを付ける
        if pid not in linked and all(pid != later for _, later, _ in ordered[i + 1:]):
            out.append(f"  {PAGE.format(pid)}")
            linked.add(pid)
    return out
