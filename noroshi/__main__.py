"""収集 → 照合 → スコアリング → 保存 → LINE 通知 を 1 回実行する。

既定はドライラン（LINE には送らず標準出力に表示）。実送信は --send を付ける。
"""
import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import ai, notify_line, scoring
from .http import Fetcher
from .matcher import Watchlist
from .sources import epss, ghsa, kev, nvd, x_buzz
from .store import Store

ROOT = Path(__file__).resolve().parent.parent
MOCK_NOW = datetime(2026, 10, 24, 6, 0, tzinfo=timezone.utc)
DEFAULT_LOOKBACK = timedelta(hours=24)
MAX_LOOKBACK = timedelta(days=7)
FRESH_DAYS = 30  # これより古く公開された CVE は NVD の再解析で更新されても候補にしない


def collect(fetcher, since, now) -> list:
    kev_all = kev.load(fetcher)
    merged = {}

    def add(v):
        if v.id in merged:
            merged[v.id].merge(v)
        else:
            merged[v.id] = v

    fresh = (now - timedelta(days=FRESH_DAYS)).date().isoformat()
    for v in nvd.fetch(fetcher, since, now, os.environ.get("NVD_API_KEY", "")):
        if v.published[:10] >= fresh:
            add(v)
    for v in ghsa.fetch(fetcher, since, os.environ.get("GITHUB_TOKEN", "")):
        if v.published[:10] >= fresh:
            add(v)
    for cve, v in kev_all.items():
        if v.kev_date_added >= since.date().isoformat():
            add(v)  # KEV 新規掲載は公開日が古くても候補にする
        elif cve in merged:
            merged[cve].merge(v)
    return list(merged.values())


def key_warnings(store, now) -> list:
    """API キーの期限と有効性を 1 日 1 回だけ確認する。"""
    today = now.date()
    if store.state.get("ai_key_checked") == today.isoformat():
        return []
    store.state["ai_key_checked"] = today.isoformat()
    expires = os.environ.get("ANTHROPIC_KEY_EXPIRES", "")
    warnings = [ai.expiry_warning(expires, today)] if expires else []
    warnings.append(ai.check_key())
    return [w for w in warnings if w]


def push(args, fetcher, texts) -> None:
    if args.send:
        notify_line.send(fetcher, texts, os.environ["LINE_CHANNEL_ACCESS_TOKEN"], os.environ["LINE_TO"])
        print("LINE に送信しました")
    else:
        print("--- LINE メッセージ（ドライラン・未送信） ---")
        print("\n\n---\n\n".join(texts))


def run(args) -> int:
    mock = args.mock
    now = datetime.fromisoformat(args.now) if args.now else (MOCK_NOW if mock else datetime.now(timezone.utc))
    fetcher = Fetcher(mock_dir=ROOT / "fixtures" if mock else None)
    store = Store(Path(args.data_dir))
    watchlist = Watchlist.load(ROOT / "config" / "watchlist.json")

    last = store.last_run()
    since = max(last, now - MAX_LOOKBACK) if last and not mock else now - DEFAULT_LOOKBACK

    vulns = collect(fetcher, since, now)
    for v in vulns:
        watchlist.match(v)
    vulns = [v for v in vulns if v.matched or v.match_type == "kev-only"]

    epss.enrich(fetcher, vulns)
    for v in vulns:
        scoring.score(v)
    # X は従量課金なので、一次スコアの高い候補だけ件数を問い合わせて再計算する
    x_buzz.enrich(fetcher, vulns, os.environ.get("X_BEARER_TOKEN", ""))
    for v in vulns:
        scoring.score(v)
    vulns.sort(key=lambda v: v.score, reverse=True)

    alerts = store.unnotified([v for v in vulns if v.level == "critical"])
    print(f"since={since.isoformat()} candidates={len(vulns)} critical_new={len(alerts)}")
    for v in vulns:
        print(f"  {v.level:8} {v.score:5.1f}  {v.id:18} tier={v.tier} {v.match_type:8} {','.join(v.matched)}")

    use_ai = not args.no_ai and not mock
    warnings = key_warnings(store, now) if use_ai else []
    if alerts:
        warning = ai.analyze_all(alerts) if use_ai else ""
        if warning and warning not in warnings:
            warnings.append(warning)
        texts = notify_line.build_messages(alerts, os.environ.get("DASHBOARD_URL", ""))
        # 警告は吹き出しの空きがあれば同じ通知に添え、なければ別に送る
        while warnings and len(texts) < notify_line.MAX_BUBBLES:
            texts.append(warnings.pop(0))
        push(args, fetcher, texts)
        if args.send:
            store.mark_notified(alerts, now)
    if warnings:
        push(args, fetcher, warnings)

    store.save(vulns, now)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="noroshi")
    p.add_argument("--mock", action="store_true", help="fixtures/ を使いネットワークに出ない")
    p.add_argument("--send", action="store_true", help="LINE に実送信する（既定はドライラン）")
    p.add_argument("--now", help="現在時刻を上書き（ISO 8601）")
    p.add_argument("--data-dir", default=str(ROOT / "data"))
    p.add_argument("--no-ai", action="store_true", help="Claude による分析を行わない")
    p.add_argument("--ping", action="store_true", help="LINE にテストメッセージを 1 通送って終了する")
    args = p.parse_args(argv)
    if args.mock and (args.send or args.ping):
        p.error("--mock と --send / --ping は併用できない")
    if (args.send or args.ping) and not (os.environ.get("LINE_CHANNEL_ACCESS_TOKEN") and os.environ.get("LINE_TO")):
        p.error("--send / --ping には LINE_CHANNEL_ACCESS_TOKEN と LINE_TO が必要")
    if args.ping:
        notify_line.send(Fetcher(), ["🔥 狼煙: テスト通知です。この通知が届けば設定は完了です。"],
                         os.environ["LINE_CHANNEL_ACCESS_TOKEN"], os.environ["LINE_TO"])
        print("LINE にテスト通知を送信しました")
        return 0
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
