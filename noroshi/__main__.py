"""収集 → 照合 → スコアリング → 保存 → LINE 通知 を 1 回実行する。

既定はドライラン（LINE には送らず標準出力に表示）。実送信は --send を付ける。
"""
import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import ai, digest, notify_line, scoring
from .http import Fetcher
from .matcher import Watchlist
from .sources import ai_vendors, cvelist, eol, epss, ghsa, jp_alerts, kev, malware, nvd, pki, status, x_buzz
from .store import Store

ROOT = Path(__file__).resolve().parent.parent
MOCK_NOW = datetime(2026, 10, 24, 6, 0, tzinfo=timezone.utc)
DEFAULT_LOOKBACK = timedelta(hours=24)
MAX_LOOKBACK = timedelta(days=7)
FRESH_DAYS = 30  # これより古く公開された CVE は NVD の再解析で更新されても候補にしない
# 配信側のキャッシュや登録の遅れで取りこぼさないよう、取得範囲を前回実行より少しさかのぼらせる。
# 重複して拾ったものは統合され、通知済みの判定で二重通知もしない
FETCH_OVERLAP = timedelta(minutes=30)
OUTAGE_WATCH_DAYS = 7  # 復旧を確認できないまま、これ以上経った障害は追跡をやめる
REPO_ADVISORY_INTERVAL = timedelta(hours=1)  # リポジトリごとに API を呼ぶので 1 時間に 1 回に抑える


def load_config(name: str) -> dict:
    return json.loads((ROOT / "config" / name).read_text(encoding="utf-8"))


def collect(fetcher, since, now, extra=()) -> list:
    kev_all = kev.load(fetcher)
    merged = {}

    def add(v):
        if v.id in merged:
            merged[v.id].merge(v)
        else:
            merged[v.id] = v

    fresh = (now - timedelta(days=FRESH_DAYS)).date().isoformat()
    from_cve = cvelist.fetch(fetcher, since, now)
    from_nvd = nvd.fetch(fetcher, since, now, os.environ.get("NVD_API_KEY", ""))
    from_ghsa = ghsa.fetch(fetcher, since, os.environ.get("GITHUB_TOKEN", ""))
    print(f"fetched cve.org={len(from_cve)} nvd={len(from_nvd)} ghsa={len(from_ghsa)} kev={len(kev_all)}")
    for v in from_cve:
        add(v)
    for v in from_nvd + from_ghsa:
        if v.published[:10] >= fresh:
            add(v)
    for v in extra:
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

    fetch_since = since - FETCH_OVERLAP
    ai_config = load_config("ai.json")
    from_repos = []
    checked = store.state.get("repo_adv_checked")
    if mock or not checked or now - datetime.fromisoformat(checked) >= REPO_ADVISORY_INTERVAL:
        repo_since = datetime.fromisoformat(checked) - FETCH_OVERLAP if checked and not mock else now - DEFAULT_LOOKBACK
        from_repos = ai_vendors.repo_advisories(fetcher, ai_config["repos"], repo_since, os.environ.get("GITHUB_TOKEN", ""))
        store.state["repo_adv_checked"] = now.isoformat()
        print(f"fetched repo-advisory={len(from_repos)}")
    vulns = collect(fetcher, fetch_since, now, from_repos)
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
    # CVE 以外の事案は照合・スコアリングを通さず、各ソースの分類だけで重要度を決める
    open_outages = store.state.setdefault("open_outages", {})
    from_pki = pki.fetch(fetcher, fetch_since)
    from_status, snapshot_ok = status.fetch(fetcher, fetch_since, set(open_outages), load_config("status.json")["providers"])
    from_malware = malware.fetch(fetcher, fetch_since, os.environ.get("GITHUB_TOKEN", ""))
    known = set(store.state["notified"]) | {v.id for v in vulns if v.level == "critical"}
    from_jp = jp_alerts.fetch(fetcher, fetch_since, known)
    from_ai = ai_vendors.news(fetcher, ai_config["feeds"], fetch_since, now, store.state)
    print(f"fetched mozilla-ca={len(from_pki)} status={len(from_status)} malware={len(from_malware)} "
          f"jp-alert={len(from_jp)} ai-news={len(from_ai)}")
    vulns += from_pki + from_status + from_malware + from_jp + from_ai
    vulns.sort(key=lambda v: v.score, reverse=True)

    alerts = store.unnotified([v for v in vulns if v.level == "critical"])
    print(f"since={since.isoformat()} candidates={len(vulns)} critical_new={len(alerts)}")
    for v in vulns:
        print(f"  {v.level:8} {v.score:5.1f}  {v.id:18} tier={v.tier} {v.match_type:8} {','.join(v.matched)}")

    use_ai = not args.no_ai and not mock
    warnings = key_warnings(store, now) if use_ai else []
    if alerts:
        warning = ai.analyze_all(alerts, vulns) if use_ai else ""
        if warning and warning not in warnings:
            warnings.append(warning)
        texts = notify_line.build_messages(alerts)
        # 警告は吹き出しの空きがあれば同じ通知に添え、なければ別に送る
        while warnings and len(texts) < notify_line.MAX_BUBBLES:
            texts.append(warnings.pop(0))
        push(args, fetcher, texts)
        if args.send:
            store.mark_notified(alerts, now)
            for v in alerts:
                if v.category == "outage":
                    open_outages[v.id] = {"title": v.title, "provider": v.matched[0], "since": now.isoformat(),
                                          "url": v.url}
    if warnings:
        push(args, fetcher, warnings)

    done = status.recovered(open_outages, from_status, snapshot_ok)
    if done:
        push(args, fetcher, ["\n\n".join(f"✅ 復旧: {open_outages[i]['title']}\n{open_outages[i].get('url', '')}".rstrip()
                                         for i in done)])
        if args.send:
            for i in done:
                del open_outages[i]
    stale = (now - timedelta(days=OUTAGE_WATCH_DAYS)).isoformat()
    for i in [i for i, o in open_outages.items() if o["since"] < stale]:
        del open_outages[i]

    items = store.save(vulns, now)
    if digest.due(store.state, now):
        since_digest = store.state.get("digest_since") or (now - timedelta(days=1)).isoformat()
        eol_lines = eol.upcoming(fetcher, load_config("eol.json")["products"],
                                 now.astimezone(digest.JST).date(), store.state.setdefault("eol_notified", {}))
        summary = ai.summarize_digest(digest.fresh_items(items, since_digest)) if use_ai else ""
        push(args, fetcher, [digest.build(items, since_digest, now, watchlist.names, eol_lines, summary)])
        store.state["digest_sent"] = now.astimezone(digest.JST).date().isoformat()
        store.state["digest_since"] = now.isoformat()
        store.save_state()
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
