"""AI 企業・AI ツールのセキュリティ情報。

- 各社の GitHub リポジトリのセキュリティアドバイザリ: グローバルのデータベースに載る前に拾う。
  中身は脆弱性なので、監視リストとの照合とスコアリングを通常どおり通す。
- 各社の発表（ブログ・ニュース）: セキュリティに関係する発表だけを残し、インシデントは即時通知する。
"""
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from ..models import Vuln
from . import ghsa

REPO_URL = "https://api.github.com/repos/{}/security-advisories"
ATOM = {"a": "http://www.w3.org/2005/Atom"}
SITEMAP = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}

# 利用者側で対応が必要になりうる発表は即時通知する
INCIDENT_RE = re.compile(r"incident|breach|compromis|unauthori[sz]ed access|data exposure|leak|vulnerab|advisory", re.I)
# それ以外でセキュリティに関係する発表は日次まとめに載せる
SECURITY_RE = re.compile(r"security|threat|misuse|malicious|abuse|exploit|cyber|attack|prompt.injection|safeguard", re.I)


def repo_advisories(fetcher, repos: list, since: datetime, token: str = "") -> list:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    items = []
    if fetcher.is_mock and not fetcher.has_mock("repo_advisories"):
        return items
    for repo in repos:
        try:
            advs = fetcher.get_json("repo_advisories", REPO_URL.format(repo), params={
                "state": "published", "sort": "published", "direction": "desc", "per_page": 10,
            }, headers=headers, mock_key=repo) or []
        except Exception as e:
            print(f"ai: {repo} のアドバイザリ取得に失敗 ({e})")
            continue
        for adv in advs:
            if (adv.get("published_at") or "") < since.strftime("%Y-%m-%dT%H:%M:%SZ"):
                continue
            v = ghsa.parse(adv)
            v.vendor_products = [repo]  # 監視リストの kev パターン（"anthropic" など）で照合させる
            v.sources = ["repo-advisory"]
            items.append(v)
    return items


def _item(feed, slug, title, published, url, level):
    safe_slug = re.sub(r"[^\w-]", "_", slug)[-60:]
    return Vuln(
        id=f"AI-{feed['id']}-{safe_slug}",
        title=f"{feed['name']}: {title}",
        description=f"{feed['name']} のセキュリティ関連の発表",
        published=published,
        updated=published,
        references=[url],
        sources=[f"ai:{feed['id']}"],
        category="ai-news",
        matched=[feed["id"]],
        match_type="ai-news",
        score=90.0 if level == "critical" else 40.0,
        level=level,
    )


def _level(text: str, relevant: bool):
    if INCIDENT_RE.search(text):
        return "critical"
    if relevant or SECURITY_RE.search(text):
        return "medium"
    return None


def _rss(feed, xml_text, since):
    for it in ET.fromstring(xml_text).iter("item"):
        title, link = it.findtext("title", ""), it.findtext("link", "")
        if feed.get("category"):
            categories = [c.text for c in it.findall("category")]
            if feed["category"] not in categories:
                continue
        try:
            published = parsedate_to_datetime(it.findtext("pubDate"))
        except (TypeError, ValueError):
            continue
        if published < since:
            continue
        # カテゴリで絞った場合は全件がセキュリティ関連。キーワードで絞る場合は一致したものだけ
        level = _level(title, relevant=bool(feed.get("category")) or not feed.get("keyword_filter"))
        if level:
            yield _item(feed, link.rstrip("/").rsplit("/", 1)[-1], title, published.isoformat(), link, level)


def _atom(feed, xml_text, since):
    for e in ET.fromstring(xml_text).findall("a:entry", ATOM):
        title = e.findtext("a:title", "", ATOM)
        link = next((l.get("href") for l in e.findall("a:link", ATOM) if l.get("rel") == "alternate"), "")
        published = datetime.fromisoformat(e.findtext("a:published", "", ATOM))
        if published < since:
            continue
        level = _level(title, relevant=True)  # セキュリティ専門のブログなので全件を対象にする
        yield _item(feed, link.rstrip("/").rsplit("/", 1)[-1].split(".")[0], title, published.isoformat(), link, level)


def _sitemap(feed, xml_text, now, known: list):
    """RSS の無いサイトは、サイトマップに新しく現れた URL を新着とみなす。初回は記録だけする。"""
    urls = [u.findtext("s:loc", "", SITEMAP) for u in ET.fromstring(xml_text).findall("s:url", SITEMAP)]
    first_run = not known
    seen = set(known)
    for url in urls:
        if url in seen:
            continue
        known.append(url)
        if first_run:
            continue
        slug = url.rstrip("/").rsplit("/", 1)[-1]
        words = slug.replace("-", " ")
        level = _level(words, relevant=False)
        if level:
            yield _item(feed, slug, words, now.isoformat(), url, level)


def news(fetcher, feeds: list, since: datetime, now: datetime, state: dict) -> list:
    items = []
    for feed in feeds:
        name = f"ai_{feed['id']}"
        if fetcher.is_mock and not fetcher.has_mock(name, "xml"):
            continue
        try:
            text = fetcher.get_text(name, feed["url"], "xml")
            if feed["type"] == "rss":
                items += list(_rss(feed, text, since))
            elif feed["type"] == "atom":
                items += list(_atom(feed, text, since))
            elif feed["type"] == "sitemap":
                known = state.setdefault("sitemap_urls", {}).setdefault(feed["id"], [])
                items += list(_sitemap(feed, text, now, known))
        except Exception as e:
            print(f"ai: {feed['name']} の取得に失敗 ({e})")
    return items
