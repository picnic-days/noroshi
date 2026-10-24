"""X（旧Twitter）上の言及件数で CVE を補強する。

投稿本文は取らず、件数だけを返す counts エンドポイントを使う。
従量課金のため、監視リストに一致した候補の上位だけを問い合わせる。
"""
URL = "https://api.x.com/2/tweets/counts/recent"
MAX_QUERIES = 20


def enrich(fetcher, vulns: list, bearer_token: str = "") -> None:
    if not bearer_token and not fetcher.is_mock:
        return
    headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else None
    targets = [v for v in vulns if v.id.startswith("CVE-")]
    targets.sort(key=lambda v: v.score, reverse=True)
    for v in targets[:MAX_QUERIES]:
        data = fetcher.get_json("x_counts", URL, params={
            "query": f'"{v.id}" -is:retweet',
            "granularity": "day",
        }, headers=headers, mock_key=v.id)
        if data:
            v.x_mentions = int(data.get("meta", {}).get("total_tweet_count", 0))
