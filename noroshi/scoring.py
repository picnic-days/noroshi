"""利用規模 × 深刻度 × 悪用状況 × X 上の言及量で 0〜100 のスコアを付ける。"""
import math
import re

TIER_POINTS = {1: 30, 2: 20, 3: 10}
KEV_ONLY_POINTS = 10  # 監視リスト外でも KEV 掲載は無視しない
KEYWORD_FACTOR = 0.7  # キーワード一致は誤検知があり得るので割り引く

RCE_RE = re.compile(r"remote code execution|execute arbitrary (?:code|commands)|\bRCE\b", re.I)
UNAUTH_RE = re.compile(r"unauthenticated|without authentication|pre-auth", re.I)

LEVELS = [(70, "critical"), (50, "high"), (30, "medium"), (0, "low")]


def _unauth_network(v) -> bool:
    vec = v.cvss_vector
    if vec and "AV:N" in vec and "PR:N" in vec:
        return True
    return bool(UNAUTH_RE.search(v.text()))


def score(v) -> None:
    b = {}
    if v.tier:
        b["popularity"] = TIER_POINTS.get(v.tier, 10) * (KEYWORD_FACTOR if v.match_type == "keyword" else 1)
    elif v.match_type == "kev-only":
        b["popularity"] = KEV_ONLY_POINTS

    if v.cvss is not None:
        b["cvss"] = v.cvss * 2
    unauth, rce = _unauth_network(v), bool(RCE_RE.search(v.text()))
    if unauth:
        b["unauth_network"] = 5
    if rce:
        b["rce"] = 5
    # 社会インフラ級の未認証 RCE は、KEV や X の反応を待たずに即時通知へ乗せる
    if v.tier == 1 and v.match_type == "exact" and unauth and rce and (v.cvss or 0) >= 9.0:
        b["tier1_critical"] = 15

    if v.kev:
        b["kev"] = 20
    if v.ransomware:
        b["ransomware"] = 5
    if v.exploit_ref:
        b["exploit_ref"] = 5
    if v.epss:
        b["epss"] = v.epss * 15

    if v.x_mentions:
        b["x_buzz"] = min(15, 5 * math.log10(1 + v.x_mentions))

    v.score_breakdown = {k: round(val, 1) for k, val in b.items()}
    v.score = round(min(100, sum(b.values())), 1)
    v.level = next(name for th, name in LEVELS if v.score >= th)
