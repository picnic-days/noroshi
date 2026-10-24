import json
import re
from fnmatch import fnmatchcase
from pathlib import Path


def _compile(pattern: str):
    # ".php" や "foo-nginx" のような部分一致を避けるため前後に境界を付ける
    return re.compile(rf"(?<![\w./-])(?:{pattern})(?![\w-])")


class Watchlist:
    def __init__(self, data: dict):
        self.entries = data["entries"]
        self.names = {e["id"]: e["name"] for e in self.entries}
        self.global_excludes = data.get("global_keyword_excludes", [])
        for e in self.entries:
            e["_kw"] = [_compile(k) for k in e.get("keywords", [])]
            e["_kev"] = [k.lower() for k in e.get("kev", [])]
            e["_pkg"] = [p.lower() for p in e.get("packages", [])]

    @classmethod
    def load(cls, path: Path) -> "Watchlist":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def _exact(self, e: dict, v) -> bool:
        if any(fnmatchcase(c, pat) for c in v.cpes for pat in e.get("cpe", [])):
            return True
        if any(p in e["_pkg"] for p in v.packages):
            return True
        vps = [vp.lower() for vp in v.vendor_products]
        return any(k in vp for k in e["_kev"] for vp in vps)

    def _keyword(self, e: dict, v) -> bool:
        text = v.text()
        if any(x in text for x in self.global_excludes):
            return False
        return any(p.search(text) for p in e["_kw"])

    def match(self, v) -> None:
        """v.matched / match_type / tier を設定する。どれにも一致しなければ matched は空。"""
        exact = [e for e in self.entries if self._exact(e, v)]
        # NVD の解析待ちで CPE が付いていない新着 CVE を拾うため、説明文のキーワードでも当てる
        hits, kind = (exact, "exact") if exact else (
            [e for e in self.entries if self._keyword(e, v)], "keyword")
        if hits:
            v.matched = [e["id"] for e in hits]
            v.match_type = kind
            v.tier = min(e["tier"] for e in hits)
        elif v.kev:
            v.matched, v.match_type, v.tier = [], "kev-only", None
        else:
            v.matched, v.match_type, v.tier = [], "", None
