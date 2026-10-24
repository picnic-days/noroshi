import gzip
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

USER_AGENT = "noroshi/0.1"


def _body(res) -> str:
    """応答本文を文字列にする。頼んでいなくても gzip で返すサーバがあるので展開する。"""
    raw = res.read()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    # AWS のステータスは UTF-16 で返るので、応答ヘッダーの文字コードに従う
    return raw.decode(res.headers.get_content_charset() or "utf-8")


class Fetcher:
    """HTTP 取得の窓口。mock_dir を指定するとネットワークに出ず fixtures/<name>.json を返す。"""

    def __init__(self, mock_dir: Optional[Path] = None, timeout: int = 30):
        self.mock_dir = Path(mock_dir) if mock_dir else None
        self.timeout = timeout

    @property
    def is_mock(self) -> bool:
        return self.mock_dir is not None

    def has_mock(self, name: str, ext: str = "json") -> bool:
        return bool(self.mock_dir) and (self.mock_dir / f"{name}.{ext}").exists()

    def get_json(self, name: str, url: str, params: Optional[dict] = None,
                 headers: Optional[dict] = None, mock_key: Optional[str] = None):
        if self.mock_dir:
            path = self.mock_dir / f"{name}.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            # 呼び出しごとに応答が変わるもの（X の件数など）は fixture をキーで引く
            return data.get(mock_key) if mock_key is not None else data
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
        with urllib.request.urlopen(req, timeout=self.timeout) as res:
            return json.loads(_body(res))

    def get_text(self, name: str, url: str, ext: str = "xml") -> str:
        if self.mock_dir:
            return (self.mock_dir / f"{name}.{ext}").read_text(encoding="utf-8")
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=self.timeout) as res:
            return _body(res)

    def get_text_range(self, name: str, url: str, nbytes: int) -> str:
        """先頭 nbytes だけ取得する。mock では fixtures/<name>.json を丸ごと返す。"""
        if self.mock_dir:
            return (self.mock_dir / f"{name}.json").read_text(encoding="utf-8")
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Range": f"bytes=0-{nbytes - 1}"})
        with urllib.request.urlopen(req, timeout=self.timeout) as res:
            # 途中で切れたマルチバイト文字は捨てる
            return res.read().decode("utf-8", "ignore")

    def post_json(self, url: str, body: dict, headers: Optional[dict] = None):
        if self.mock_dir:
            raise RuntimeError("mock モードでは POST しない")
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/json", **(headers or {})},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                raw = res.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            # API が返すエラー理由を残す（認証失敗や宛先誤りの切り分け用）
            raise RuntimeError(f"HTTP {e.code} {url}: {e.read().decode('utf-8', 'replace')}") from None
