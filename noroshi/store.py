"""ダッシュボード用の vulns.json と、通知済み管理の state.json を読み書きする。"""
import json
from datetime import datetime, timedelta
from pathlib import Path

from .models import Vuln

RETENTION_DAYS = 30


def _read(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


class Store:
    def __init__(self, data_dir: Path):
        self.vulns_path = Path(data_dir) / "vulns.json"
        self.state_path = Path(data_dir) / "state.json"
        self.state = _read(self.state_path, {"last_run": None, "notified": {}})

    def last_run(self):
        lr = self.state.get("last_run")
        return datetime.fromisoformat(lr) if lr else None

    def unnotified(self, vulns: list) -> list:
        return [v for v in vulns if v.id not in self.state["notified"]]

    def mark_notified(self, vulns: list, now: datetime) -> None:
        for v in vulns:
            self.state["notified"][v.id] = now.isoformat()

    def save(self, vulns: list, now: datetime) -> list:
        """既存データに今回分を上書きマージし、保持期間を過ぎたものを落として保存する。"""
        existing = {d["id"]: Vuln.from_dict(d) for d in _read(self.vulns_path, {"items": []})["items"]}
        for v in vulns:
            existing[v.id] = v
        cutoff = (now - timedelta(days=RETENTION_DAYS)).isoformat()
        # ソースごとに日付の形式が違うので日付部分だけで比較する
        items = [v for v in existing.values() if (v.updated or v.published)[:10] >= cutoff[:10]]
        items.sort(key=lambda v: v.score, reverse=True)
        _write(self.vulns_path, {"generated_at": now.isoformat(), "items": [v.to_dict() for v in items]})

        self.state["last_run"] = now.isoformat()
        self.state["notified"] = {k: t for k, t in self.state["notified"].items() if t >= cutoff}
        _write(self.state_path, self.state)
        return items
