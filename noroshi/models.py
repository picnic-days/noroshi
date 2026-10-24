from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class Vuln:
    id: str  # CVE ID（無ければ GHSA ID）
    aliases: list = field(default_factory=list)
    title: str = ""
    description: str = ""
    published: str = ""
    updated: str = ""
    cvss: Optional[float] = None
    cvss_vector: str = ""
    severity: str = ""
    cpes: list = field(default_factory=list)  # "vendor:product"
    packages: list = field(default_factory=list)  # "ecosystem:name"
    vendor_products: list = field(default_factory=list)  # KEV の vendorProject + product
    references: list = field(default_factory=list)
    exploit_ref: bool = False
    kev: bool = False
    kev_date_added: str = ""
    ransomware: bool = False
    ssvc_exploitation: str = ""  # CISA ADP の SSVC: active / poc / none
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    x_mentions: Optional[int] = None
    sources: list = field(default_factory=list)
    category: str = "vuln"  # "vuln" / "pki" / "outage" / "malware" / "jp-alert"
    resolved_at: str = ""  # 障害の復旧時刻（outage のみ）
    first_seen: str = ""  # 狼煙が初めて記録した時刻（日次まとめの新着判定に使う）
    # マッチング・スコアリング結果
    matched: list = field(default_factory=list)
    match_type: str = ""  # "exact" / "keyword" / "kev-only"
    tier: Optional[int] = None
    score: float = 0.0
    level: str = ""
    score_breakdown: dict = field(default_factory=dict)
    ai_analysis: str = ""  # Claude による「状況」と「対応策」

    def merge(self, other: "Vuln") -> None:
        """同一脆弱性の別ソース情報を取り込む。"""
        for name in ("aliases", "cpes", "packages", "vendor_products", "references", "sources"):
            mine = getattr(self, name)
            for v in getattr(other, name):
                if v not in mine:
                    mine.append(v)
        for name in ("title", "description", "published", "cvss_vector", "severity", "kev_date_added"):
            if not getattr(self, name) and getattr(other, name):
                setattr(self, name, getattr(other, name))
        if other.updated > self.updated:
            self.updated = other.updated
        if other.cvss is not None and (self.cvss is None or other.cvss > self.cvss):
            self.cvss = other.cvss
            self.cvss_vector = other.cvss_vector or self.cvss_vector
        self.exploit_ref = self.exploit_ref or other.exploit_ref
        self.kev = self.kev or other.kev
        self.ransomware = self.ransomware or other.ransomware
        self.ssvc_exploitation = self.ssvc_exploitation or other.ssvc_exploitation

    def text(self) -> str:
        return "\n".join([self.title, self.description] + self.vendor_products)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Vuln":
        known = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in d.items() if k in known})
