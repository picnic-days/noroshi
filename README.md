# noroshi（狼煙）

広く使われているソフトウェアの脆弱性を一次情報（CVE.org / NVD / GitHub Security Advisories / CISA KEV / EPSS）と X の言及量から収集・スコアリングし、緊急案件を LINE に通知する。結果は `data/vulns.json` に出力し、ダッシュボードから読む。

緊急案件は Claude（Opus 5.5 + Web 検索）が一次情報を確認し、「状況」と「対応策」を日本語でまとめて LINE に添える。

収集・スコアリング部分は外部依存なし（Python 3.9+ 標準ライブラリのみ）。AI 分析には `anthropic` SDK（Python 3.10+）が必要。

## 使い方

```sh
python3 -m noroshi --mock            # fixtures/ を使ったドライラン（ネットワークに出ない）
python3 -m noroshi                   # 実データを取得、LINE には送らない
python3 -m noroshi --send            # 実データを取得し LINE に送信
python3 -m unittest discover -s tests  # テスト
```

## 環境変数

| 変数 | 用途 | 必須 |
|---|---|---|
| `LINE_CHANNEL_ACCESS_TOKEN` | LINE Messaging API のチャネルアクセストークン | `--send` 時 |
| `LINE_TO` | 送信先の userId / groupId | `--send` 時 |
| `ANTHROPIC_API_KEY` | 緊急案件の AI 分析（未設定ならスキップ、`--no-ai` でも無効化） | 任意 |
| `ANTHROPIC_KEY_EXPIRES` | API キーの有効期限（YYYY-MM-DD、GitHub の Variables）。7 日前から毎日 LINE で知らせる | 任意 |
| `NVD_API_KEY` | NVD のレート制限緩和 | 任意 |
| `GITHUB_TOKEN` | GHSA のレート制限緩和 | 任意 |
| `X_BEARER_TOKEN` | X の言及件数取得（未設定なら X 軸はスキップ） | 任意 |
| `DASHBOARD_URL` | 通知文末尾に付けるリンク | 任意 |

## スコア（0〜100）

| 軸 | 内容 | 点 |
|---|---|---|
| 利用規模 | 監視リストの tier 1 / 2 / 3（キーワード一致は ×0.7）、リスト外の KEV は 10 | 30 / 20 / 10 |
| 深刻度 | CVSS×2、未認証ネットワーク +5、RCE +5、tier1 の未認証 RCE（CVSS 9.0 以上）+15 | 〜45 |
| 悪用状況 | KEV +20（未掲載で CISA の SSVC が active なら +15）、ランサムウェア利用 +5、Exploit 参照 +5、EPSS×15 | 〜45 |
| X 言及量 | 5×log10(1+件数) | 〜15 |

70 以上が critical で LINE 即時通知、50 以上 high、30 以上 medium。

監視対象は `config/watchlist.json` を編集する。

## 通知

- **即時（LINE）**: critical の脆弱性と、認証局（CA）の鍵侵害・ルート証明書の信頼取り消し
- **日次まとめ（LINE、毎朝 9 時台）**: 過去 24 時間に新しく見つかった critical / high / medium を製品ごとに集計
- 認証局（CA）事案は Mozilla CA Program（Bugzilla）から取得し、誤発行・失効遅延は日次まとめ、監査遅延・文書不備は記録のみ

## 脆弱性以外の監視

| 種類 | 取得元 | 即時通知 | 日次まとめ |
|---|---|---|---|
| 認証局（CA）事案 | Mozilla CA Program（Bugzilla） | 鍵侵害・信頼取り消し | 誤発行・失効遅延 |
| クラウド・SaaS 障害 | 各社の公式ステータスページ（`config/status.json`） | major / critical（復旧時も通知） | minor、短時間で解決済みのもの |
| 悪性パッケージ | GitHub マルウェア勧告 + npm / PyPI のダウンロード数 | 週 1 万 DL 以上 | 週 1,000 DL 以上 |
| 国内の注意喚起 | JPCERT/CC 注意喚起・IPA 重要なセキュリティ情報 | 狼煙が未通知の事案、事前告知 | 通知済み CVE の注意喚起・更新 |
| サポート終了（EOL） | endoflife.date（`config/eol.json`） | - | 90・30・7 日前と当日 |
