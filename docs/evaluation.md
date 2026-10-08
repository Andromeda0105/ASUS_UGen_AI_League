# MVP 離線評估

## 範圍與方法

測試完整 workflow：`multipart import → parse → detect → correlate → graph → hypotheses → bounded read-only investigation → Markdown export → SQLite reload/delete`。不使用 Ollama，AI 離線回退另以 mock 測試。所有測試 SQLite 使用暫存目錄；瀏覽器 smoke 使用獨立 Firefox profile，不碰個人設定。

三組資料各自說明：

1. **Synthetic regression**：repo `samples/` 與自動測試構造的受控字串。涵蓋正常登入／流量、malformed、空檔、非 UTF-8、超限、年份／時區、跨 IP／帳號、相同時間、反向時間線、重複／亂序、共享 IP／NAT 歧義、以及日誌中的 HTML／prompt injection。這些是規則預期樣本，不能作為真實世界攻擊 ground truth。
2. **External security logs**：[Loghub OpenSSH](https://github.com/logpai/loghub/tree/master/OpenSSH)。上游說明為實驗室 OpenSSH server 的 28+ 天日誌；本地收錄其 2,000 行公開子集，保留原文，版本與 SHA-256 在 `backend/tests/fixtures/external/provenance.json`。授權位於相鄰 `LOGHUB_LICENSE`：限研究／學術使用，須保留授權、提供 repo 連結並於適用時引用論文。引用：Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu, *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics*, ISSRE 2023。這組沒有攻擊／campaign 標籤，**不計算 precision/recall 或真實 incident grouping accuracy**。[上游授權](https://github.com/logpai/loghub/blob/master/LICENSE)
3. **Controlled lab**：`scripts/collect_lab.py` 真正向暫時的 loopback HTTP server 發送四筆請求，產生 Nginx combined 格式日誌。`backend/tests/fixtures/lab/` 保存此次捕捉與逐筆意圖標籤。兩筆 benign、SQLi pattern 一筆、XSS pattern 一筆；server 一律回 200，不執行 SQL／JavaScript。**這是 Python HTTP 日誌 emitter，並非真實 Nginx 或 SSH daemon lab，也不代表漏洞利用成功。**未來可補入真實部署 capture，不能以目前結果宣稱完成真實 Nginx／SSH 攻擊實驗。

## 實測結果

本次環境：Python 3.14.7、FastAPI 0.141.1、SQLite 3.53.4、Linux x86_64；SSH 年份指定 2026、`LOG_TIMEZONE=Asia/Taipei`、Ollama 關閉。機器與詳細欄位見 [evaluation-results.json](evaluation-results.json)。

| 資料 | 輸入行 | 接受／跳過 | 解析接受率 | 告警／Incident | 匯入延遲 ms | 已檢查引用／無效 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| synthetic 多階段 | 10 | 10／0 | 100% | 3／1 | 11.15 | 134／0 |
| synthetic benign | 12 | 10／2 | 83.33% | 0／0 | 3.54 | 30／0 |
| Loghub OpenSSH | 2,000 | 520／1,480 | 26% | 11／10 | 50.00 | 2,602／0 |
| controlled HTTP | 4 | 4／0 | 100% | 2／1 | 2.74 | 44／0 |

- 解析接受率 = 可生成目前 LogEvent 的行數 / 全部輸入行數。不是通用 SSH parser accuracy；非認證訊息、PAM、disconnect 等目前不支援，會逐行回報跳過，而非靜默遺失。
- `message repeated N times` 不展開成 N 筆證據，可能低估真實驗證嘗試；不能宣稱捕捉所有 OpenSSH 攻擊。
- 延遲是**單次本機 TestClient 實測**，包含匯入、圖形／假說及 SQLite 提交，不含 AI、瀏覽器繪圖或完整調查／匯出。不是 p95、吞吐量或 production benchmark。
- 引用檢查覆蓋圖形邊、觀察事實、假說分類及實際唯讀問題答案；整合測試逐一確認引用可由 evidence endpoint 解析。報告 exporter 也拒絕不存在的證據引用。
- 四筆 controlled HTTP 的 pattern labels：TP=2、FP=0、FN=0，precision=1、recall=1。這個樣本非常小、刻意涵蓋已知規則，**不能推估正式環境偵測率或入侵機率**。
- synthetic grouping 的單一 fixture 預期為一個群組、三個告警；測試符合，另有不同來源 IP、時間窗口、帳號差異與反向順序測試。這是規則預期一致性，不是外部 labeled campaign grouping quality。

## 自動測試與使用流程

後端共 77 項測試；Firefox smoke 共 25 項檢查。後端測試驗證：空／壞檔可見診斷、有效資料部分成功、檔案／行數／streaming body 限制、prompt injection 的 literal report 表示、工具 allowlist、預算 0／1、缺少遙測保持 unknown、未校準分數與無證據不升級結論。SQLite trigger 在逐筆寫入中途故意失敗，確認交易 rollback、歷史無 completed row；調查寫入失敗也恢復記憶體狀態。新 Python 程序讀取同一資料庫以確認 backend process reload。

Firefox smoke 驗證實際控制項：雙檔上傳、第 7 行錯誤診斷、Incident context、事件／告警原文 dialog、假說／圖形高亮、單一問題預算、offline report、歷史重開／刪除與其他掃描不受影響。報告與日誌字串不當成 HTML 執行。

## 重現指令

在 repo 根目錄，安裝相依套件：

```sh
.venv/bin/pip install -e './backend[test]'
COPILOT_DB_PATH=/tmp/copilot-regression.sqlite3 PYTHONPATH=backend .venv/bin/python -m unittest discover -s backend/tests -v
PYTHONPATH=backend .venv/bin/python scripts/evaluate.py --output /tmp/copilot-evaluation.json
PYTHONPATH=backend .venv/bin/python scripts/browser_smoke.py
node --check app.js
node --check graph.js
node --check hypotheses.js
```

Firefox smoke 需要系統有 `firefox` 與可啟動 loopback server 的權限。不使用個人 profile；測試結果與暫存資料庫留在 `/tmp/copilot-browser-*`。

重跑受控 capture（需要 loopback socket 權限；不需 Docker／Ollama）：

```sh
.venv/bin/python scripts/collect_lab.py --output /tmp/copilot-lab
```

可將 `/tmp/copilot-lab/access.log` 透過介面以 Nginx 類型匯入。capture 使用當下 UTC 時間，並保留 request intent labels。未來更新 committed fixture 時，必須同步保存 `labels.json`、重跑評估並更新數字。

## 已知限制與後續驗證

- 尚無真實 Nginx／SSH daemon controlled attack capture、大型帶標籤生產資料、歷史登入基線、NAT 身份或 auditd／程序／網路外傳遙測；目前對操作者與成功入侵的判斷保持未知。
- 不支援跨主機 attribution、跨年份 SSH 的自動年分推斷、live ingestion、長期負載／多 worker 一致性。SSH 多檔共用指定年份及 `LOG_TIMEZONE`。
- AI interpretation 的語意正確性、模型升級回歸與 adversarial attack success rate 尚未在真實模型上量化；mock 測試只驗證介面、引用與限制，不能取代模型品質評估。
- 許多合法請求也可能含 SQL／HTML 字串，規則仍可能誤報。外部資料的 11 個告警只代表規則命中，未經逐筆事件調查，不能宣稱全部為攻擊。
