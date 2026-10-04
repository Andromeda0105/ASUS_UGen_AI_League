# AI Security Log Copilot

本機 SSH／Nginx 日誌調查工具。規則引擎負責偵測，Incident Correlator 建立關聯與時間線，Ollama / Qwen 負責唯讀查證及解釋。AI 不會修改偵測結果或執行系統操作。

```text
SSH / Nginx logs → Parsers → LogEvent → Detectors → SecurityAlert
                                                       ↓
                                              Incident Correlator
                                                       ↓
                                                    Incident
                                                       ↓
                                         Local AI + Read-only tools
                                                       ↓
                                      AIAnalysis + Evidence references
```

## 啟動

需要 Python 3.11+、Ollama，以及已下載的 `qwen3:4b`。

```sh
# Ollama 已啟動時不用重複執行
ollama serve
```

另一個終端機，在 repo 根目錄：

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ./backend
uvicorn app.main:app --app-dir backend --reload
```

已建立虛擬環境時只需啟用環境並啟動 Uvicorn。開啟 <http://127.0.0.1:8000>；API 文件在 <http://127.0.0.1:8000/docs>。

環境變數：

| 變數 | 預設 | 用途 |
| --- | --- | --- |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | 後端可連到的 Ollama 地址 |
| `OLLAMA_MODEL` | `qwen3:4b` | 本機已安裝的模型，需支援 tools 與 structured output |
| `OLLAMA_TIMEOUT` | `180` | 每次模型請求逾時秒數；有告警時可能發出兩次請求 |
| `LOG_TIMEZONE` | `Asia/Taipei` | 無時區的 SSH syslog 所屬主機時區 |

SSH 樣本目前以 2026 年解析；Nginx 使用日誌內的年份與 offset。跨來源日誌必須來自同一主機／同一分析範圍，且時間設定一致。

## 查看新功能

1. 在樣本選單選擇 **跨來源 · Web 探測 → SSH 可疑登入**。
2. 按 **偵測並分析**，等待本機模型完成調查。
3. 檢查 **規則告警**：10 筆事件會產生 3 個告警。
4. 檢查 **Incident 關聯與時間線**：會形成 1 個 Critical Incident。
5. 查看 AI 的摘要、判讀依據、唯讀調查建議及尚缺證據。
6. 點擊 `INC-…`、`SSH-…`、`NGX-…` 或 `EVT-…` 引用，查看本次掃描的結構化證據與原始日誌。
7. 展開 **唯讀工具查詢紀錄**，查看模型實際要求的查詢與結果。

示範時間線：

| 時間（UTC+8） | 證據 |
| --- | --- |
| 15:01 | 四次敏感路徑探測，形成 Web enumeration 告警 |
| 15:05 | 同 IP 對 admin 五次認證失敗，形成 SSH brute-force 告警 |
| 15:06 | 同 IP、同帳號成功登入，形成 suspicious-login 告警 |

Critical 是調查優先程度，**不代表已確認入侵**。成功登入可能合法；樣本沒有登入後程序、權限提升、資料存取或外洩證據。

Ollama 不可用或輸出未通過驗證時，規則告警、Incident 與時間線仍可查看。前端狀態標記只保存在當頁，不會持久保存。

## 偵測與關聯規則

- **SSH brute force**：同 IP 在 60 秒內至少五次失敗認證。
- **Suspicious login**：同 IP、同帳號成功登入，之前 10 分鐘內至少五次失敗；同一時間點不視為「先失敗後成功」。
- **SQLi attempt**：解碼請求中的 UNION SELECT、相同值比較、延遲函式、information_schema、破壞性 SQL 或引號接 SQL 註解。一般 `--` 字串不單獨觸發。
- **XSS attempt**：script 標籤、事件 handler 或 javascript URL；一般 img 標籤與單純討論 script/javascript 不單獨觸發。
- **Web enumeration**：同 IP 60 秒內至少四次敏感路徑請求、三個不同路徑，至少兩次 HTTP 404。單次 `/.env` 不形成 enumeration。
- **Incident**：按同 IP 與證據時間分組，群組跨度最多 10 分鐘，避免相鄰事件無限串接。只有有序 Web enumeration → 同帳號至少五次 SSH 失敗 → 可疑登入，才提升為 Critical；其餘維持告警的最高嚴重程度。

IP 可能共用於 NAT／代理，因此 Incident 表示調查關聯假說。SQLi／XSS 告警只表示攻擊嘗試，HTTP 200 不足以判定成功利用。

## AI 與唯讀工具

AI 主要輸入為 Incident、時間線與規則證據。原始 `raw_log` 不送入模型；模型可取得正規化帳號、IP、URI 等資料，這些字串都視為不可信資料。

工具僅查詢**本次掃描快照**：

| 工具 | 功能 |
| --- | --- |
| `search_events` | 依來源 IP、帳號、含時區的起訖時間查詢事件 |
| `get_user_logins` | 查詢指定帳號的成功登入 |
| `get_related_alerts` | 查詢指定來源 IP 的告警 |
| `get_incident_timeline` | 查詢指定 Incident 的時間線 |

工具採白名單，不接受任意檔案路徑、命令或變更操作。模型至多一輪工具選擇、四個工具呼叫；查詢預設回傳 40 筆、最多 100 筆，並回報 `total`／`truncated`。模型若未提出工具查詢，後端會補查首個 Incident 的時間線與來源事件；紀錄以 `origin: fallback` 標示，模型提出的查詢則為 `origin: model`。

最終分析使用 Ollama JSON schema 與 Pydantic 驗證：

```json
{
  "summary": "...",
  "assessment": [{"text": "...", "evidence_ids": ["SSH-..."]}],
  "recommendations": [{"text": "...", "evidence_ids": ["INC-..."]}],
  "missing_evidence": ["缺少登入後程序活動"],
  "confidence": 0.6
}
```

每個判讀與建議都必須引用本次掃描實際存在的證據 ID。格式錯誤或不存在的引用會隱藏整份 AI 結果；後端也會保守過濾非唯讀建議，若全部被移除則顯示預設唯讀調查方向，並透過 `ai_warnings` 說明。這不是語意安全的完整證明；ID 驗證與詞彙過濾無法保證所有文字正確，仍需人工檢查。`confidence` 是模型對分析完整度的自評，沒有校準，不是入侵機率。

JSON schema 和 tool calling 接法參考 [Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs) 與 [Ollama tool calling](https://docs.ollama.com/capabilities/tool-calling)。同時設定 `think=false` 並加入 [Qwen3 官方 `/no_think` 開關](https://qwenlm.github.io/blog/qwen3/)，降低思考內容外漏及生成耗時。

## 樣本

原有 SSH 樣本在 `samples/ssh/`，Nginx 樣本在 `samples/`。新跨來源樣本在 `samples/scenarios/`，可從選單直接使用。

修正帳號比對後，原有 `ssh:compromised_login.log` 從 3 個告警改為 **2 個 brute-force 告警**：成功登入帳號 deploy 的失敗次數不足五次，不能用其他帳號的失敗推論 deploy 遭猜測。樣本原文保留。

## API

- `GET /api/health`、`GET /api/ollama/status`：服務與模型狀態。
- `GET /api/samples`：可用樣本名稱。
- `GET /api/events`、`GET /api/alerts`：預設 SSH 樣本資料。
- `POST /api/scan`：偵測、關聯並選擇性分析，回傳 `scan_id`、`alerts`、`incidents`、`ai_analysis`、`investigation`、`ai_warnings`。
- `GET /api/scans/{scan_id}/evidence/{evidence_id}`：本機證據，包含原始日誌。
- `GET /api/scans/{scan_id}/tools/{tool_name}`：唯讀調查，參數以 query string 傳入。

單一情境：

```sh
curl -X POST http://127.0.0.1:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"sample":"scenario:multi_stage","with_ai":false}'
```

多個既有樣本一起分析（`samples` 有設定時優先於 `sample`；重複事件會去重）：

```sh
curl -X POST http://127.0.0.1:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"samples":["ssh:suspicious_login.log","nginx:enumeration.log"],"with_ai":true}'
```

不同時間或不同 IP 的樣本不會強行產生多階段 Incident。取得 `scan_id` 後，可將其代入：

```sh
curl 'http://127.0.0.1:8000/api/scans/SCAN_ID/tools/get_user_logins?username=admin'
```

快照只在單一後端程序記憶體中保留最近 32 次掃描；重啟／reload 或淘汰後須重新掃描。本階段請使用單一 Uvicorn worker。

## 連線排查與驗證

從**執行 Uvicorn 的環境**執行 `curl http://127.0.0.1:11434/api/tags`。容器／sandbox 的 `127.0.0.1` 不一定是主機；可在主機終端執行後端，或設定該環境可達的 `OLLAMA_BASE_URL`。

```sh
PYTHONPATH=backend .venv/bin/python -m unittest discover -s backend/tests -v
node --check app.js
```

目前沒有即時收集、firewall／auditd／process 日誌、主機行為基線或安全關聯圖。事件專屬欄位仍保留相容的現有模型，尚未全面遷移至 attributes。活動／威脅分布圖仍為標示過的展示圖表。
