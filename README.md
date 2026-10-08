# AI Security Log Copilot

本機 SSH／Nginx 日誌調查工具。規則引擎負責偵測，Incident Correlator 建立關聯與時間線，Ollama / Qwen 負責唯讀查證及解釋。AI 不會修改偵測結果或執行系統操作。

```text
SSH / Nginx logs → Parsers → LogEvent → Detectors → SecurityAlert
                                                       ↓
                                              Incident Correlator
                                                       ↓
                                                    Incident
                                                       ↓
                                      Evidence Graph + Hypothesis Engine
                                                       ↓
                                         Local AI + Read-only tools
                                                       ↓
                                      AIAnalysis + Evidence references
```

## 啟動

需要 Python 3.11+。Ollama 與 `qwen3:4b` 僅供可選的 AI 分析；匯入、規則偵測、調查及匯出均可離線使用。

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

已建立虛擬環境者，本次升級請先執行 `.venv/bin/pip install -e ./backend` 安裝 multipart 相依套件，再重新啟動 Uvicorn。開啟 <http://127.0.0.1:8000>；API 文件在 <http://127.0.0.1:8000/docs>。

環境變數：

| 變數 | 預設 | 用途 |
| --- | --- | --- |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | 後端可連到的 Ollama 地址 |
| `OLLAMA_MODEL` | `qwen3:4b` | 本機已安裝的模型，需支援 structured output |
| `OLLAMA_TIMEOUT` | `300` | 每次模型請求逾時秒數；首次調查最多兩次模型請求 |
| `LOG_TIMEZONE` | `Asia/Taipei` | 無時區的 SSH syslog 所屬主機時區 |

SSH 樣本目前以 2026 年解析；Nginx 使用日誌內的年份與 offset。跨來源日誌必須來自同一主機／同一分析範圍，且時間設定一致。

## MVP：匯入 → 調查 → 匯出 → 重開

1. 在「匯入本機日誌」選擇一或多個檔案，各檔分別選 `SSH authentication` 或 `Nginx combined access`。不使用自動格式辨識。
2. SSH syslog 不含年份，請填入實際 **SSH 年份**；主機時區由 `LOG_TIMEZONE` 設定。示範 `samples/scenarios/multi_stage_auth.log` 的年份填 `2026`。Nginx 直接使用日誌內年份與時區 offset。
3. 建議先取消「使用 AI」，按「匯入並偵測」。每檔會顯示接受／跳過行數、重複行數，以及最多 100 筆含行號的診斷；更多診斷會顯示省略數。空檔或編碼錯誤的檔案會標示未接受，其他有效檔案仍可成功匯入。全部無效時回傳錯誤，不新增歷史。
4. 在 Incident 清單按「選擇此 Incident」，時間線、假說、圖形與 AI 評估會同步切換。點選證據 ID 可查看正規化欄位與原始日誌。
5. 按「唯讀調查」，或選某個問題的「唯讀查詢」。畫面顯示本輪預算、查詢答案與停止原因；有 Ollama 時可按「AI 比較假說」。
6. 按 Incident 旁或調查區的「下載 Markdown」，取得包含證據附錄、假說、未回答問題與不確定性的報告。沒有 AI 也能下載；模型判讀另行標示為推論。
7. 「掃描歷史」可開啟先前結果，恢復已回答問題與 AI 分析，不會重新呼叫模型。重新啟動後端後，頁面預設重開最近一筆；空歷史第一次載入會建立跨來源示範掃描。
8. 使用「刪除」移除指定掃描及其證據／調查紀錄，其他掃描不受影響。告警詳情的狀態標記仍僅供當頁使用，未儲存。

快速示範：同時選擇 `samples/scenarios/multi_stage_access.log`（Nginx）與 `samples/scenarios/multi_stage_auth.log`（SSH，2026），預期 **10 筆事件、3 個告警、1 個 Incident**。

匯入規則與限制：UTF-8 / UTF-8 BOM、SSH 的 `Failed password`／`Accepted password|publickey|keyboard-interactive/pam`、Nginx **combined** 格式。其他 SSH 訊息會標示跳過；不會展開 `message repeated N times` 為 N 個獨立事件。完全相同的正規化事件 ID 會去重；保留單檔接受數與整次去重數。多個主機／不同年份的 SSH 日誌請分次匯入；本輪 SSH 檔案共用同一年份與主機時區。

| 設定 | 預設 | 用途 |
| --- | --- | --- |
| `COPILOT_DB_PATH` | `data/copilot.sqlite3` | 本機 SQLite 路徑 |
| `UPLOAD_MAX_FILES` | `8` | 每次檔案數 |
| `UPLOAD_MAX_FILE_BYTES` | `2097152` | 單檔 2 MiB |
| `UPLOAD_MAX_TOTAL_BYTES` | `8388608` | 合計 8 MiB |
| `UPLOAD_MAX_LINES` | `10000` | 每檔行數；超出則拒絕本次匯入 |
| `UPLOAD_MAX_LINE_BYTES` | `16384` | 單行長度；超出則標示跳過 |

環境變數需在啟動前設定。檔案超過大小／總量限制回傳 413；不支援類型或全部無法解析回傳 422。大量事件的完整圖形可能較慢，預設以 Incident 範圍並隱藏事件節點。

### 本機保存與保留行為

SQLite 的 `scans` 保存 metadata、alerts、incidents、假說和調查結果的 JSON；`events` 保存逐筆正規化事件與原始日誌，以 scan ID 外鍵串連並連動刪除。每次儲存使用交易，提交成功後才將掃描公開；資料庫寫入失敗回傳 503，不顯示已完成。重新載入時保留證據 ID，從證據重建圖形，恢復已回答問題與模型結果。

沒有自動到期政策：掃描會保留至使用者刪除。`data/` 已排除 Git；原始上傳檔案不另存，解析成功行的原文會保存在 SQLite。未解析的行只保留診斷，不保存原文。SQLite 是本機明文檔案，新增檔案使用僅擁有者讀寫權限；不把原始日誌寫入 browser storage 或應用程式例行日誌。刪除是資料庫邏輯刪除，不能保證備份或磁碟殘留被抹除。下載報告也包含原始證據。

此版本定位為單一使用者的本機服務，請維持預設 `127.0.0.1` 綁定；尚未提供多人權限／主機身份管理。圖形重建使用目前版本規則，之後升級規則可能改變衍生關係，原始證據 ID 不變。

### 新增 API

- `GET /api/import/config`：匯入限制、預設 SSH 年份與主機時區。
- `POST /api/scans/upload`：multipart，多個 `files` 與順序一致的 `source_types`，另傳 `ssh_year`、`with_ai`、`tool_budget`。
- `GET /api/scans?limit=20&offset=0`：分頁歷史 metadata；不傳回原始日誌。
- `GET /api/scans/{scan_id}`：重開完整掃描結果與保存的各 Incident 調查結果。
- `DELETE /api/scans/{scan_id}`：刪除指定掃描。
- `GET /api/scans/{scan_id}/incidents/{incident_id}/report.md`：下載證據可追溯的 Markdown。

```sh
curl -X POST http://127.0.0.1:8000/api/scans/upload \
  -F 'files=@samples/scenarios/multi_stage_access.log' -F 'source_types=nginx' \
  -F 'files=@samples/scenarios/multi_stage_auth.log' -F 'source_types=ssh' \
  -F 'ssh_year=2026' -F 'with_ai=false'

curl http://127.0.0.1:8000/api/scans
curl 'http://127.0.0.1:8000/api/scans/SCAN_ID/incidents/INCIDENT_ID/report.md' -o incident.md
```

## 查看證據圖與假說

1. 選擇 **跨來源 · Web 探測 → SSH 可疑登入**。建議先取消勾選 **使用 AI**，按 **偵測並分析**，立即查看結果。
2. 原有偵測結果仍為 **10 筆事件、3 個告警、1 個 Critical Incident**。
3. 在 **Hypothesis-driven Investigation** 比較 H1 單一攻擊者、H2 共享來源／NAT、H3 攻擊後合法登入。觀察事實由後端建立，推論另列；展開支持／反駁／中性證據並點擊引用。
4. 在 **Incident Evidence Graph** 查看實線（觀察／記錄關係）與虛線（推論）。點選 H1／H2／H3 標題可高亮相關節點與關係；點選事件、告警或 Incident 節點可開啟既有證據視窗。
5. 勾選 **顯示事件節點** 查看完整 20 個節點；使用 **顯示推論**、縮放與範圍選單調整圖形。概覽預設隱藏事件節點，以保持可讀性。
6. 按 **唯讀調查（不使用 AI）**。示範有三個可回答問題，預設預算 4 會查完後停止，說明剩餘問題需要 auditd、身份歸屬與歷史基線。
7. 按 **AI 比較假說**，讓 Qwen 解釋 競爭假說 與剩餘不確定性。若還有未回答問題，AI 先選擇問題；查證過的問題不會重複查詢。
8. 可將 **本輪工具預算** 改成 `1`，展示調查如何在預算耗盡時停止；每個可回答問題也可單獨按 **唯讀查詢**。
9. 多個 Incident 時，先在假說區的下拉選單切換，再調查該 Incident。掃描時使用 AI 預設聚焦嚴重程度最高、時間最新的一個 Incident。

不需要 Ollama 即可使用圖形、規則假說、證據導航與唯讀查詢。完整 AI 調查的本機 CPU 實測約需 6 分鐘，耗時依硬體而異；已先完成唯讀查詢時會跳過問題選擇回合，通常較快。

示範時間線：

| 時間（UTC+8） | 證據 |
| --- | --- |
| 15:01 | 四次敏感路徑探測，形成 Web enumeration 告警 |
| 15:05 | 同 IP 對 admin 五次認證失敗，形成 SSH brute-force 告警 |
| 15:06 | 同 IP、同帳號成功登入，形成 suspicious-login 告警 |

Critical 是調查優先程度，**不代表已確認入侵**。成功登入可能合法；樣本沒有登入後程序、權限提升、資料存取或外洩證據。

Ollama 不可用或輸出未通過驗證時，規則告警、Incident、關係圖、規則假說與已完成的唯讀查詢仍可查看。前端狀態標記只保存在當頁，不會持久保存。

## 偵測與關聯規則

- **SSH brute force**：同 IP 在 60 秒內至少五次失敗認證。
- **Suspicious login**：同 IP、同帳號成功登入，之前 10 分鐘內至少五次失敗；同一時間點不視為「先失敗後成功」。
- **SQLi attempt**：解碼請求中的 UNION SELECT、相同值比較、延遲函式、information_schema、破壞性 SQL 或引號接 SQL 註解。一般 `--` 字串不單獨觸發。
- **XSS attempt**：script 標籤、事件 handler 或 javascript URL；一般 img 標籤與單純討論 script/javascript 不單獨觸發。
- **Web enumeration**：同 IP 60 秒內至少四次敏感路徑請求、三個不同路徑，至少兩次 HTTP 404。單次 `/.env` 不形成 enumeration。
- **Incident**：按同 IP 與證據時間分組，群組跨度最多 10 分鐘，避免相鄰事件無限串接。只有有序 Web enumeration → 同帳號至少五次 SSH 失敗 → 可疑登入，才提升為 Critical；其餘維持告警的最高嚴重程度。

IP 可能共用於 NAT／代理，因此 Incident 表示調查關聯假說。SQLi／XSS 告警只表示攻擊嘗試，HTTP 200 不足以判定成功利用。

## AI 與唯讀工具

AI 主要輸入為聚焦 Incident 的觀察事實、確定性圖形概覽、競爭假說與調查問題。原始 `raw_log` 不送入模型；模型可取得正規化帳號、IP、URI 等資料，這些字串都視為不可信資料。

工具僅查詢**本次掃描快照**：

| 工具 | 功能 |
| --- | --- |
| `search_events` | 依來源 IP、帳號、含時區的起訖時間查詢事件 |
| `get_user_logins` | 查詢指定帳號的成功登入 |
| `get_related_alerts` | 查詢指定來源 IP 的告警 |
| `get_incident_timeline` | 查詢指定 Incident 的時間線 |

工具採白名單，不接受任意檔案路徑、命令或變更操作。後端從已驗證的假說模板建立調查問題與固定工具參數；AI 只能選擇既有 `question_ids`，不能任意新增工具或參數。

每個請求最多 **一輪工具查詢**；工具預算預設 4、可設定 0–12，錯誤查詢也計入預算。查詢最多回傳 100 筆，並標示 `total`／`truncated`。模型跳過問題或輸出無效計畫時，後端依可信問題順序補查；紀錄的 `origin: model` 表示模型選擇，`origin: rule` 表示後端安排。查到的額外記錄會加入觀察事實並列為中性證據；不會因此自動宣稱入侵或合法登入。

調查會記錄停止原因：預算耗盡、單輪上限、可回答問題完成，或剩餘問題需要未提供的遙測。空結果只表示本次樣本沒有符合條件的記錄，不能證明真實主機沒有程序、sudo 或其他活動。

最終分析使用 Ollama JSON schema 與 Pydantic 驗證：

```json
{
  "summary": "...",
  "assessment": [{"text": "...", "evidence_ids": ["SSH-..."]}],
  "recommendations": [{"text": "...", "evidence_ids": ["INC-..."]}],
  "missing_evidence": ["缺少登入後程序活動"],
  "confidence": 0.6,
  "hypothesis_evaluations": [{
    "hypothesis_id": "HYP-...",
    "status": "plausible",
    "confidence": 0.55,
    "inference": "此解釋可能符合部分證據，但操作者身份仍未知。",
    "evidence_ids": ["SSH-..."],
    "graph_edge_ids": ["EDGE-..."]
  }]
}
```

每個判讀、建議與假說比較都必須引用真實證據，假說 ID 與圖形邊 ID 也會驗證。AI 不可建立／修改圖形或告警；沒有來源身份或擁有者證據時，不允許將假說升級為確定結果。格式錯誤或不存在的引用會隱藏整份 AI 結果；後端也會保守過濾非唯讀建議，若全部被移除則顯示預設唯讀調查方向，並透過 `ai_warnings` 說明。這不是語意安全的完整證明；ID 驗證與詞彙過濾無法保證所有文字正確，仍需人工檢查。報告的 `confidence` 是模型對分析完整度的自評；假說的 `confidence` 是證據支持程度，後端會依資料不足設定分數上限；圖形邊的分數則是規則對關係的支持程度。三者均未經統計校準、不是入侵機率，假說分數不需要合計為 1。

JSON schema 和 tool calling 接法參考 [Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs) 與 [Ollama tool calling](https://docs.ollama.com/capabilities/tool-calling)。同時設定 `think=false` 並加入 [Qwen3 官方 `/no_think` 開關](https://qwenlm.github.io/blog/qwen3/)，降低思考內容外漏及生成耗時。

## 樣本

原有 SSH 樣本在 `samples/ssh/`，Nginx 樣本在 `samples/`。新跨來源樣本在 `samples/scenarios/`，可從選單直接使用。

修正帳號比對後，原有 `ssh:compromised_login.log` 從 3 個告警改為 **2 個 brute-force 告警**：成功登入帳號 deploy 的失敗次數不足五次，不能用其他帳號的失敗推論 deploy 遭猜測。樣本原文保留。

## API

- `GET /api/health`、`GET /api/ollama/status`：服務與模型狀態。
- `GET /api/samples`：可用樣本名稱。
- `GET /api/events`、`GET /api/alerts`：預設 SSH 樣本資料。
- `POST /api/scan`：偵測、關聯並選擇性分析，回傳 `scan_id`、`alerts`、`incidents`、`ai_analysis`、`investigation`、`ai_warnings`、`hypotheses`、`focused_incident_id`。
- `GET /api/scans/{scan_id}/graph`：本次掃描的確定性節點與關係圖。
- `GET /api/scans/{scan_id}/hypotheses`：各 Incident 的假說、觀察事實、調查問題及停止原因。
- `POST /api/scans/{scan_id}/incidents/{incident_id}/investigate`：調查指定 Incident，例如 `{"with_ai":false,"tool_budget":4}`；可傳 `question_ids` 執行指定的可回答問題。
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
curl 'http://127.0.0.1:8000/api/scans/SCAN_ID/graph'
curl 'http://127.0.0.1:8000/api/scans/SCAN_ID/hypotheses'
curl -X POST 'http://127.0.0.1:8000/api/scans/SCAN_ID/incidents/INCIDENT_ID/investigate' \
  -H 'Content-Type: application/json' \
  -d '{"with_ai":false,"tool_budget":4}'
```

掃描與調查結果持續儲存在 SQLite，重啟／reload 後可以重開；記憶體只快取最近 32 次掃描。此 MVP 請使用單一 Uvicorn worker，避免不同程序的快取互相覆寫調查結果。

## 連線排查與驗證

測試需先安裝 `.venv/bin/pip install -e './backend[test]'`。完整測試與評估不使用 Ollama；請參閱 [docs/evaluation.md](docs/evaluation.md) 的資料來源、實測數字與限制。


從**執行 Uvicorn 的環境**執行 `curl http://127.0.0.1:11434/api/tags`。容器／sandbox 的 `127.0.0.1` 不一定是主機；可在主機終端執行後端，或設定該環境可達的 `OLLAMA_BASE_URL`。

```sh
COPILOT_DB_PATH=/tmp/copilot-regression.sqlite3 PYTHONPATH=backend .venv/bin/python -m unittest discover -s backend/tests -v
node --check app.js
node --check graph.js
node --check hypotheses.js
# 可選：已安裝 Firefox 的主機環境，使用獨立臨時 profile 做實際 DOM 與 API 驗證
PYTHONPATH=backend .venv/bin/python scripts/browser_smoke.py
```

目前沒有即時收集、firewall／auditd／process 日誌或主機行為基線。事件專屬欄位仍保留相容的現有模型，尚未全面遷移至 attributes。原先展示用的活動／威脅分布圖已替換為匯入、歷史與目前掃描資訊。


## 新功能實作位置

| 檔案 | 功能 |
| --- | --- |
| `backend/app/intelligence_models.py` | 圖形、假說、問題、AI 比較與調查結果契約 |
| `backend/app/graph.py` | 從 EvidenceStore 建立有證據引用的確定性圖形 |
| `backend/app/hypotheses.py` | 競爭假說模板、證據分類、觀察事實與問題 |
| `backend/app/investigator.py` | 有界問題選擇、唯讀查詢、停止條件與 AI 比較驗證 |
| `backend/app/importer.py` | 有上限的匯入與逐行診斷 |
| `backend/app/storage.py` | SQLite 交易保存、恢復、歷史與刪除 |
| `backend/app/reports.py` | Incident Markdown 匯出，原始日誌作為 literal data |
| `graph.js` | SVG 關係圖、節點／邊證據導航、篩選與假說高亮 |
| `hypotheses.js` | 競爭假說卡片、觀察事實、缺少證據與問題互動 |

圖形與假說不依賴 LLM、不需要圖形資料庫。所有資料限定在當次掃描，沒有跨主機身份歸屬功能。實線包含日誌觀察與後端建立的記錄／群組關係；`CONTAINS` 表示群組成員，`FOLLOWED_BY` 只表示時間先後，均不是因果證明。

H2 目前沒有直接 NAT 證據，因此保持「證據不足」或低支持程度的合理假說。H1／H3 不能由 SSH/Nginx 判定成功登入者是否為攻擊者／擁有者。新增 auditd 等資料前，後端對 H1、H2、H3 的 AI 支持分數上限分別為 0.65、0.35、0.55；這是保守顯示規則，沒有統計校準。
