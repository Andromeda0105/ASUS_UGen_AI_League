let incidents=[];
let currentSnapshot=null,correlationItems=[],selectedCorrelationId=null;
let historyItems=[],historyTotal=0,workflowBusy=false;
let currentScanId=null;
let evidenceRequestSequence=0;

let activeFilter='all'; let selectedId=null; let showAll=false;
const rows=document.querySelector('#incident-rows');
const severityClass={Critical:'critical',High:'high',Medium:'medium',Low:'medium'};
const severityLabel={Critical:'嚴重',High:'高',Medium:'中',Low:'低'};
const statusLabel={Open:'未處理',Investigating:'調查中',Resolved:'已解決'};
function visibleIncidents(){const q=document.querySelector('#search-input').value.trim().toLowerCase();return incidents.filter(item=>{const filterOk=activeFilter==='all'||(activeFilter==='Open'?item.status==='Open':item.severity===activeFilter);const queryOk=!q||`${item.title} ${item.subtitle} ${item.ip} ${item.id}`.toLowerCase().includes(q);return filterOk&&queryOk}).slice(0,showAll?incidents.length:5)}
function renderRows(){const data=visibleIncidents();rows.innerHTML=data.map(item=>`<tr data-id="${item.id}" class="${item.id===selectedId?'selected':''}"><td><span class="severity ${severityClass[item.severity]}"><i></i>${severityLabel[item.severity]}</span></td><td><span class="incident-title">${item.title}</span><span class="incident-sub">${item.subtitle}</span></td><td><span class="ip">${item.ip}</span></td><td><span class="time">${item.age}</span></td><td><span class="status ${item.status.toLowerCase()}">${statusLabel[item.status]}</span></td><td><span class="row-more">···</span></td></tr>`).join('');document.querySelector('#empty-state').hidden=data.length>0;document.querySelector('#result-count').textContent=`顯示 ${data.length} 筆事件`;rows.querySelectorAll('tr').forEach(row=>row.addEventListener('click',()=>selectIncident(row.dataset.id)));}
function selectIncident(id){
  selectedId=id;
  const item=incidents.find(x=>x.id===id);
  if(!item)return;
  renderRows();
  const parent=correlationItems.find(i=>i.alert_ids.includes(id));if(parent)selectInvestigationIncident(parent.id);
  const panel=document.querySelector('#detail-panel');
  const requestFields=item.requestTarget
    ? `<div class="field"><small>HTTP Request</small><b>${item.requestMethod} ${item.requestTarget}</b></div><div class="field"><small>HTTP 狀態碼</small><b>${item.statusCode}</b></div>`
    : `<div class="field"><small>相關帳號</small><b>${item.user}</b></div><div class="field"><small>活動摘要</small><b>${item.count}</b></div>`;
  panel.innerHTML=`<div class="detail-top"><span>${item.id} · ${item.age}</span><button class="close-detail" aria-label="關閉詳情">×</button></div><span class="detail-severity ${severityClass[item.severity]}">${severityLabel[item.severity]}風險</span><h2>${item.title}</h2><p class="detail-summary">${item.summary}</p><div class="detail-status-row"><span>事件狀態（僅本頁）</span><button id="status-toggle">${statusLabel[item.status]}　⌄</button></div><section class="detail-section"><h3>事件資訊</h3><div class="detail-fields"><div class="field"><small>來源 IP</small><b class="mono">${item.ip}</b></div><div class="field"><small>日誌來源</small><b>${item.source}</b></div>${requestFields}</div></section><section class="detail-section"><h3>原始日誌</h3><div class="detail-box">${item.raw}</div></section><section class="detail-section"><h3>建議檢查</h3><div class="recommendation">${item.recommendation}</div></section><div class="detail-actions"><button class="primary" id="resolve-button">${item.status==='Resolved'?'重新開啟事件':'標記為已解決'}</button><button id="copy-button">複製事件 ID</button></div>`;
  panel.querySelector('.close-detail').addEventListener('click',()=>{selectedId=null;panel.innerHTML='<div class="detail-empty"><span class="detail-empty-icon">⌁</span><b>選取一個安全事件</b><p>查看事件摘要、原始日誌及建議處置。</p></div>';renderRows()});
  panel.querySelector('#resolve-button').addEventListener('click',()=>{item.status=item.status==='Resolved'?'Open':'Resolved';renderSummary();selectIncident(id);toast(item.status==='Resolved'?'本頁標記為已解決（未儲存）':'本頁重新開啟（未儲存）')});
  panel.querySelector('#status-toggle').addEventListener('click',()=>{item.status=item.status==='Open'?'Investigating':item.status==='Investigating'?'Resolved':'Open';renderSummary();selectIncident(id);toast(`事件狀態已更新：${statusLabel[item.status]}`)});
  panel.querySelector('#copy-button').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(item.id);toast(`已複製 ${item.id}`)}catch{toast(`事件 ID：${item.id}`)}});
}
function renderSummary(){const open=incidents.filter(x=>x.status!=='Resolved').length;document.querySelector('#stat-open').textContent=String(open).padStart(2,'0');document.querySelector('#nav-open-count').textContent=open;document.querySelector('#open-pill').textContent=`${open} 未處理`;document.querySelector('#stat-critical').textContent=String(incidents.filter(x=>['Critical','High'].includes(x.severity)&&x.status!=='Resolved').length).padStart(2,'0');}
let toastTimer;function toast(message){let node=document.querySelector('.toast');if(!node){node=document.createElement('div');node.className='toast';document.body.append(node)}node.textContent=message;node.classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>node.classList.remove('show'),1900)}
document.querySelector('#search-input').addEventListener('input',renderRows);document.querySelector('#filter-button').addEventListener('click',()=>{const row=document.querySelector('#filter-row');row.hidden=!row.hidden});document.querySelectorAll('.filter-chip').forEach(chip=>chip.addEventListener('click',()=>{activeFilter=chip.dataset.filter;document.querySelectorAll('.filter-chip').forEach(c=>c.classList.toggle('selected',c===chip));document.querySelector('#filter-indicator').style.display=activeFilter==='all'?'none':'inline-block';renderRows()}));document.querySelector('#show-all').addEventListener('click',()=>{showAll=!showAll;document.querySelector('#show-all').innerHTML=showAll?'收合事件 <span>↑</span>':'查看所有事件 <span>→</span>';renderRows()});
renderRows();renderSummary();

function escapeHtml(value){return String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]))}
function timeLabel(value){const date=new Date(value);return new Intl.DateTimeFormat('zh-TW',{hour:'2-digit',minute:'2-digit',hour12:false}).format(date)}
function mapAlerts(alerts){return alerts.map(alert=>{
  const related=alert.related_events||[];
  const lastEvent=related.at(-1);
  return {
    id:escapeHtml(alert.id),severity:alert.severity,title:escapeHtml(alert.title),
    subtitle:escapeHtml(alert.evidence?.join(' · ')||alert.alert_type),ip:escapeHtml(alert.source_ip),
    time:timeLabel(alert.timestamp),age:timeLabel(alert.timestamp),status:alert.status,
    source:escapeHtml(lastEvent?.source||'—'),user:escapeHtml(alert.username||'—'),count:`${related.length} 筆關聯事件`,
    requestMethod:escapeHtml(lastEvent?.request_method||''),requestTarget:escapeHtml(lastEvent?.request_target||''),
    statusCode:escapeHtml(lastEvent?.status_code||''),
    summary:escapeHtml(alert.summary),raw:related.map(event=>`${escapeHtml(event.id)} · ${escapeHtml(event.raw_log)}`).join('<br><br>'),
    recommendation:escapeHtml(alert.recommendation),
  };
})}
function updateAlerts(alerts){incidents=mapAlerts(alerts);selectedId=null;renderRows();renderSummary();document.querySelector('#show-all').hidden=incidents.length<=5;document.querySelector('#detail-panel').innerHTML='<div class="detail-empty"><span class="detail-empty-icon">⌁</span><b>選取一個安全事件</b><p>查看事件摘要、原始日誌及建議處置。</p></div>'}
async function loadDetectedAlerts(){
  try{
    const [samplesResponse,ollamaResponse,configResponse]=await Promise.all([
      fetch('/api/samples'),fetch('/api/ollama/status'),fetch('/api/import/config')]);
    if(samplesResponse.ok){const samples=await samplesResponse.json();document.querySelector('#sample-select').innerHTML=samples.map(sample=>`<option value="${escapeHtml(sample.name)}">${escapeHtml(sample.label)}</option>`).join('')}
    if(configResponse.ok){const config=await configResponse.json();document.querySelector('#ssh-year').value=config.ssh_year;document.querySelector('#upload-limits').textContent=`最多 ${config.max_files} 檔；單檔 ${(config.max_file_bytes/1048576).toFixed(1)} MiB，總計 ${(config.max_total_bytes/1048576).toFixed(1)} MiB；每檔 ${config.max_lines_per_file} 行。SSH 時區：${config.ssh_timezone}`}
    if(ollamaResponse.ok){const state=await ollamaResponse.json();document.querySelector('#model-label').textContent=state.available?`${state.model} · 本機就緒`:`${state.model} · 尚未連線`;document.querySelector('.local-pill').classList.toggle('offline',!state.available)}
    await refreshHistory();
    if(historyItems.length)await openSavedScan(historyItems[0].scan_id);
    else{const response=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sample:'scenario:multi_stage',with_ai:false})});if(response.ok){applyScan(await response.json());await refreshHistory()}}
    document.querySelector('.demo-badge').innerHTML='<i></i>本機 API · SQLite 保存';
  }catch(error){toast(`無法載入工作區：${error.message}`)}
}
function setWorkflowBusy(busy){workflowBusy=busy;HypothesisPanel.setBusy(busy);document.querySelectorAll('#scan-button,#upload-button,#upload-files,#ssh-year,#sample-select,#scan-with-ai,#refresh-history,#history-more,#hypothesis-incident,#graph-scope,#tool-budget,[data-open-scan],[data-delete-scan],[data-select-incident]').forEach(el=>el.disabled=busy)}
function applyScan(result){
  ++evidenceRequestSequence;document.querySelector('#evidence-dialog').close();
  currentSnapshot=result;currentScanId=result.scan_id;correlationItems=result.incidents||[];
  selectedCorrelationId=result.focused_incident_id||correlationItems[0]?.id||null;
  updateAlerts(result.alerts);loadEvidenceGraph(result.scan_id);HypothesisPanel.setData(result.hypotheses||[],selectedCorrelationId);renderCorrelations(correlationItems);
  document.querySelector('#stat-events').textContent=result.event_count;document.querySelector('#event-count-foot').textContent='目前掃描的去重事件數';
  document.querySelector('#scan-overview').innerHTML=`<p><b>${escapeHtml(result.sample)}</b></p><p>Scan ID：${escapeHtml(result.scan_id)} · ${escapeHtml(result.created_at?new Date(result.created_at).toLocaleString():'')}<br>${result.event_count} 筆事件 · ${result.alerts.length} 個規則告警 · ${correlationItems.length} 個 Incident · 去除 ${result.duplicate_event_count||0} 筆重複事件</p>`;
  renderImportFeedback(result.file_results||[]);renderCurrentAnalysis();syncReportDownload();renderHistory();
}
function renderCurrentAnalysis(){
  const output=document.querySelector('#ai-analysis'),status=document.querySelector('#copilot-status');
  const saved=currentSnapshot?.investigation_results?.[selectedCorrelationId];
  const analysis=saved?.ai_analysis||(currentSnapshot?.focused_incident_id===selectedCorrelationId?currentSnapshot?.ai_analysis:null);
  if(analysis){output.className='analysis-content';renderAnalysis(analysis,saved?.investigation||currentSnapshot.investigation||[],saved?.ai_warnings||currentSnapshot.ai_warnings||[]);status.textContent=`已儲存的 AI 推論 · ${selectedCorrelationId||'目前掃描'}`}
  else{output.className='analysis-content';output.textContent=saved?.ai_error||currentSnapshot?.ai_error||'確定性結果已完成。可選擇 Incident 進行唯讀調查；AI 可選用。';if(saved?.investigation?.length)output.innerHTML+=toolTraceMarkup(saved.investigation);status.textContent=selectedCorrelationId?`目前調查：${selectedCorrelationId}`:'沒有 Incident；仍可查看解析結果與歷史。'}
}
function syncReportDownload(){const link=document.querySelector('#download-selected-report');link.hidden=!selectedCorrelationId;if(selectedCorrelationId){link.href=`/api/scans/${encodeURIComponent(currentScanId)}/incidents/${encodeURIComponent(selectedCorrelationId)}/report.md`;link.setAttribute('download','')}}
function selectInvestigationIncident(id,syncHypothesis=true){if(!correlationItems.some(i=>i.id===id))return;selectedCorrelationId=id;if(syncHypothesis)HypothesisPanel.chooseIncident(id);renderCorrelations(correlationItems);renderCurrentAnalysis();syncReportDownload()}
async function scanSelectedSample(){
  const button=document.querySelector('#scan-button');
  const output=document.querySelector('#ai-analysis');
  const status=document.querySelector('#copilot-status');
  setWorkflowBusy(true);button.innerHTML='◌ <span>正在偵測與分析…</span>';
  output.className='analysis-content loading';output.textContent='規則引擎正在偵測與關聯日誌，接著會呼叫本機 Ollama 進行唯讀調查…';
  status.textContent='分析工作進行中；日誌原文不會送入模型。';
  try{
    const response=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sample:document.querySelector('#sample-select').value,with_ai:document.querySelector('#scan-with-ai').checked,tool_budget:Number(document.querySelector('#tool-budget').value||4)})});
    const result=await response.json();
    if(!response.ok)throw new Error(result.detail||`HTTP ${response.status}`);
    applyScan(result);await refreshHistory();
    const sampleLabel=result.sample;
    if(result.ai_status==='completed'){
      output.className='analysis-content';renderAnalysis(result.ai_analysis,result.investigation||[],result.ai_warnings||[]);
      status.textContent=`分析完成 · ${sampleLabel} · ${result.event_count} 筆解析事件、${result.alerts.length} 個規則告警、${result.incidents.length} 個 Incident`;
    }else if(result.ai_status==='skipped'){
      output.className='analysis-content';output.textContent='確定性偵測、關係圖與競爭假說已完成；未使用 AI。可按「唯讀調查」查證問題，或按「AI 比較假說」。';status.textContent='後端事實與假說已建立 · 尚未進行 AI 比較';
    }else{
      output.className='analysis-content error';
      output.textContent=`偵測完成，共解析 ${result.event_count} 筆事件、產生 ${result.alerts.length} 個告警。\n\nAI 分析暫不可用：${result.ai_error||'本機模型未回應'}\n\n請檢查 Ollama 或分析錯誤，然後重新按「偵測並分析」。`;
      if(result.investigation?.length)output.innerHTML+=toolTraceMarkup(result.investigation);
      status.textContent=`規則偵測完成 · ${sampleLabel} · AI 分析未完成`;
    }
  }catch(error){
    output.className='analysis-content error';output.textContent=`無法完成掃描：${error.message}`;status.textContent='本機 API 無法連線，請確認後端服務已啟動。';
  }finally{setWorkflowBusy(false);button.innerHTML='⌕ <span>偵測並分析</span>'}
}
document.querySelector('#scan-button').addEventListener('click',scanSelectedSample);
SecurityGraph.init();
HypothesisPanel.init();
loadDetectedAlerts();

const stageLabels={web_reconnaissance:'Web 探測',credential_attack:'SSH 密碼猜測',suspicious_authentication:'可疑成功登入',web_exploitation_attempt:'Web 漏洞利用嘗試'};
function evidenceButton(id){return `<button class="evidence-link" data-evidence="${escapeHtml(id)}">${escapeHtml(id)}</button>`}
function bindEvidence(container){container.querySelectorAll('[data-evidence]').forEach(button=>button.addEventListener('click',()=>showEvidence(button.dataset.evidence)))}
function incidentSources(item){return [...new Set((currentSnapshot?.alerts||[]).filter(a=>item.alert_ids.includes(a.id)).flatMap(a=>(a.related_events||[]).map(e=>e.source)))].join(' / ')}
function renderCorrelations(items){
  const container=document.querySelector('#correlated-incidents');
  container.innerHTML=items.length?items.map(item=>`<article class="incident-card ${item.id===selectedCorrelationId?'selected-context':''}"><div class="title-inline"><span class="severity ${severityClass[item.severity]}">${severityLabel[item.severity]}</span><h3>${escapeHtml(item.title)}</h3></div><p>${escapeHtml(item.source_ips.join(', '))} · ${escapeHtml(item.usernames.join(', ')||'無帳號資料')} · ${item.alert_ids.length} 個告警 · ${escapeHtml(incidentSources(item))} · ${evidenceButton(item.id)}</p><p>${escapeHtml(item.start_time)} ～ ${escapeHtml(item.end_time)}</p><div class="context-actions"><button class="incident-context-select" data-select-incident="${escapeHtml(item.id)}">${item.id===selectedCorrelationId?'目前調查':'選擇此 Incident'}</button><a class="report-download" download href="/api/scans/${encodeURIComponent(currentScanId)}/incidents/${encodeURIComponent(item.id)}/report.md">下載 Markdown</a></div>${item.id===selectedCorrelationId?`<p>${escapeHtml(item.correlation_reason)}</p><ol class="attack-timeline">${item.timeline.map(entry=>`<li><time>${timeLabel(entry.timestamp)}</time> <b>${escapeHtml(stageLabels[entry.stage]||entry.stage)}</b> ${evidenceButton(entry.alert_id)}<div>${entry.event_ids.map(evidenceButton).join(' ')}</div></li>`).join('')}</ol>`:''}</article>`).join(''):'沒有規則告警，因此沒有建立 Incident。解析結果與歷史仍可查看。';
  bindEvidence(container);container.querySelectorAll('[data-select-incident]').forEach(button=>{button.disabled=workflowBusy;button.addEventListener('click',()=>selectInvestigationIncident(button.dataset.selectIncident))});
}
function toolTraceMarkup(trace){return `<details><summary>唯讀工具查詢紀錄（${trace.length} 次）</summary><pre>${escapeHtml(JSON.stringify(trace,null,2))}</pre></details>`}
function renderAnalysis(analysis,trace,warnings=[]){
  const container=document.querySelector('#ai-analysis');
  function claims(items){return `<ul>${items.map(claim=>`<li>${escapeHtml(claim.text)}<div>${claim.evidence_ids.map(evidenceButton).join(' ')}</div></li>`).join('')}</ul>`}
  container.innerHTML=`<p class="analysis-confidence">判讀界線：攻擊嘗試與成功驗證不等於已確認惡意入侵；仍需查證主機與帳號活動。</p><h3>AI 摘要（推論）</h3><p>${escapeHtml(analysis.summary)}</p><h3>AI 判讀依據（引用證據，非新增事實）</h3>${claims(analysis.assessment)}<h3>建議調查（唯讀）</h3>${claims(analysis.recommendations)}<h3>尚缺證據</h3><ul>${analysis.missing_evidence.map(item=>`<li>${escapeHtml(item)}</li>`).join('')}</ul><p class="analysis-confidence">模型分析完整度自評：${Math.round(analysis.confidence*100)}%（非入侵機率）</p>${warnings.map(note=>`<p class="analysis-confidence">${escapeHtml(note)}</p>`).join('')}${toolTraceMarkup(trace)}`;
  bindEvidence(container);
}
async function showEvidence(id){
  const sequence=++evidenceRequestSequence,scanId=currentScanId;
  const dialog=document.querySelector('#evidence-dialog');
  const content=document.querySelector('#evidence-content');
  content.textContent='正在讀取本次掃描證據…';
  if(!dialog.open)dialog.showModal();
  try{
    const response=await fetch(`/api/scans/${encodeURIComponent(scanId)}/evidence/${encodeURIComponent(id)}`);
    if(!response.ok)throw new Error('證據快照已不存在，請重新掃描。');
    const evidence=await response.json();
    if(sequence===evidenceRequestSequence&&scanId===currentScanId)content.textContent=JSON.stringify(evidence,null,2);
  }catch(error){if(sequence===evidenceRequestSequence)content.textContent=error.message}
}
document.querySelector('#close-evidence').addEventListener('click',()=>document.querySelector('#evidence-dialog').close());

let graphRequestSequence=0;
async function loadEvidenceGraph(scanId){
  const sequence=++graphRequestSequence;
  try{const response=await fetch(`/api/scans/${encodeURIComponent(scanId)}/graph`);if(!response.ok)throw new Error('證據圖暫不可用');const graph=await response.json();if(sequence===graphRequestSequence&&scanId===currentScanId){SecurityGraph.setData(graph);HypothesisPanel.applyGraphFocus()}}catch(error){if(sequence===graphRequestSequence)document.querySelector('#evidence-graph').textContent=error.message}
}

async function runSelectedIncident(withAI,questionIds=null){
  const incidentId=HypothesisPanel.selectedId(),scanId=currentScanId;
  if(!incidentId||!scanId)return;
  const output=document.querySelector('#ai-analysis'),status=document.querySelector('#copilot-status');
  const button=document.querySelector('#scan-button');
  setWorkflowBusy(true);
  status.textContent=withAI?'正在選擇可回答問題、唯讀查詢並比較假說…':'正在查詢本次樣本中的唯讀證據…';
  try{
    const response=await fetch(`/api/scans/${encodeURIComponent(scanId)}/incidents/${encodeURIComponent(incidentId)}/investigate`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({with_ai:withAI,tool_budget:questionIds?1:Number(document.querySelector('#tool-budget').value||4),question_ids:questionIds})});
    const result=await response.json();
    if(!response.ok)throw new Error(result.detail||'調查無法完成');
    if(scanId!==currentScanId)return;
    HypothesisPanel.replaceReport(result.report);
    const old=currentSnapshot.investigation_results?.[incidentId];currentSnapshot.investigation_results??={};currentSnapshot.investigation_results[incidentId]={...result,ai_analysis:result.ai_analysis||old?.ai_analysis};
    currentSnapshot.hypotheses=currentSnapshot.hypotheses.map(r=>r.incident_id===incidentId?result.report:r);
    if(result.ai_status==='completed'){output.className='analysis-content';renderAnalysis(result.ai_analysis,result.investigation,result.ai_warnings);status.textContent=`假說比較完成 · ${incidentId} · 停止原因已列於調查狀態`}
    else{output.className=result.ai_status==='unavailable'?'analysis-content error':'analysis-content';output.textContent=result.ai_error?`AI 比較未完成：${result.ai_error}\n唯讀查詢與後端假說仍可查看。`:'唯讀查詢完成。觀察事實、競爭假說與缺少證據仍分開呈現。';output.innerHTML+=toolTraceMarkup(result.investigation);status.textContent='本輪調查已停止 · 查看問題答案與停止原因'}
  }catch(error){toast(error.message);status.textContent=error.message}
  finally{setWorkflowBusy(false)}
}

let selectedUploadFiles=[];
document.querySelector('#upload-files').addEventListener('change',event=>{
  selectedUploadFiles=Array.from(event.target.files);const list=document.querySelector('#upload-file-list');list.replaceChildren();
  selectedUploadFiles.forEach((file,index)=>{const row=document.createElement('div');row.className='import-file';const name=document.createElement('span');name.textContent=`${file.name} · ${file.size} bytes`;const select=document.createElement('select');select.dataset.fileIndex=index;select.setAttribute('aria-label',`${file.name} 日誌類型`);for(const [value,label] of [['ssh','SSH authentication'],['nginx','Nginx combined access']]){const option=document.createElement('option');option.value=value;option.textContent=label;select.append(option)}select.value=/access|nginx/i.test(file.name)?'nginx':'ssh';row.append(name,select);list.append(row)});
});
function renderImportFeedback(reports,message=''){
  const box=document.querySelector('#import-feedback');box.innerHTML=message?`<p class="import-feedback-error">${escapeHtml(message)}</p>`:'';
  box.innerHTML+=reports.map(r=>`<article class="import-feedback-item ${escapeHtml(r.status)}"><strong>${escapeHtml(r.filename)} · ${escapeHtml(r.source_type)} · ${escapeHtml({accepted:'已接受',partial:'部分成功',rejected:'未接受'}[r.status]||r.status)}</strong><p>${r.line_count} 行 · 接受 ${r.accepted_lines} 行 · 跳過 ${r.rejected_lines} 行 · 檔內去重 ${r.duplicate_lines} 行${r.ssh_year?` · SSH 年份 ${r.ssh_year}、時區 ${escapeHtml(r.timezone)}`:''}</p>${r.issues.length?`<details><summary>解析診斷（${r.issues.length} 筆${r.issues_omitted?`，另 ${r.issues_omitted} 筆未展開`:''}）</summary><ul>${r.issues.map(issue=>`<li>${issue.line?'第 '+issue.line+' 行':'檔案'}：${escapeHtml(issue.reason)}</li>`).join('')}</ul></details>`:''}</article>`).join('');
}
document.querySelector('#upload-button').addEventListener('click',async()=>{
  if(!selectedUploadFiles.length){renderImportFeedback([],'請先選擇日誌檔案。');return}
  const data=new FormData();selectedUploadFiles.forEach((file,index)=>{data.append('files',file);data.append('source_types',document.querySelector(`[data-file-index="${index}"]`).value)});
  data.append('ssh_year',document.querySelector('#ssh-year').value);data.append('with_ai',String(document.querySelector('#scan-with-ai').checked));data.append('tool_budget',document.querySelector('#tool-budget').value);
  setWorkflowBusy(true);document.querySelector('#upload-button').textContent='匯入處理中…';
  try{const response=await fetch('/api/scans/upload',{method:'POST',body:data});const result=await response.json();if(!response.ok){const detail=result.detail;renderImportFeedback(detail?.file_results||[],typeof detail==='string'?detail:detail?.message||JSON.stringify(detail));return}applyScan(result);await refreshHistory();toast('匯入完成，已儲存於本機。')}
  catch(error){renderImportFeedback([],`匯入失敗：${error.message}`)}
  finally{setWorkflowBusy(false);document.querySelector('#upload-button').textContent='匯入並偵測'}
});
function renderHistory(){
  const container=document.querySelector('#scan-history');container.replaceChildren();
  if(!historyItems.length){container.textContent='尚無掃描紀錄。';return}
  historyItems.forEach(item=>{const row=document.createElement('div');row.className=`history-row ${item.scan_id===currentScanId?'active':''}`;const info=document.createElement('div'),title=document.createElement('strong'),meta=document.createElement('small');title.textContent=item.sample;meta.textContent=`${new Date(item.created_at).toLocaleString()} · ${item.source_types.join(' / ')} · ${item.event_count} 事件 / ${item.alert_count} 告警 / ${item.incident_count} Incident · ${item.scan_id}`;info.append(title,meta);const open=document.createElement('button');open.className='investigation-action';open.textContent='開啟';open.dataset.openScan=item.scan_id;open.disabled=workflowBusy;open.addEventListener('click',()=>openSavedScan(item.scan_id));const remove=document.createElement('button');remove.className='history-delete';remove.textContent='刪除';remove.dataset.deleteScan=item.scan_id;remove.disabled=workflowBusy;remove.addEventListener('click',()=>deleteSavedScan(item.scan_id));row.append(info,open,remove);container.append(row)});
  document.querySelector('#history-more').hidden=historyItems.length>=historyTotal;
}
async function refreshHistory(append=false){const response=await fetch(`/api/scans?limit=20&offset=${append?historyItems.length:0}`);if(!response.ok)throw new Error('無法讀取掃描歷史。');const data=await response.json();historyItems=append?historyItems.concat(data.items):data.items;historyTotal=data.total;renderHistory()}
async function openSavedScan(id){setWorkflowBusy(true);try{const response=await fetch(`/api/scans/${encodeURIComponent(id)}`);if(!response.ok)throw new Error('掃描不存在或無法讀取。');applyScan(await response.json());toast('已開啟儲存的掃描。')}catch(error){toast(error.message)}finally{setWorkflowBusy(false)}}
async function deleteSavedScan(id){
  if(!window.confirm('刪除此掃描及其本機證據與調查紀錄？此操作無法復原。'))return;
  setWorkflowBusy(true);try{const response=await fetch(`/api/scans/${encodeURIComponent(id)}`,{method:'DELETE'});if(!response.ok)throw new Error('無法刪除掃描。');if(id===currentScanId){currentScanId=null;currentSnapshot=null;correlationItems=[];selectedCorrelationId=null;++evidenceRequestSequence;document.querySelector('#evidence-dialog').close();updateAlerts([]);HypothesisPanel.setData([]);SecurityGraph.setData({nodes:[],edges:[]});renderCorrelations([]);syncReportDownload();document.querySelector('#scan-overview').textContent='目前掃描已刪除；可開啟其他歷史或重新匯入。';document.querySelector('#stat-events').textContent='—';document.querySelector('#ai-analysis').textContent='目前沒有掃描。';document.querySelector('#copilot-status').textContent='目前沒有掃描。';renderImportFeedback([])}await refreshHistory();toast('掃描已刪除。')}catch(error){toast(error.message)}finally{setWorkflowBusy(false)}
}
document.querySelector('#refresh-history').addEventListener('click',()=>refreshHistory().catch(error=>toast(error.message)));
document.querySelector('#history-more').addEventListener('click',()=>refreshHistory(true).catch(error=>toast(error.message)));
