let incidents=[];
let currentSnapshot=null,correlationItems=[],selectedCorrelationId=null;
let historyItems=[],historyTotal=0,workflowBusy=false;
let currentScanId=null;
let evidenceRequestSequence=0;

let activeFilter='all'; let selectedId=null; let showAll=false;
const rows=document.querySelector('#incident-rows');
const severityClass={Critical:'critical',High:'high',Medium:'medium',Low:'medium'};
const severityLabel={Critical:'Critical',High:'High',Medium:'Medium',Low:'Low'};
const statusLabel={Open:'Open',Investigating:'Investigating',Resolved:'Resolved'};
function visibleIncidents(){const q=document.querySelector('#search-input').value.trim().toLowerCase();return incidents.filter(item=>{const filterOk=activeFilter==='all'||(activeFilter==='Open'?item.status==='Open':item.severity===activeFilter);const queryOk=!q||`${item.title} ${item.subtitle} ${item.ip} ${item.id}`.toLowerCase().includes(q);return filterOk&&queryOk}).slice(0,showAll?incidents.length:5)}
function renderRows(){const data=visibleIncidents();rows.innerHTML=data.map(item=>`<tr data-id="${item.id}" class="${item.id===selectedId?'selected':''}"><td><span class="severity ${severityClass[item.severity]}"><i></i>${severityLabel[item.severity]}</span></td><td><span class="incident-title">${item.title}</span><span class="incident-sub">${item.subtitle}</span></td><td><span class="ip">${item.ip}</span></td><td><span class="time">${item.age}</span></td><td><span class="status ${item.status.toLowerCase()}">${statusLabel[item.status]}</span></td><td><span class="row-more">···</span></td></tr>`).join('');document.querySelector('#empty-state').hidden=data.length>0;document.querySelector('#result-count').textContent=`Showing ${data.length} alerts`;rows.querySelectorAll('tr').forEach(row=>row.addEventListener('click',()=>selectIncident(row.dataset.id)));}
function selectIncident(id){
  selectedId=id;
  const item=incidents.find(x=>x.id===id);
  if(!item)return;
  renderRows();
  const parent=correlationItems.find(i=>i.alert_ids.includes(id));if(parent)selectInvestigationIncident(parent.id);
  const panel=document.querySelector('#detail-panel');
  const requestFields=item.requestTarget
    ? `<div class="field"><small>HTTP Request</small><b>${item.requestMethod} ${item.requestTarget}</b></div><div class="field"><small>HTTP status code</small><b>${item.statusCode}</b></div>`
    : `<div class="field"><small>Account</small><b>${item.user}</b></div><div class="field"><small>Activity summary</small><b>${item.count}</b></div>`;
  panel.innerHTML=`<div class="detail-top"><span>${item.id} · ${item.age}</span><button class="close-detail" aria-label="Close details">×</button></div><span class="detail-severity ${severityClass[item.severity]}">${severityLabel[item.severity]} risk</span><h2>${item.title}</h2><p class="detail-summary">${item.summary}</p><div class="detail-status-row"><span>Alert status (this page only)</span><button id="status-toggle">${statusLabel[item.status]}　⌄</button></div><section class="detail-section"><h3>Alert information</h3><div class="detail-fields"><div class="field"><small>Source IP</small><b class="mono">${item.ip}</b></div><div class="field"><small>Log sources</small><b>${item.source}</b></div>${requestFields}</div></section><section class="detail-section"><h3>Raw logs</h3><div class="detail-box">${item.raw}</div></section><section class="detail-section"><h3>Suggested checks</h3><div class="recommendation">${item.recommendation}</div></section><div class="detail-actions"><button class="primary" id="resolve-button">${item.status==='Resolved'?'Reopen alert':'Mark as resolved'}</button><button id="copy-button">Copy alert ID</button></div>`;
  panel.querySelector('.close-detail').addEventListener('click',()=>{selectedId=null;panel.innerHTML='<div class="detail-empty"><span class="detail-empty-icon">⌁</span><b>Select a security alert</b><p>View the alert summary, original logs, and suggested checks.</p></div>';renderRows()});
  panel.querySelector('#resolve-button').addEventListener('click',()=>{item.status=item.status==='Resolved'?'Open':'Resolved';renderSummary();selectIncident(id);toast(item.status==='Resolved'?'Marked as resolved on this page (not saved)':'Reopened on this page (not saved)')});
  panel.querySelector('#status-toggle').addEventListener('click',()=>{item.status=item.status==='Open'?'Investigating':item.status==='Investigating'?'Resolved':'Open';renderSummary();selectIncident(id);toast(`Alert status updated: ${statusLabel[item.status]}`)});
  panel.querySelector('#copy-button').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(item.id);toast(`Copied ${item.id}`)}catch{toast(`Alert ID: ${item.id}`)}});
}
function renderSummary(){const open=incidents.filter(x=>x.status!=='Resolved').length;document.querySelector('#stat-open').textContent=String(open).padStart(2,'0');document.querySelector('#nav-open-count').textContent=open;document.querySelector('#open-pill').textContent=`${open} open`;document.querySelector('#stat-critical').textContent=String(incidents.filter(x=>['Critical','High'].includes(x.severity)&&x.status!=='Resolved').length).padStart(2,'0');}
let toastTimer;function toast(message){let node=document.querySelector('.toast');if(!node){node=document.createElement('div');node.className='toast';document.body.append(node)}node.textContent=message;node.classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>node.classList.remove('show'),1900)}
document.querySelector('#search-input').addEventListener('input',renderRows);document.querySelector('#filter-button').addEventListener('click',()=>{const row=document.querySelector('#filter-row');row.hidden=!row.hidden});document.querySelectorAll('.filter-chip').forEach(chip=>chip.addEventListener('click',()=>{activeFilter=chip.dataset.filter;document.querySelectorAll('.filter-chip').forEach(c=>c.classList.toggle('selected',c===chip));document.querySelector('#filter-indicator').style.display=activeFilter==='all'?'none':'inline-block';renderRows()}));document.querySelector('#show-all').addEventListener('click',()=>{showAll=!showAll;document.querySelector('#show-all').innerHTML=showAll?'Show fewer alerts <span>↑</span>':'Show all alerts <span>→</span>';renderRows()});
renderRows();renderSummary();

function escapeHtml(value){return String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]))}
function timeLabel(value){const date=new Date(value);return new Intl.DateTimeFormat('en-US',{hour:'2-digit',minute:'2-digit',hour12:false}).format(date)}
function mapAlerts(alerts){return alerts.map(alert=>{
  const related=alert.related_events||[];
  const lastEvent=related.at(-1);
  return {
    id:escapeHtml(alert.id),severity:alert.severity,title:escapeHtml(alert.title),
    subtitle:escapeHtml(alert.evidence?.join(' · ')||alert.alert_type),ip:escapeHtml(alert.source_ip),
    time:timeLabel(alert.timestamp),age:timeLabel(alert.timestamp),status:alert.status,
    source:escapeHtml(lastEvent?.source||'—'),user:escapeHtml(alert.username||'—'),count:`${related.length} related events`,
    requestMethod:escapeHtml(lastEvent?.request_method||''),requestTarget:escapeHtml(lastEvent?.request_target||''),
    statusCode:escapeHtml(lastEvent?.status_code||''),
    summary:escapeHtml(alert.summary),raw:related.map(event=>`${escapeHtml(event.id)} · ${escapeHtml(event.raw_log)}`).join('<br><br>'),
    recommendation:escapeHtml(alert.recommendation),
  };
})}
function updateAlerts(alerts){incidents=mapAlerts(alerts);selectedId=null;renderRows();renderSummary();document.querySelector('#show-all').hidden=incidents.length<=5;document.querySelector('#detail-panel').innerHTML='<div class="detail-empty"><span class="detail-empty-icon">⌁</span><b>Select a security alert</b><p>View the alert summary, original logs, and suggested checks.</p></div>'}
async function loadDetectedAlerts(){
  try{
    const [samplesResponse,ollamaResponse,configResponse]=await Promise.all([
      fetch('/api/samples'),fetch('/api/ollama/status'),fetch('/api/import/config')]);
    if(samplesResponse.ok){const samples=await samplesResponse.json();document.querySelector('#sample-select').innerHTML=samples.map(sample=>`<option value="${escapeHtml(sample.name)}">${escapeHtml(sample.label)}</option>`).join('')}
    if(configResponse.ok){const config=await configResponse.json();document.querySelector('#ssh-year').value=config.ssh_year;document.querySelector('#upload-limits').textContent=`Up to ${config.max_files} files; per file: ${(config.max_file_bytes/1048576).toFixed(1)} MiB; total: ${(config.max_total_bytes/1048576).toFixed(1)} MiB; ${config.max_lines_per_file} lines per file. SSH timezone: ${config.ssh_timezone}`}
    if(ollamaResponse.ok){const state=await ollamaResponse.json();document.querySelector('#model-label').textContent=state.available?`${state.model} · Ready locally`:`${state.model} · Offline`;document.querySelector('.local-pill').classList.toggle('offline',!state.available)}
    await refreshHistory();
    if(historyItems.length)await openSavedScan(historyItems[0].scan_id);
    else{const response=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sample:'scenario:multi_stage',with_ai:false})});if(response.ok){applyScan(await response.json());await refreshHistory()}}
    document.querySelector('.demo-badge').innerHTML='<i></i>Local API · SQLite storage';
  }catch(error){toast(`Unable to load workspace: ${error.message}`)}
}
function setWorkflowBusy(busy){workflowBusy=busy;HypothesisPanel.setBusy(busy);document.querySelectorAll('#scan-button,#upload-button,#choose-log-files,#upload-files,#ssh-year,#sample-select,#scan-with-ai,#refresh-history,#history-more,#hypothesis-incident,#graph-scope,#tool-budget,[data-open-scan],[data-delete-scan],[data-select-incident]').forEach(el=>el.disabled=busy)}
function applyScan(result){
  ++evidenceRequestSequence;document.querySelector('#evidence-dialog').close();
  currentSnapshot=result;currentScanId=result.scan_id;correlationItems=result.incidents||[];
  selectedCorrelationId=result.focused_incident_id||correlationItems[0]?.id||null;
  updateAlerts(result.alerts);loadEvidenceGraph(result.scan_id);HypothesisPanel.setData(result.hypotheses||[],selectedCorrelationId);renderCorrelations(correlationItems);
  document.querySelector('#stat-events').textContent=result.event_count;document.querySelector('#event-count-foot').textContent='Unique events in the current scan';
  document.querySelector('#scan-overview').innerHTML=`<p><b>${escapeHtml(result.sample)}</b></p><p>Scan ID: ${escapeHtml(result.scan_id)} · ${escapeHtml(result.created_at?new Date(result.created_at).toLocaleString('en-US'):'')}<br>${result.event_count} events · ${result.alerts.length} rule alerts · ${correlationItems.length} incidents · ${result.duplicate_event_count||0} duplicates removed</p>`;
  renderImportFeedback(result.file_results||[]);renderCurrentAnalysis();syncReportDownload();renderHistory();
}
function renderCurrentAnalysis(){
  const output=document.querySelector('#ai-analysis'),status=document.querySelector('#copilot-status');
  const saved=currentSnapshot?.investigation_results?.[selectedCorrelationId];
  const analysis=saved?.ai_analysis||(currentSnapshot?.focused_incident_id===selectedCorrelationId?currentSnapshot?.ai_analysis:null);
  if(analysis){output.className='analysis-content';renderAnalysis(analysis,saved?.investigation||currentSnapshot.investigation||[],saved?.ai_warnings||currentSnapshot.ai_warnings||[]);status.textContent=`Saved AI interpretation · ${selectedCorrelationId||'Current scan'}`}
  else{output.className='analysis-content';output.textContent=saved?.ai_error||currentSnapshot?.ai_error||'Deterministic analysis is complete. Select an incident for read-only investigation. AI is optional.';if(saved?.investigation?.length)output.innerHTML+=toolTraceMarkup(saved.investigation);status.textContent=selectedCorrelationId?`Investigating: ${selectedCorrelationId}`:'No incidents. Parsing results and history are still available.'}
}
function syncReportDownload(){const link=document.querySelector('#download-selected-report');link.hidden=!selectedCorrelationId;if(selectedCorrelationId){link.href=`/api/scans/${encodeURIComponent(currentScanId)}/incidents/${encodeURIComponent(selectedCorrelationId)}/report.md`;link.setAttribute('download','')}}
function selectInvestigationIncident(id,syncHypothesis=true){if(!correlationItems.some(i=>i.id===id))return;selectedCorrelationId=id;if(syncHypothesis)HypothesisPanel.chooseIncident(id);renderCorrelations(correlationItems);renderCurrentAnalysis();syncReportDownload()}
async function scanSelectedSample(){
  const button=document.querySelector('#scan-button');
  const output=document.querySelector('#ai-analysis');
  const status=document.querySelector('#copilot-status');
  setWorkflowBusy(true);button.innerHTML='◌ <span>Detecting and analyzing…</span>';
  output.className='analysis-content loading';output.textContent='Detecting and correlating logs. If enabled, local Ollama will assist with read-only investigation…';
  status.textContent='Analysis in progress. Raw log lines are not sent to the model.';
  try{
    const response=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sample:document.querySelector('#sample-select').value,with_ai:document.querySelector('#scan-with-ai').checked,tool_budget:Number(document.querySelector('#tool-budget').value||4)})});
    const result=await response.json();
    if(!response.ok)throw new Error(result.detail||`HTTP ${response.status}`);
    applyScan(result);await refreshHistory();
    const sampleLabel=result.sample;
    if(result.ai_status==='completed'){
      output.className='analysis-content';renderAnalysis(result.ai_analysis,result.investigation||[],result.ai_warnings||[]);
      status.textContent=`Analysis complete · ${sampleLabel} · ${result.event_count} parsed events, ${result.alerts.length} rule alerts, ${result.incidents.length} incidents`;
    }else if(result.ai_status==='skipped'){
      output.className='analysis-content';output.textContent='Detection, the evidence graph, and competing hypotheses are ready. AI was not used. Run a read-only investigation or compare hypotheses with AI.';status.textContent='Observed facts and hypotheses are ready · AI comparison not run';
    }else{
      output.className='analysis-content error';
      output.textContent=`Detection complete: ${result.event_count} parsed events and ${result.alerts.length} alerts.\n\nAI analysis unavailable: ${result.ai_error||'The local model did not respond'}\n\nCheck Ollama or the analysis error, then run detection again.`;
      if(result.investigation?.length)output.innerHTML+=toolTraceMarkup(result.investigation);
      status.textContent=`Rule detection complete · ${sampleLabel} · AI analysis incomplete`;
    }
  }catch(error){
    output.className='analysis-content error';output.textContent=`Unable to complete scan: ${error.message}`;status.textContent='Unable to reach the local API. Make sure the backend is running.';
  }finally{setWorkflowBusy(false);button.innerHTML='⌕ <span>Detect and analyze</span>'}
}
document.querySelector('#scan-button').addEventListener('click',scanSelectedSample);
SecurityGraph.init();
HypothesisPanel.init();
loadDetectedAlerts();

const stageLabels={web_reconnaissance:'Web reconnaissance',credential_attack:'SSH password guessing',suspicious_authentication:'Suspicious successful authentication',web_exploitation_attempt:'Web exploitation attempt'};
function evidenceButton(id){return `<button class="evidence-link" data-evidence="${escapeHtml(id)}">${escapeHtml(id)}</button>`}
function bindEvidence(container){container.querySelectorAll('[data-evidence]').forEach(button=>button.addEventListener('click',()=>showEvidence(button.dataset.evidence)))}
function incidentSources(item){return [...new Set((currentSnapshot?.alerts||[]).filter(a=>item.alert_ids.includes(a.id)).flatMap(a=>(a.related_events||[]).map(e=>e.source)))].join(' / ')}
function renderCorrelations(items){
  const container=document.querySelector('#correlated-incidents');
  container.innerHTML=items.length?items.map(item=>`<article class="incident-card ${item.id===selectedCorrelationId?'selected-context':''}"><div class="title-inline"><span class="severity ${severityClass[item.severity]}">${severityLabel[item.severity]}</span><h3>${escapeHtml(item.title)}</h3></div><p>${escapeHtml(item.source_ips.join(', '))} · ${escapeHtml(item.usernames.join(', ')||'No account information')} · ${item.alert_ids.length} alerts · ${escapeHtml(incidentSources(item))} · ${evidenceButton(item.id)}</p><p>${escapeHtml(item.start_time)} – ${escapeHtml(item.end_time)}</p><div class="context-actions"><button class="incident-context-select" data-select-incident="${escapeHtml(item.id)}">${item.id===selectedCorrelationId?'Selected incident':'Select incident'}</button><a class="report-download" download href="/api/scans/${encodeURIComponent(currentScanId)}/incidents/${encodeURIComponent(item.id)}/report.md">Download Markdown</a></div>${item.id===selectedCorrelationId?`<p>${escapeHtml(item.correlation_reason)}</p><ol class="attack-timeline">${item.timeline.map(entry=>`<li><time>${timeLabel(entry.timestamp)}</time> <b>${escapeHtml(stageLabels[entry.stage]||entry.stage)}</b> ${evidenceButton(entry.alert_id)}<div>${entry.event_ids.map(evidenceButton).join(' ')}</div></li>`).join('')}</ol>`:''}</article>`).join(''):'No rule alerts, so no incidents were created. Parsing results and history remain available.';
  bindEvidence(container);container.querySelectorAll('[data-select-incident]').forEach(button=>{button.disabled=workflowBusy;button.addEventListener('click',()=>selectInvestigationIncident(button.dataset.selectIncident))});
}
function toolTraceMarkup(trace){return `<details><summary>Read-only tool trace (${trace.length} calls)</summary><pre>${escapeHtml(JSON.stringify(trace,null,2))}</pre></details>`}
function renderAnalysis(analysis,trace,warnings=[]){
  const container=document.querySelector('#ai-analysis');
  if(/[\u3400-\u9fff]/.test([analysis.summary,...analysis.assessment.map(c=>c.text),...analysis.recommendations.map(c=>c.text),...analysis.missing_evidence,...(analysis.hypothesis_evaluations||[]).map(h=>h.inference)].join(' '))){container.textContent='This saved AI assessment was generated in the previous language. Run AI comparison again for an English assessment.';return}
  function claims(items){return `<ul>${items.map(claim=>`<li>${escapeHtml(claim.text)}<div>${claim.evidence_ids.map(evidenceButton).join(' ')}</div></li>`).join('')}</ul>`}
  container.innerHTML=`<p class="analysis-confidence">Interpretation limits: attack attempts and successful authentication do not confirm compromise. Verify host and account activity.</p><h3>AI summary (inference)</h3><p>${escapeHtml(analysis.summary)}</p><h3>AI assessment (cited evidence, not new facts)</h3>${claims(analysis.assessment)}<h3>Suggested investigation (read-only)</h3>${claims(analysis.recommendations)}<h3>Missing evidence</h3><ul>${analysis.missing_evidence.map(item=>`<li>${escapeHtml(item)}</li>`).join('')}</ul><p class="analysis-confidence">Model self-rating of analysis completeness: ${Math.round(analysis.confidence*100)}%(not a compromise probability)</p>${warnings.map(note=>`<p class="analysis-confidence">${escapeHtml(note)}</p>`).join('')}${toolTraceMarkup(trace)}`;
  bindEvidence(container);
}
async function showEvidence(id){
  const sequence=++evidenceRequestSequence,scanId=currentScanId;
  const dialog=document.querySelector('#evidence-dialog');
  const content=document.querySelector('#evidence-content');
  content.textContent='Loading scan evidence…';
  if(!dialog.open)dialog.showModal();
  try{
    const response=await fetch(`/api/scans/${encodeURIComponent(scanId)}/evidence/${encodeURIComponent(id)}`);
    if(!response.ok)throw new Error('The evidence snapshot is unavailable. Reopen the scan or scan again.');
    const evidence=await response.json();
    if(sequence===evidenceRequestSequence&&scanId===currentScanId)content.textContent=JSON.stringify(evidence,null,2);
  }catch(error){if(sequence===evidenceRequestSequence)content.textContent=error.message}
}
document.querySelector('#close-evidence').addEventListener('click',()=>document.querySelector('#evidence-dialog').close());

let graphRequestSequence=0;
async function loadEvidenceGraph(scanId){
  const sequence=++graphRequestSequence;
  try{const response=await fetch(`/api/scans/${encodeURIComponent(scanId)}/graph`);if(!response.ok)throw new Error('Evidence graph unavailable');const graph=await response.json();if(sequence===graphRequestSequence&&scanId===currentScanId){SecurityGraph.setData(graph);HypothesisPanel.applyGraphFocus()}}catch(error){if(sequence===graphRequestSequence)document.querySelector('#evidence-graph').textContent=error.message}
}

async function runSelectedIncident(withAI,questionIds=null){
  const incidentId=HypothesisPanel.selectedId(),scanId=currentScanId;
  if(!incidentId||!scanId)return;
  const output=document.querySelector('#ai-analysis'),status=document.querySelector('#copilot-status');
  const button=document.querySelector('#scan-button');
  setWorkflowBusy(true);
  status.textContent=withAI?'Selecting answerable questions, querying evidence, and comparing hypotheses…':'Querying read-only evidence in this scan…';
  try{
    const response=await fetch(`/api/scans/${encodeURIComponent(scanId)}/incidents/${encodeURIComponent(incidentId)}/investigate`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({with_ai:withAI,tool_budget:questionIds?1:Number(document.querySelector('#tool-budget').value||4),question_ids:questionIds})});
    const result=await response.json();
    if(!response.ok)throw new Error(result.detail||'Unable to complete investigation');
    if(scanId!==currentScanId)return;
    HypothesisPanel.replaceReport(result.report);
    const old=currentSnapshot.investigation_results?.[incidentId];currentSnapshot.investigation_results??={};currentSnapshot.investigation_results[incidentId]={...result,ai_analysis:result.ai_analysis||old?.ai_analysis};
    currentSnapshot.hypotheses=currentSnapshot.hypotheses.map(r=>r.incident_id===incidentId?result.report:r);
    if(result.ai_status==='completed'){output.className='analysis-content';renderAnalysis(result.ai_analysis,result.investigation,result.ai_warnings);status.textContent=`Hypothesis comparison complete · ${incidentId} · See investigation status for the stopping reason`}
    else{output.className=result.ai_status==='unavailable'?'analysis-content error':'analysis-content';output.textContent=result.ai_error?`AI comparison incomplete: ${result.ai_error}\nRead-only results and backend hypotheses remain available.`:'Read-only queries completed. Observed facts, competing hypotheses, and missing evidence are shown separately.';output.innerHTML+=toolTraceMarkup(result.investigation);status.textContent='Investigation round stopped · Review question answers and the stopping reason'}
  }catch(error){toast(error.message);status.textContent=error.message}
  finally{setWorkflowBusy(false)}
}

let selectedUploadFiles=[];
document.querySelector('#upload-files').addEventListener('change',event=>{
  selectedUploadFiles=Array.from(event.target.files);document.querySelector('#upload-selection').textContent=selectedUploadFiles.length?`${selectedUploadFiles.length} file(s) selected`:'No files selected';const list=document.querySelector('#upload-file-list');list.replaceChildren();
  selectedUploadFiles.forEach((file,index)=>{const row=document.createElement('div');row.className='import-file';const name=document.createElement('span');name.textContent=`${file.name} · ${file.size} bytes`;const select=document.createElement('select');select.dataset.fileIndex=index;select.setAttribute('aria-label',`${file.name} log type`);for(const [value,label] of [['ssh','SSH authentication'],['nginx','Nginx combined access']]){const option=document.createElement('option');option.value=value;option.textContent=label;select.append(option)}select.value=/access|nginx/i.test(file.name)?'nginx':'ssh';row.append(name,select);list.append(row)});
});
function renderImportFeedback(reports,message=''){
  const box=document.querySelector('#import-feedback');box.innerHTML=message?`<p class="import-feedback-error">${escapeHtml(message)}</p>`:'';
  box.innerHTML+=reports.map(r=>`<article class="import-feedback-item ${escapeHtml(r.status)}"><strong>${escapeHtml(r.filename)} · ${escapeHtml(r.source_type)} · ${escapeHtml({accepted:'Accepted',partial:'Partial success',rejected:'Rejected'}[r.status]||r.status)}</strong><p>${r.line_count} lines · ${r.accepted_lines} accepted · ${r.rejected_lines} skipped · ${r.duplicate_lines} duplicates in file${r.ssh_year?` · SSH year ${r.ssh_year}, timezone ${escapeHtml(r.timezone)}`:''}</p>${r.issues.length?`<details><summary>Parse diagnostics (${r.issues.length} entries${r.issues_omitted?`; ${r.issues_omitted} more omitted`:''})</summary><ul>${r.issues.map(issue=>`<li>${issue.line?'Line '+issue.line:'File'}: ${escapeHtml(issue.reason)}</li>`).join('')}</ul></details>`:''}</article>`).join('');
}
document.querySelector('#upload-button').addEventListener('click',async()=>{
  if(!selectedUploadFiles.length){renderImportFeedback([],'Select log files first.');return}
  const data=new FormData();selectedUploadFiles.forEach((file,index)=>{data.append('files',file);data.append('source_types',document.querySelector(`[data-file-index="${index}"]`).value)});
  data.append('ssh_year',document.querySelector('#ssh-year').value);data.append('with_ai',String(document.querySelector('#scan-with-ai').checked));data.append('tool_budget',document.querySelector('#tool-budget').value);
  setWorkflowBusy(true);document.querySelector('#upload-button').textContent='Importing…';
  try{const response=await fetch('/api/scans/upload',{method:'POST',body:data});const result=await response.json();if(!response.ok){const detail=result.detail;renderImportFeedback(detail?.file_results||[],typeof detail==='string'?detail:detail?.message||JSON.stringify(detail));return}applyScan(result);await refreshHistory();toast('Import complete and saved locally.')}
  catch(error){renderImportFeedback([],`Import failed: ${error.message}`)}
  finally{setWorkflowBusy(false);document.querySelector('#upload-button').textContent='Import and detect'}
});
function renderHistory(){
  const container=document.querySelector('#scan-history');container.replaceChildren();
  if(!historyItems.length){container.textContent='No saved scans yet.';return}
  historyItems.forEach(item=>{const row=document.createElement('div');row.className=`history-row ${item.scan_id===currentScanId?'active':''}`;const info=document.createElement('div'),title=document.createElement('strong'),meta=document.createElement('small');title.textContent=item.sample;meta.textContent=`${new Date(item.created_at).toLocaleString('en-US')} · ${item.source_types.join(' / ')} · ${item.event_count} events / ${item.alert_count} alerts / ${item.incident_count} Incident · ${item.scan_id}`;info.append(title,meta);const open=document.createElement('button');open.className='investigation-action';open.textContent='Open';open.dataset.openScan=item.scan_id;open.disabled=workflowBusy;open.addEventListener('click',()=>openSavedScan(item.scan_id));const remove=document.createElement('button');remove.className='history-delete';remove.textContent='Delete';remove.dataset.deleteScan=item.scan_id;remove.disabled=workflowBusy;remove.addEventListener('click',()=>deleteSavedScan(item.scan_id));row.append(info,open,remove);container.append(row)});
  document.querySelector('#history-more').hidden=historyItems.length>=historyTotal;
}
async function refreshHistory(append=false){const response=await fetch(`/api/scans?limit=20&offset=${append?historyItems.length:0}`);if(!response.ok)throw new Error('Unable to load scan history.');const data=await response.json();historyItems=append?historyItems.concat(data.items):data.items;historyTotal=data.total;renderHistory()}
async function openSavedScan(id){setWorkflowBusy(true);try{const response=await fetch(`/api/scans/${encodeURIComponent(id)}`);if(!response.ok)throw new Error('Scan not found or unavailable.');applyScan(await response.json());toast('Saved scan opened.')}catch(error){toast(error.message)}finally{setWorkflowBusy(false)}}
async function deleteSavedScan(id){
  if(!await confirmScanDeletion())return;
  setWorkflowBusy(true);try{const response=await fetch(`/api/scans/${encodeURIComponent(id)}`,{method:'DELETE'});if(!response.ok)throw new Error('Unable to delete scan.');if(id===currentScanId){currentScanId=null;currentSnapshot=null;correlationItems=[];selectedCorrelationId=null;++evidenceRequestSequence;document.querySelector('#evidence-dialog').close();updateAlerts([]);HypothesisPanel.setData([]);SecurityGraph.setData({nodes:[],edges:[]});renderCorrelations([]);syncReportDownload();document.querySelector('#scan-overview').textContent='The current scan was deleted. Open another saved scan or import logs.';document.querySelector('#stat-events').textContent='—';document.querySelector('#ai-analysis').textContent='No scan selected.';document.querySelector('#copilot-status').textContent='No scan selected.';renderImportFeedback([])}await refreshHistory();toast('Scan deleted.')}catch(error){toast(error.message)}finally{setWorkflowBusy(false)}
}
document.querySelector('#refresh-history').addEventListener('click',()=>refreshHistory().catch(error=>toast(error.message)));
document.querySelector('#history-more').addEventListener('click',()=>refreshHistory(true).catch(error=>toast(error.message)));


document.querySelector('#choose-log-files').addEventListener('click',()=>document.querySelector('#upload-files').click());
function confirmScanDeletion(){
  const dialog=document.querySelector('#delete-scan-dialog');
  if(dialog.open)return Promise.resolve(false);
  return new Promise(resolve=>{
    let answer=false;
    const accept=()=>{answer=true;dialog.close()};
    const cancel=()=>dialog.close();
    const closed=()=>{
      document.querySelector('#confirm-delete-scan').removeEventListener('click',accept);
      document.querySelector('#cancel-delete-scan').removeEventListener('click',cancel);
      resolve(answer);
    };
    document.querySelector('#confirm-delete-scan').addEventListener('click',accept);
    document.querySelector('#cancel-delete-scan').addEventListener('click',cancel);
    dialog.addEventListener('close',closed,{once:true});dialog.showModal();
  });
}
