let incidents=[];

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
  const panel=document.querySelector('#detail-panel');
  const requestFields=item.requestTarget
    ? `<div class="field"><small>HTTP Request</small><b>${item.requestMethod} ${item.requestTarget}</b></div><div class="field"><small>HTTP 狀態碼</small><b>${item.statusCode}</b></div>`
    : `<div class="field"><small>相關帳號</small><b>${item.user}</b></div><div class="field"><small>活動摘要</small><b>${item.count}</b></div>`;
  panel.innerHTML=`<div class="detail-top"><span>${item.id} · ${item.age}</span><button class="close-detail" aria-label="關閉詳情">×</button></div><span class="detail-severity ${severityClass[item.severity]}">${severityLabel[item.severity]}風險</span><h2>${item.title}</h2><p class="detail-summary">${item.summary}</p><div class="detail-status-row"><span>事件狀態</span><button id="status-toggle">${statusLabel[item.status]}　⌄</button></div><section class="detail-section"><h3>事件資訊</h3><div class="detail-fields"><div class="field"><small>來源 IP</small><b class="mono">${item.ip}</b></div><div class="field"><small>日誌來源</small><b>${item.source}</b></div>${requestFields}</div></section><section class="detail-section"><h3>原始日誌</h3><div class="detail-box">${item.raw}</div></section><section class="detail-section"><h3>建議檢查</h3><div class="recommendation">${item.recommendation}</div></section><div class="detail-actions"><button class="primary" id="resolve-button">${item.status==='Resolved'?'重新開啟事件':'標記為已解決'}</button><button id="copy-button">複製事件 ID</button></div>`;
  panel.querySelector('.close-detail').addEventListener('click',()=>{selectedId=null;panel.innerHTML='<div class="detail-empty"><span class="detail-empty-icon">⌁</span><b>選取一個安全事件</b><p>查看事件摘要、原始日誌及建議處置。</p></div>';renderRows()});
  panel.querySelector('#resolve-button').addEventListener('click',()=>{item.status=item.status==='Resolved'?'Open':'Resolved';renderSummary();selectIncident(id);toast(item.status==='Resolved'?'事件已標記為已解決':'事件已重新開啟')});
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
    summary:escapeHtml(alert.summary),raw:escapeHtml(lastEvent?.raw_log||''),
    recommendation:escapeHtml(alert.recommendation),
  };
})}
function updateAlerts(alerts){incidents=mapAlerts(alerts);selectedId=null;renderRows();renderSummary();document.querySelector('#show-all').hidden=incidents.length<=5;document.querySelector('#detail-panel').innerHTML='<div class="detail-empty"><span class="detail-empty-icon">⌁</span><b>選取一個安全事件</b><p>查看事件摘要、原始日誌及建議處置。</p></div>'}
async function loadDetectedAlerts(){
  try{
    const [alertsResponse,samplesResponse,ollamaResponse,eventsResponse]=await Promise.all([
      fetch('/api/alerts'),fetch('/api/samples'),fetch('/api/ollama/status'),fetch('/api/events')
    ]);
    if(alertsResponse.ok)updateAlerts(await alertsResponse.json());
    if(eventsResponse.ok){const events=await eventsResponse.json();document.querySelector('#stat-events').textContent=events.length;document.querySelector('#event-count-foot').textContent='預設樣本解析筆數'}
    if(samplesResponse.ok){
      const samples=await samplesResponse.json();
      document.querySelector('#sample-select').innerHTML=samples.map(sample=>`<option value="${escapeHtml(sample.name)}">${escapeHtml(sample.label)}</option>`).join('');
    }
    if(ollamaResponse.ok){
      const state=await ollamaResponse.json();
      document.querySelector('#model-label').textContent=state.available?`${state.model} · 本機就緒`:`${state.model} · 尚未連線`;
      document.querySelector('.local-pill').classList.toggle('offline',!state.available);
    }
    document.querySelector('.demo-badge').innerHTML='<i></i>本機 API · 示範資料';
  }catch(error){console.info('Local API unavailable:',error.message)}
}
async function scanSelectedSample(){
  const button=document.querySelector('#scan-button');
  const output=document.querySelector('#ai-analysis');
  const status=document.querySelector('#copilot-status');
  button.disabled=true;button.innerHTML='◌ <span>正在偵測與分析…</span>';
  output.className='analysis-content loading';output.textContent='規則引擎正在分析 SSH 事件，接著會呼叫本機 Ollama…';
  status.textContent='分析工作進行中；日誌原文不會送入模型。';
  try{
    const response=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sample:document.querySelector('#sample-select').value,with_ai:true})});
    const result=await response.json();
    if(!response.ok)throw new Error(result.detail||`HTTP ${response.status}`);
    updateAlerts(result.alerts);
    document.querySelector('#stat-events').textContent=result.event_count;
    document.querySelector('#event-count-foot').textContent='目前樣本解析筆數';
    const sampleLabel=document.querySelector('#sample-select').selectedOptions[0]?.textContent||result.sample;
    if(result.ai_status==='completed'){
      output.className='analysis-content';output.textContent=result.ai_analysis;
      status.textContent=`分析完成 · ${sampleLabel} · ${result.event_count} 筆解析事件、${result.alerts.length} 個規則告警`;
    }else{
      output.className='analysis-content error';
      output.textContent=`偵測完成，共解析 ${result.event_count} 筆事件、產生 ${result.alerts.length} 個告警。\n\nAI 分析暫不可用：${result.ai_error||'本機模型未回應'}\n\n啟動 Ollama 後可重新按「偵測並分析」。`;
      status.textContent=`規則偵測完成 · ${sampleLabel} · AI 尚未連線`;
    }
  }catch(error){
    output.className='analysis-content error';output.textContent=`無法完成掃描：${error.message}`;status.textContent='本機 API 無法連線，請確認後端服務已啟動。';
  }finally{button.disabled=false;button.innerHTML='⌕ <span>偵測並分析</span>'}
}
document.querySelector('#scan-button').addEventListener('click',scanSelectedSample);
loadDetectedAlerts();
