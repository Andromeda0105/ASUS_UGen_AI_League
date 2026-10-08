/* Trusted facts and competing explanations are rendered separately from model inference. */
window.HypothesisPanel=(()=>{
  let reports=[],selectedIncident=null,selectedHypothesis=null,busy=false;
  const el=id=>document.getElementById(id);
  const statuses={plausible:'合理但未驗證',supported:'有證據支持',weak:'支持較弱',contradicted:'有反駁證據',insufficient_evidence:'證據不足'};
  const stops={not_run:'尚未調查',all_answerable_checked:'可回答問題已完成',tool_budget_exhausted:'工具預算已用盡',unavailable_telemetry:'需要未提供的遙測',no_new_distinguishing_evidence:'沒有新的區分證據',iteration_limit:'已達單輪查詢上限'};
  function refs(ids){return ids.length?ids.map(evidenceButton).join(' '):'<span class="no-evidence">目前沒有這類直接證據</span>'}
  function current(){return reports.find(r=>r.incident_id===selectedIncident)}
  function setBusy(value){busy=value;document.querySelectorAll('.investigation-action').forEach(button=>{button.disabled=busy||button.dataset.unavailable==='true'})}
  function applyGraphFocus(){const report=current();if(!report)return;const h=report.hypotheses.find(h=>h.id===selectedHypothesis);if(h)SecurityGraph.highlight(h);else SecurityGraph.selectScope(report.incident_id)}
  function render(){
    const report=current(),container=el('hypothesis-cards');
    el('read-investigate').dataset.unavailable=el('ai-investigate').dataset.unavailable=String(!report);
    if(!report){container.textContent='目前沒有 Incident；一般流量不會被強行產生攻擊假說。';el('observed-facts').replaceChildren();el('investigation-questions').replaceChildren();el('investigation-stop').textContent='';el('missing-evidence').replaceChildren();setBusy(busy);return}
    el('observed-facts').innerHTML=`<h3>觀察事實（後端從日誌建立）</h3><ul>${report.observed_facts.map(f=>`<li>${escapeHtml(f.text)}<div>${refs(f.evidence_ids)}</div></li>`).join('')}</ul>`;
    container.innerHTML=report.hypotheses.map(h=>`<article class="hypothesis-card ${h.id===selectedHypothesis?'focused':''}"><button class="hypothesis-select" data-hypothesis="${escapeHtml(h.id)}"><strong>${escapeHtml(h.title)}</strong><span class="hypothesis-status ${h.status}">${escapeHtml(statuses[h.status]||h.status)}</span><b>證據支持分數 ${h.confidence.toFixed(2)}</b></button><p>${escapeHtml(h.description)}</p><small>${h.confidence_origin==='rule'?'規則初始評估':'AI 比較，受證據上限約束'} · 非入侵機率</small><details><summary>支持／反駁／中性證據</summary><h4>支持（可與此解釋相容，不代表證明）</h4>${refs(h.supporting_evidence_ids)}<h4>反駁</h4>${refs(h.contradicting_evidence_ids)}<h4>中性</h4>${refs(h.neutral_evidence_ids)}</details><h4>缺少證據</h4><ul>${h.missing_evidence.map(v=>`<li>${escapeHtml(v)}</li>`).join('')}</ul><h4>推論（未驗證）</h4><p>${escapeHtml(h.inference)}</p>${refs(h.inference_evidence_ids||[])}</article>`).join('');
    container.querySelectorAll('[data-hypothesis]').forEach(button=>button.addEventListener('click',()=>{selectedHypothesis=button.dataset.hypothesis;render();applyGraphFocus()}));
    el('missing-evidence').innerHTML=`<h3>目前仍無法區分</h3><p>${escapeHtml(report.uncertainty)}</p><ul>${report.missing_evidence.map(v=>`<li>${escapeHtml(v)}</li>`).join('')}</ul>`;
    el('investigation-questions').innerHTML=`<h3>調查問題</h3>${report.questions.map(q=>`<article class="question-row"><div><strong>${escapeHtml(q.question)}</strong><small>${q.answerable?'可由本次樣本查詢':'缺少 '+escapeHtml(q.evidence_type)+' 遙測'}</small><p>${escapeHtml(q.answer||'尚未查詢')}</p>${q.evidence_ids.length?refs(q.evidence_ids):''}${q.truncated?'<p class="query-truncated">回傳結果已截斷，不能當成完整活動。</p>':''}</div><button class="investigation-action" data-question="${escapeHtml(q.id)}" data-unavailable="${!q.answerable||q.status==='answered'}">${!q.answerable?'資料未提供':q.status==='answered'?'已查證':'唯讀查詢'}</button></article>`).join('')}`;
    el('investigation-questions').querySelectorAll('[data-question]').forEach(button=>button.addEventListener('click',()=>runSelectedIncident(false,[button.dataset.question])));
    el('investigation-stop').innerHTML=`<h3>調查狀態：${escapeHtml(stops[report.stop_reason]||report.stop_reason)}</h3><p>${escapeHtml(report.stop_explanation)}</p><p>本輪 ${report.tool_calls} / ${report.tool_budget} 次工具呼叫 · ${report.iteration_count} / 1 輪查詢</p><p>${escapeHtml(report.confidence_note)}</p>`;
    [container,el('observed-facts'),el('investigation-questions')].forEach(bindEvidence);
    setBusy(busy);
  }
  function setData(data,preferred){reports=data||[];selectedIncident=reports.some(r=>r.incident_id===preferred)?preferred:(reports.some(r=>r.incident_id===selectedIncident)?selectedIncident:reports[0]?.incident_id||null);selectedHypothesis=null;const select=el('hypothesis-incident');select.replaceChildren();reports.forEach(report=>{const option=document.createElement('option');option.value=report.incident_id;option.textContent=report.incident_id;select.append(option)});select.value=selectedIncident||'';render();applyGraphFocus()}
  function replaceReport(report){reports=reports.map(r=>r.incident_id===report.incident_id?report:r);selectedIncident=report.incident_id;el('hypothesis-incident').value=selectedIncident;render();applyGraphFocus()}
  function init(){el('hypothesis-incident').addEventListener('change',event=>{selectedIncident=event.target.value;selectedHypothesis=null;render();applyGraphFocus()});el('read-investigate').addEventListener('click',()=>runSelectedIncident(false));el('ai-investigate').addEventListener('click',()=>runSelectedIncident(true));render()}
  return {init,setData,replaceReport,setBusy,applyGraphFocus,selectedId:()=>selectedIncident};
})();
