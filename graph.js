/* Scan-local graph: SVG labels use textContent; evidence stays in the existing API. */
window.SecurityGraph=(()=>{
  let graph={nodes:[],edges:[]},scope=null,overlay=null;
  const ns='http://www.w3.org/2000/svg';
  const types={ip:'來源 IP',event:'事件',endpoint:'HTTP 端點',user:'帳號',alert:'告警',incident:'Incident'};
  const relations={GENERATED:'來源記錄',TARGETED:'針對帳號',REQUESTED:'請求',AUTHENTICATED_AS:'成功驗證',SUPPORTED_BY:'證據支持',CONTAINS:'群組成員',FOLLOWED_BY:'時間先後',POSSIBLE_ATTACK_PROGRESSION:'可能進展'};
  const el=id=>document.getElementById(id);
  function svgNode(tag,attrs={},text){const n=document.createElementNS(ns,tag);Object.entries(attrs).forEach(([key,value])=>n.setAttribute(key,String(value)));if(text!==undefined)n.textContent=text;return n}
  function scopedNodes(){
    if(!scope)return new Set(graph.nodes.map(n=>n.id));
    const incident=graph.nodes.find(n=>n.id===scope);
    if(!incident)return new Set();
    const ids=new Set([scope,...(incident.properties.alert_ids||[])]);
    graph.edges.forEach(e=>{if(e.relation==='SUPPORTED_BY'&&ids.has(e.source))ids.add(e.target)});
    if(overlay)[...(overlay.supporting_evidence_ids||[]),...(overlay.contradicting_evidence_ids||[]),...(overlay.neutral_evidence_ids||[]),...(overlay.inference_evidence_ids||[])].forEach(id=>{if(graph.nodes.some(node=>node.id===id))ids.add(id)});
    const base=new Set(ids);
    graph.edges.forEach(e=>{if(base.has(e.source))ids.add(e.target);if(base.has(e.target))ids.add(e.source)});
    return ids;
  }
  function classify(edge){if(!overlay)return '';if(overlay.supporting_edge_ids?.includes(edge.id))return 'supporting';if(overlay.contradicting_edge_ids?.includes(edge.id))return 'contradicting';if(overlay.neutral_edge_ids?.includes(edge.id))return 'neutral';if(edge.evidence_ids.some(id=>overlay.supporting_evidence_ids?.includes(id)))return 'supporting';if(edge.evidence_ids.some(id=>overlay.contradicting_evidence_ids?.includes(id)))return 'contradicting';return 'dimmed'}
  function inspect(item,isEdge){
    const panel=el('graph-inspector');panel.replaceChildren();
    const heading=document.createElement('h3');heading.textContent=isEdge?`${relations[item.relation]||item.relation} · ${item.edge_type==='observed'?'觀察／記錄關係':'推論關係'}`:`${types[item.node_type]} · ${item.label}`;panel.append(heading);
    if(!isEdge&&['event','alert','incident'].includes(item.node_type)){const button=document.createElement('button');button.className='evidence-link';button.textContent='開啟原始證據';button.addEventListener('click',()=>showEvidence(item.id));panel.append(button)}
    if(isEdge){const note=document.createElement('p');note.textContent=(item.reasons||[]).join('；')+(item.confidence===null?'':` · 關係支持分數 ${item.confidence}（非入侵機率）`);panel.append(note);item.evidence_ids.forEach(id=>{const button=document.createElement('button');button.className='evidence-link';button.textContent=id;button.addEventListener('click',()=>showEvidence(id));panel.append(button)})}
    const detail=document.createElement('pre');detail.textContent=JSON.stringify(isEdge?item:item.properties,null,2);panel.append(detail);
  }
  function render(){
    const container=el('evidence-graph');if(!container)return;
    container.replaceChildren();const ids=scopedNodes(),showEvents=el('graph-events').checked,showInferred=el('graph-inferred').checked;
    const nodes=graph.nodes.filter(n=>ids.has(n.id)&&(showEvents||n.node_type!=='event'));
    const visible=new Set(nodes.map(n=>n.id));const edges=graph.edges.filter(e=>visible.has(e.source)&&visible.has(e.target)&&(showInferred||e.edge_type==='observed'));
    el('graph-count').textContent=`${nodes.length} 個節點 · ${edges.length} 條關係`;
    if(!nodes.length){container.textContent='目前掃描沒有可顯示的圖形資料。';return}
    const columns=[['ip'],['event'],['endpoint','user'],['alert'],['incident']];
    // Collapse the empty event column in the overview.
    const active=columns.filter(column=>nodes.some(n=>column.includes(n.node_type)));
    const height=Math.max(300,...active.map(column=>nodes.filter(n=>column.includes(n.node_type)).length*66+90));
    const width=active.length*240+50,positions=new Map();
    active.forEach((column,index)=>{const list=nodes.filter(n=>column.includes(n.node_type)).sort((a,b)=>a.label.localeCompare(b.label)||a.id.localeCompare(b.id));list.forEach((n,row)=>positions.set(n.id,{x:index*240+25,y:70+row*66}))});
    const zoom=Number(el('graph-zoom').value||100)/100;
    const svg=svgNode('svg',{viewBox:`0 0 ${width} ${height}`,width:width*zoom,height:height*zoom,role:'group','aria-label':'掃描證據圖：實線為觀察或記錄關係，虛線為推論'});
    const defs=svgNode('defs'),marker=svgNode('marker',{id:'graph-arrow',viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:6,markerHeight:6,orient:'auto-start-reverse'});marker.append(svgNode('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:'#90a5bd'}));defs.append(marker);svg.append(defs);
    active.forEach((column,index)=>svg.append(svgNode('text',{x:index*240+25,y:30,class:'graph-column'},column.map(t=>types[t]).join(' / '))));
    edges.forEach(edge=>{const a=positions.get(edge.source),b=positions.get(edge.target),forward=b.x>a.x;const sx=forward?a.x+180:a.x,tx=forward?b.x:b.x+180;const sy=a.y+20,ty=b.y+20,curve=forward?(sx+tx)/2:Math.max(sx,tx)+65;const path=svgNode('path',{d:`M ${sx} ${sy} C ${curve} ${sy} ${curve} ${ty} ${tx} ${ty}`,class:`graph-edge ${edge.edge_type} ${classify(edge)}`,'marker-end':'url(#graph-arrow)',tabindex:0,role:'button','aria-label':`${relations[edge.relation]||edge.relation} ${edge.edge_type}`});path.append(svgNode('title',{},`${relations[edge.relation]||edge.relation} · ${edge.edge_type} · ${(edge.reasons||[]).join('；')}`));path.addEventListener('click',()=>inspect(edge,true));path.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();inspect(edge,true)}});svg.append(path)});
    function nodeFocus(id){if(!overlay)return '';const states=edges.filter(e=>e.source===id||e.target===id).map(classify);return ['contradicting','supporting','neutral'].find(state=>states.includes(state))||'dimmed'}
    nodes.forEach(node=>{const p=positions.get(node.id);const group=svgNode('g',{transform:`translate(${p.x},${p.y})`,class:`graph-node ${node.node_type} ${nodeFocus(node.id)}`,tabindex:0,role:'button','aria-label':`${types[node.node_type]} ${node.label}`});group.append(svgNode('rect',{width:180,height:42,rx:7}));group.append(svgNode('text',{x:9,y:17,class:'graph-node-kind'},types[node.node_type]));const label=node.node_type==='event'?`${node.properties.timestamp?.slice(11,19)||''} ${node.properties.username||node.properties.request_target||node.label}`:node.label;group.append(svgNode('text',{x:9,y:32,class:'graph-node-label'},label.length>21?label.slice(0,20)+'…':label));group.append(svgNode('title',{},`${node.label} · ${node.id}`));const click=()=>{inspect(node,false);if(['event','alert','incident'].includes(node.node_type))showEvidence(node.id)};group.addEventListener('click',click);group.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();click()}});svg.append(group)});
    container.append(svg);
  }
  function setData(data){graph=data||{nodes:[],edges:[]};overlay=null;el('graph-overlay').textContent='未選擇假說';el('graph-inspector').textContent='點選節點或關係查看說明。';const incidents=graph.nodes.filter(n=>n.node_type==='incident');const select=el('graph-scope');select.replaceChildren();const all=document.createElement('option');all.value='';all.textContent='整份掃描';select.append(all);incidents.forEach(n=>{const option=document.createElement('option');option.value=n.id;option.textContent=`${n.properties.source_ips?.join(', ')||''} · ${n.id}`;select.append(option)});scope=incidents[0]?.id||null;select.value=scope||'';render()}
  function highlight(hypothesis){overlay=hypothesis;scope=hypothesis?.incident_id||scope;el('graph-scope').value=scope||'';el('graph-overlay').textContent=hypothesis?`假說焦點：${hypothesis.title}`:'未選擇假說';render()}
  function selectScope(id){scope=id;overlay=null;el('graph-scope').value=id||'';el('graph-overlay').textContent='未選擇假說';render()}
  function init(){['graph-events','graph-inferred','graph-zoom'].forEach(id=>el(id).addEventListener('input',render));el('graph-scope').addEventListener('change',event=>{scope=event.target.value||null;overlay=null;el('graph-overlay').textContent='未選擇假說';render()});el('graph-clear').addEventListener('click',()=>{overlay=null;el('graph-overlay').textContent='未選擇假說';render()})}
  return {init,setData,highlight,selectScope};
})();
