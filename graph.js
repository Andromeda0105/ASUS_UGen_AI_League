/* Scan-local graph: SVG labels use textContent; evidence stays in the existing API. */
window.SecurityGraph=(()=>{
  let graph={nodes:[],edges:[]},scope=null,overlay=null;
  const ns='http://www.w3.org/2000/svg';
  const types={ip:'Source IP',event:'Event',endpoint:'HTTP endpoint',user:'Account',alert:'Alert',incident:'Incident'};
  const relations={GENERATED:'Recorded source',TARGETED:'Targeted account',REQUESTED:'Request',AUTHENTICATED_AS:'Successful authentication',SUPPORTED_BY:'Evidence support',CONTAINS:'Group membership',FOLLOWED_BY:'Time order',POSSIBLE_ATTACK_PROGRESSION:'Possible progression'};
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
    const heading=document.createElement('h3');heading.textContent=isEdge?`${relations[item.relation]||item.relation} · ${item.edge_type==='observed'?'Observed / recorded relationship':'Inferred relationship'}`:`${types[item.node_type]} · ${item.label}`;panel.append(heading);
    if(!isEdge&&['event','alert','incident'].includes(item.node_type)){const button=document.createElement('button');button.className='evidence-link';button.textContent='Open original evidence';button.addEventListener('click',()=>showEvidence(item.id));panel.append(button)}
    if(isEdge){const note=document.createElement('p');note.textContent=(item.reasons||[]).join('; ')+(item.confidence===null?'':` · Relationship support score ${item.confidence}(not a compromise probability)`);panel.append(note);item.evidence_ids.forEach(id=>{const button=document.createElement('button');button.className='evidence-link';button.textContent=id;button.addEventListener('click',()=>showEvidence(id));panel.append(button)})}
    const detail=document.createElement('pre');detail.textContent=JSON.stringify(isEdge?item:item.properties,null,2);panel.append(detail);
  }
  function render(){
    const container=el('evidence-graph');if(!container)return;
    container.replaceChildren();const ids=scopedNodes(),showEvents=el('graph-events').checked,showInferred=el('graph-inferred').checked;
    const nodes=graph.nodes.filter(n=>ids.has(n.id)&&(showEvents||n.node_type!=='event'));
    const visible=new Set(nodes.map(n=>n.id));const edges=graph.edges.filter(e=>visible.has(e.source)&&visible.has(e.target)&&(showInferred||e.edge_type==='observed'));
    el('graph-count').textContent=`${nodes.length} nodes · ${edges.length} edges`;
    if(!nodes.length){container.textContent='No graph data to display for this scan.';return}
    const columns=[['ip'],['event'],['endpoint','user'],['alert'],['incident']];
    // Collapse the empty event column in the overview.
    const active=columns.filter(column=>nodes.some(n=>column.includes(n.node_type)));
    const height=Math.max(300,...active.map(column=>nodes.filter(n=>column.includes(n.node_type)).length*66+90));
    const width=active.length*240+50,positions=new Map();
    active.forEach((column,index)=>{const list=nodes.filter(n=>column.includes(n.node_type)).sort((a,b)=>a.label.localeCompare(b.label)||a.id.localeCompare(b.id));list.forEach((n,row)=>positions.set(n.id,{x:index*240+25,y:70+row*66}))});
    const zoom=Number(el('graph-zoom').value||100)/100;
    const svg=svgNode('svg',{viewBox:`0 0 ${width} ${height}`,width:width*zoom,height:height*zoom,role:'group','aria-label':'Scan evidence graph: solid edges are observed or recorded; dashed edges are inferred'});
    const defs=svgNode('defs'),marker=svgNode('marker',{id:'graph-arrow',viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:6,markerHeight:6,orient:'auto-start-reverse'});marker.append(svgNode('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:'#90a5bd'}));defs.append(marker);svg.append(defs);
    active.forEach((column,index)=>svg.append(svgNode('text',{x:index*240+25,y:30,class:'graph-column'},column.map(t=>types[t]).join(' / '))));
    edges.forEach(edge=>{const a=positions.get(edge.source),b=positions.get(edge.target),forward=b.x>a.x;const sx=forward?a.x+180:a.x,tx=forward?b.x:b.x+180;const sy=a.y+20,ty=b.y+20,curve=forward?(sx+tx)/2:Math.max(sx,tx)+65;const path=svgNode('path',{d:`M ${sx} ${sy} C ${curve} ${sy} ${curve} ${ty} ${tx} ${ty}`,class:`graph-edge ${edge.edge_type} ${classify(edge)}`,'marker-end':'url(#graph-arrow)',tabindex:0,role:'button','aria-label':`${relations[edge.relation]||edge.relation} ${edge.edge_type}`});path.append(svgNode('title',{},`${relations[edge.relation]||edge.relation} · ${edge.edge_type} · ${(edge.reasons||[]).join('; ')}`));path.addEventListener('click',()=>inspect(edge,true));path.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();inspect(edge,true)}});svg.append(path)});
    function nodeFocus(id){if(!overlay)return '';const states=edges.filter(e=>e.source===id||e.target===id).map(classify);return ['contradicting','supporting','neutral'].find(state=>states.includes(state))||'dimmed'}
    nodes.forEach(node=>{const p=positions.get(node.id);const group=svgNode('g',{transform:`translate(${p.x},${p.y})`,class:`graph-node ${node.node_type} ${nodeFocus(node.id)}`,tabindex:0,role:'button','aria-label':`${types[node.node_type]} ${node.label}`});group.append(svgNode('rect',{width:180,height:42,rx:7}));group.append(svgNode('text',{x:9,y:17,class:'graph-node-kind'},types[node.node_type]));const label=node.node_type==='event'?`${node.properties.timestamp?.slice(11,19)||''} ${node.properties.username||node.properties.request_target||node.label}`:node.label;group.append(svgNode('text',{x:9,y:32,class:'graph-node-label'},label.length>21?label.slice(0,20)+'…':label));group.append(svgNode('title',{},`${node.label} · ${node.id}`));const click=()=>{inspect(node,false);if(['event','alert','incident'].includes(node.node_type))showEvidence(node.id)};group.addEventListener('click',click);group.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();click()}});svg.append(group)});
    container.append(svg);
  }
  function setData(data){graph=data||{nodes:[],edges:[]};overlay=null;el('graph-overlay').textContent='No hypothesis selected';el('graph-inspector').textContent='Select a node or edge to view details.';const incidents=graph.nodes.filter(n=>n.node_type==='incident');const select=el('graph-scope');select.replaceChildren();const all=document.createElement('option');all.value='';all.textContent='Entire scan';select.append(all);incidents.forEach(n=>{const option=document.createElement('option');option.value=n.id;option.textContent=`${n.properties.source_ips?.join(', ')||''} · ${n.id}`;select.append(option)});scope=incidents[0]?.id||null;select.value=scope||'';render()}
  function highlight(hypothesis){overlay=hypothesis;scope=hypothesis?.incident_id||scope;el('graph-scope').value=scope||'';el('graph-overlay').textContent=hypothesis?`Hypothesis focus: ${hypothesis.title}`:'No hypothesis selected';render()}
  function selectScope(id){scope=id;overlay=null;el('graph-scope').value=id||'';el('graph-overlay').textContent='No hypothesis selected';render()}
  function init(){['graph-events','graph-inferred','graph-zoom'].forEach(id=>el(id).addEventListener('input',render));el('graph-scope').addEventListener('change',event=>{scope=event.target.value||null;overlay=null;el('graph-overlay').textContent='No hypothesis selected';render();if(scope)selectInvestigationIncident(scope)});el('graph-clear').addEventListener('click',()=>{overlay=null;el('graph-overlay').textContent='No hypothesis selected';render()})}
  return {init,setData,highlight,selectScope};
})();
