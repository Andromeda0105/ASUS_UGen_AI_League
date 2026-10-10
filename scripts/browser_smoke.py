import json
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.request import Request, urlopen
import uvicorn
from fastapi import Request as FastAPIRequest
from fastapi.responses import HTMLResponse, FileResponse
from app.main import app, ROOT

work = Path(tempfile.mkdtemp(prefix='copilot-browser-',dir='/tmp'))
result_path = work/'result.json'
os.environ['COPILOT_DB_PATH']=str(work/'browser.sqlite3')
from app.main import SCANS
SCANS.clear()
script = r'''
(async()=>{
const results=[];function check(name,ok){if(!ok)throw new Error(name);results.push(name)};
async function waitFor(test){for(let n=0;n<150;n++){if(test())return;await new Promise(resolve=>setTimeout(resolve,100))}throw new Error('timeout')}
try{
await waitFor(()=>!!currentScanId&&document.querySelectorAll('.hypothesis-card').length===3);
const scanResponse=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({with_ai:false})});
const scan=await scanResponse.json();currentScanId=scan.scan_id;
const graph=await (await fetch(`/api/scans/${scan.scan_id}/graph`)).json();
SecurityGraph.setData(graph);HypothesisPanel.setData(scan.hypotheses,scan.focused_incident_id);
check('3 competing hypotheses',document.querySelectorAll('.hypothesis-card').length===3);
check('observed facts separated',document.querySelector('#observed-facts').textContent.includes('Observed facts'));
check('graph overview nodes',document.querySelectorAll('.graph-node').length===10);
check('2 inferred edges',document.querySelectorAll('.graph-edge.inferred').length===2);
document.querySelector('[data-hypothesis]').click();
check('hypothesis overlay',document.querySelector('#graph-overlay').textContent.includes('H1'));
check('supporting edges',document.querySelectorAll('.graph-edge.supporting').length>0);
document.querySelector('#graph-inferred').checked=false;document.querySelector('#graph-inferred').dispatchEvent(new Event('input'));
check('inferred filter',document.querySelectorAll('.graph-edge.inferred').length===0);
document.querySelector('#graph-inferred').checked=true;document.querySelector('#graph-events').checked=true;document.querySelector('#graph-events').dispatchEvent(new Event('input'));
check('all 20 nodes',document.querySelectorAll('.graph-node').length===20);
document.querySelector('.graph-node.alert').dispatchEvent(new MouseEvent('click',{bubbles:true}));
await waitFor(()=>document.querySelector('#evidence-content').textContent.includes('raw_log'));
check('node opens original evidence',document.querySelector('#evidence-dialog').open);
document.querySelector('#close-evidence').click();
document.querySelector('#read-investigate').click();
await waitFor(()=>!document.querySelector('#scan-button').disabled&&document.querySelector('#investigation-stop').textContent.includes('Additional telemetry required'));
check('bounded read-only investigation',document.querySelector('#investigation-stop').textContent.includes('3 / 4'));
check('questions answered',Array.from(document.querySelectorAll('[data-question]')).filter(b=>b.textContent==='Checked').length===3);
check('missing evidence explicit',document.querySelector('#missing-evidence').textContent.includes('cannot distinguish'));
const poisoned=structuredClone(graph);poisoned.nodes.find(n=>n.node_type==='ip').label='<img src=x onerror="window.__graphInjected=true">';
SecurityGraph.setData(poisoned);
check('graph labels are text',!document.querySelector('#evidence-graph img')&&!window.__graphInjected);
const reports=structuredClone(scan.hypotheses);reports[0].hypotheses[0].description='<script>window.__hypInjected=true<\/script>';
HypothesisPanel.setData(reports,scan.focused_incident_id);
check('hypothesis strings escaped',!document.querySelector('#hypothesis-cards script')&&!window.__hypInjected);
SecurityGraph.setData(graph);HypothesisPanel.setData(scan.hypotheses,scan.focused_incident_id);

// Complete the MVP workflow through dashboard controls.
const fixtures=await (await fetch('/__fixtures')).json();
const transfer=new DataTransfer();
transfer.items.add(new File([fixtures.nginx], 'my_access.log', {type:'text/plain'}));
transfer.items.add(new File([fixtures.ssh+'malformed line\n'], 'my_auth.log', {type:'text/plain'}));
const input=document.querySelector('#upload-files');input.files=transfer.files;input.dispatchEvent(new Event('change'));
document.querySelector('#ssh-year').value='2026';document.querySelector('#scan-with-ai').checked=false;
const oldScan=currentScanId;document.querySelector('#upload-button').click();
await waitFor(()=>currentScanId!==oldScan&&!workflowBusy);
check('UI imports two custom logs',document.querySelector('#stat-events').textContent==='10');
check('UI shows line-number diagnostics',document.querySelector('#import-feedback').textContent.includes('Line 7'));
check('incident context selected',document.querySelectorAll('.selected-context').length===1&&HypothesisPanel.selectedId()===selectedCorrelationId);
const reportLink=document.querySelector('#download-selected-report');
check('report action available',!reportLink.hidden);
const markdown=await (await fetch(reportLink.href)).text();
check('offline Markdown download',markdown.includes('Incident investigation report')&&markdown.includes('No AI assessment available'));
document.querySelector('[data-question]:not([data-unavailable="true"])').click();
await waitFor(()=>!workflowBusy&&document.querySelector('#investigation-stop').textContent.includes('1 / 1'));
check('UI selected question obeys budget',document.querySelector('#investigation-stop').textContent.includes('1 / 1'));
const importedId=currentScanId;
check('import persisted in history',!!document.querySelector(`[data-open-scan="${importedId}"]`));
await openSavedScan(scan.scan_id);await openSavedScan(importedId);
check('reopen preserves answered question',Array.from(document.querySelectorAll('[data-question]')).some(b=>b.textContent==='Checked'));
const deletion=deleteSavedScan(importedId);await waitFor(()=>document.querySelector('#delete-scan-dialog').open);document.querySelector('#confirm-delete-scan').click();await deletion;
check('delete clears current workspace',currentScanId===null&&document.querySelector('#scan-overview').textContent.includes('was deleted'));
check('other history scan remains',!!document.querySelector(`[data-open-scan="${scan.scan_id}"]`));
await openSavedScan(scan.scan_id);
check('remaining scan reopens',currentScanId===scan.scan_id);
await fetch('/__ui-result',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ok:true,results})});
}catch(error){await fetch('/__ui-result',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ok:false,error:error.message,stack:error.stack,results})})}
})();
'''
(work/'test.js').write_text(script)
@app.get('/__fixtures',include_in_schema=False)
async def fixtures():
    directory=ROOT/'samples/scenarios'
    return {'nginx':(directory/'multi_stage_access.log').read_text(),'ssh':(directory/'multi_stage_auth.log').read_text()}
@app.get('/__ui-test',include_in_schema=False)
async def harness():
    page=(ROOT/'index.html').read_text().replace('</body>','<script src="/__ui-test.js"></script></body>')
    # Isolate the local UI test from third-party font downloads.
    page='\n'.join(line for line in page.splitlines() if 'fonts.googleapis.com' not in line and 'fonts.gstatic.com' not in line)
    return HTMLResponse(page)
@app.get('/__ui-test.js',include_in_schema=False)
async def test_js():
    return FileResponse(work/'test.js',media_type='application/javascript')
@app.post('/__ui-result',include_in_schema=False)
async def captured(request:FastAPIRequest):
    result_path.write_text(json.dumps(await request.json()))
    return {'ok':True}
with socket.socket() as sock:
    sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,log_level='warning'))
thread=threading.Thread(target=server.run,daemon=True);thread.start()
for _ in range(100):
    if server.started:break
    time.sleep(.05)
base=f'http://127.0.0.1:{port}'
# Verify the real HTTP response contracts before browser testing.
def get(path):
    with urlopen(base+path,timeout=5) as response:return response.status,response.read()
body=json.dumps({'with_ai':False}).encode()
with urlopen(Request(base+'/api/scan',data=body,headers={'Content-Type':'application/json'}),timeout=5) as response:
    scan=json.load(response)
for path in [f"/api/scans/{scan['scan_id']}/graph",f"/api/scans/{scan['scan_id']}/hypotheses",'/graph.js','/hypotheses.js','/openapi.json']:
    assert get(path)[0]==200
print('HTTP graph/hypothesis/static/schema endpoints passed',flush=True)
profile=work/'profile';profile.mkdir()
process=subprocess.Popen(['firefox','--headless','--no-remote','--profile',str(profile),base+'/__ui-test'],
                         stdout=subprocess.DEVNULL,stderr=(work/'firefox.log').open('w'),env={**os.environ,'MOZ_HEADLESS':'1'})
try:
    for _ in range(450):
        if result_path.exists():break
        if process.poll() is not None:raise RuntimeError('Firefox exited: '+(work/'firefox.log').read_text()[-2000:])
        time.sleep(.1)
    assert result_path.exists(),'Browser test timeout: '+(work/'firefox.log').read_text()[-2000:]
    result=json.loads(result_path.read_text());print(json.dumps(result,ensure_ascii=False),flush=True)
    assert result['ok'],result
finally:
    process.terminate()
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:process.kill();process.wait()
    server.should_exit=True;thread.join(timeout=5)
