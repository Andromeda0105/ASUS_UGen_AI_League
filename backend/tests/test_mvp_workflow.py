"""Offline API integration: imports, persistence, investigation, exports and deletion."""
import hashlib
import html
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from app.main import app, SCANS, scan_store
from app.storage import repository

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / 'fixtures'


def upload(client, sources, **fields):
    files = [('files', (name, content, 'text/plain')) for name, kind, content in sources]
    return client.post('/api/scans/upload', files=files,
                       data={'source_types': [s[1] for s in sources], 'ssh_year': '2026',
                             'with_ai': 'false', **fields})


def multi_stage():
    directory = ROOT / 'samples/scenarios'
    return [('access.log', 'nginx', (directory/'multi_stage_access.log').read_bytes()),
            ('auth.log', 'ssh', (directory/'multi_stage_auth.log').read_bytes())]


class MVPTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'COPILOT_DB_PATH': str(Path(self.work.name)/'test.sqlite3')})
        self.env.start()
        SCANS.clear()
        self.client = TestClient(app)
        self.ai = patch('app.investigator.chat', side_effect=AssertionError('Offline tests must not call AI'))
        self.ai.start()

    def tearDown(self):
        self.ai.stop()
        self.client.close()
        SCANS.clear()
        self.env.stop()
        self.work.cleanup()

    def imported(self, sources=None):
        response = upload(self.client, sources or multi_stage())
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_full_workflow_offline_and_restart(self):
        scan = self.imported()
        scan_id, incident_id = scan['scan_id'], scan['incidents'][0]['id']
        prefix = f'/api/scans/{scan_id}'
        self.assertEqual((scan['event_count'], len(scan['alerts']), len(scan['incidents'])), (10, 3, 1))
        self.assertEqual([r['accepted_lines'] for r in scan['file_results']], [4, 6])
        graph = self.client.get(prefix+'/graph').json()
        store = scan_store(scan_id)
        ids = store.ids
        self.assertTrue(all(set(e['evidence_ids']) <= ids for e in graph['edges']))
        self.assertTrue(any(e['edge_type'] == 'inferred' for e in graph['edges']))
        response = self.client.post(prefix+f'/incidents/{incident_id}/investigate', json={'with_ai': False, 'tool_budget': 4})
        self.assertEqual(response.status_code, 200, response.text)
        report = response.json()['report']
        self.assertEqual(report['stop_reason'], 'unavailable_telemetry')
        self.assertEqual(report['tool_calls'], 3)
        for q in report['questions']:
            self.assertTrue(set(q['evidence_ids']) <= ids)
        for h in report['hypotheses']:
            for name in ('supporting_evidence_ids', 'contradicting_evidence_ids', 'neutral_evidence_ids'):
                for evidence_id in h[name]:
                    self.assertEqual(self.client.get(prefix+'/evidence/'+evidence_id).status_code, 200)
        before = self.client.get(prefix).json()
        # Discard every in-memory store; new repository connections must restore disk state.
        SCANS.clear()
        after = self.client.get(prefix).json()
        self.assertEqual(before, after)
        self.assertEqual(self.client.get(prefix+'/graph').json(), graph)
        markdown = self.client.get(prefix+f'/incidents/{incident_id}/report.md')
        self.assertEqual(markdown.status_code, 200, markdown.text)
        self.assertIn('attachment;', markdown.headers['content-disposition'])
        self.assertIn(incident_id, html.unescape(markdown.text))
        self.assertIn('No AI assessment available', markdown.text)
        self.assertIn('Inferred, unverified', markdown.text)
        self.assertIn('does not prove compromise', markdown.text)
        history = self.client.get('/api/scans').json()
        self.assertEqual(history['total'], 1)
        self.assertEqual(history['items'][0]['scan_id'], scan_id)
        second = self.imported()
        self.assertEqual(self.client.delete(prefix).status_code, 200)
        self.assertEqual(self.client.get(prefix).status_code, 404)
        self.assertEqual(self.client.get(f"/api/scans/{second['scan_id']}").status_code, 200)
        with repository.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM events WHERE scan_id=?', (scan_id,)).fetchone()[0], 0)


    def test_fresh_backend_process_reads_saved_scan(self):
        scan=self.imported()
        script="from app.main import get_scan, get_graph; import json; s=get_scan(%r); print(json.dumps({'scan':s.model_dump(mode='json'),'graph':get_graph(s.scan_id).model_dump(mode='json')}))" % scan['scan_id']
        process=subprocess.run([sys.executable,'-c',script],capture_output=True,text=True,check=True,timeout=15)
        snapshot=json.loads(process.stdout)
        self.assertEqual(snapshot['scan'],scan)
        self.assertEqual(snapshot['graph'],self.client.get(f"/api/scans/{scan['scan_id']}/graph").json())

    def test_one_ssh_file(self):
        scan = self.imported([('own.log', 'ssh', (ROOT/'samples/ssh/bruteforce.log').read_bytes())])
        self.assertEqual([a['alert_type'] for a in scan['alerts']], ['ssh_brute_force'])

    def test_partial_lines_and_bad_files_are_visible(self):
        sources = multi_stage()
        sources[1] = ('../../<bad>.log', 'ssh', sources[1][2] + b'malformed line\n')
        sources += [('empty.log', 'ssh', b''), ('binary.log', 'nginx', b'\xff\x00')]
        scan = self.imported(sources)
        parsed, empty, binary = scan['file_results'][1:]
        self.assertEqual(parsed['filename'], '<bad>.log')
        self.assertEqual((parsed['accepted_lines'], parsed['rejected_lines']), (6, 1))
        self.assertEqual(parsed['issues'][0]['line'], 7)
        self.assertEqual((empty['status'], binary['status']), ('rejected', 'rejected'))
        self.assertEqual(scan['event_count'], 10)

    def test_invalid_inputs_have_no_completed_history(self):
        for sources in [[('bad.log', 'ssh', b'bad')], [('empty.log', 'ssh', b'')], [('x.log', 'unsupported', b'bad')]]:
            response = upload(self.client, sources)
            self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(self.client.get('/api/scans').json()['total'], 0)
        self.assertEqual(self.client.post('/api/scans/upload', files={'files': ('a.log', b'bad')}).status_code, 422)

    def test_configurable_limits(self):
        for config,content in [({'UPLOAD_MAX_FILE_BYTES':'4'},b'12345'),
                               ({'UPLOAD_MAX_TOTAL_BYTES':'4'},b'12345'),
                               ({'UPLOAD_MAX_LINES':'1'}, b'one\ntwo\n')]:
            with patch.dict(os.environ, config):
                self.assertEqual(upload(self.client, [('x.log','ssh',content)]).status_code, 413)
        with patch.dict(os.environ, {'UPLOAD_MAX_FILES':'1'}):
            self.assertEqual(upload(self.client, multi_stage()).status_code, 400)
        # Streaming request without Content-Length also has a body ceiling.
        with patch.dict(os.environ, {'UPLOAD_MAX_TOTAL_BYTES':'4'}):
            response = self.client.post('/api/scans/upload', content=iter([b'x'*70000]),
                                        headers={'Content-Type': 'multipart/form-data; boundary=x'})
            self.assertEqual(response.status_code, 413)
        self.assertEqual(self.client.get('/api/scans').json()['total'], 0)

    def test_duplicates_and_out_of_order_do_not_inflate(self):
        sources = multi_stage()
        sources[1] = ('auth.log','ssh',b'\n'.join(sources[1][2].splitlines()[::-1])*1+b'\n'+sources[1][2])
        scan = self.imported(sources)
        self.assertEqual(scan['event_count'], 10)
        self.assertEqual(len(scan['alerts']), 3)
        self.assertEqual(scan['duplicate_event_count'], 6) # per-file parser already removes duplicates
        self.assertEqual(scan['file_results'][1]['duplicate_lines'], 6)

    def test_timezone_year_and_invalid_dates(self):
        text = b'Feb 30 12:00:00 host sshd[1]: Failed password for root from 10.0.0.8 port 20 ssh2\n'
        text += b'Oct 09 12:00:00 host sshd[1]: Accepted publickey for alice from 10.0.0.8 port 20 ssh2\n'
        scan = self.imported([('auth.log','ssh',text)])
        self.assertEqual(scan['file_results'][0]['issues'][0]['line'], 1)
        store = scan_store(scan['scan_id'])
        self.assertEqual(store.events[0].timestamp.year, 2026)
        self.assertIsNotNone(store.events[0].timestamp.tzinfo)
        ngx = b'10.0.0.8 - - [09/Oct/2026:04:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "normal"\n'
        scan = self.imported([('auth.log','ssh',text), ('access.log','nginx',ngx)])
        self.assertEqual(scan_store(scan['scan_id']).events[0].timestamp, scan_store(scan['scan_id']).events[1].timestamp)
        self.assertEqual(upload(self.client, [('auth.log','ssh',text)], ssh_year='0').status_code, 422)

    def test_benign_shared_ip_no_invented_incident(self):
        sources = [('access.log','nginx',(ROOT/'samples/normal.log').read_bytes()),
                   ('auth.log','ssh',(ROOT/'samples/ssh/normal.log').read_bytes())]
        scan = self.imported(sources)
        self.assertEqual((len(scan['alerts']),len(scan['incidents']),len(scan['hypotheses'])),(0,0,0))
        self.assertEqual(self.client.get(f"/api/scans/{scan['scan_id']}/incidents/nope/report.md").status_code,404)

    def test_nat_hypothesis_remains_unknown_and_tools_readonly(self):
        scan = self.imported()
        hypothesis = next(h for h in scan['hypotheses'][0]['hypotheses'] if h['template'] == 'possible_shared_source_activity')
        self.assertEqual(hypothesis['status'],'insufficient_evidence')
        self.assertEqual(hypothesis['supporting_evidence_ids'],[])
        response = self.client.get(f"/api/scans/{scan['scan_id']}/tools/execute_shell", params={'source_ip':'$(touch hacked)'})
        self.assertEqual(response.status_code,422)

    def test_injection_in_log_is_literal_report_data(self):
        sources = multi_stage()
        # A valid request can contain hostile user-agent strings, but no actual line breaks.
        sources[0] = ('# evil.md', 'nginx', sources[0][2].replace(b'"demo"',b'"<script>IGNORE_ALL_RULES</script> ``` # EVIL"'))
        scan = self.imported(sources)
        prefix = f"/api/scans/{scan['scan_id']}"
        response = self.client.get(prefix+f"/incidents/{scan['incidents'][0]['id']}/report.md")
        for line in response.text.splitlines():
            if 'IGNORE_ALL_RULES' in line:
                self.assertTrue(line.startswith('    '), line)
        self.assertNotIn('\n# EVIL',response.text)
        self.assertNotIn('\n```',response.text)
        self.assertNotIn('raw_log',json.dumps(self.client.get(prefix+'/graph').json()))

    def test_database_failure_is_atomic_not_completed(self):
        # Actual SQLite trigger aborts midway through normalized event inserts.
        with repository.connect() as db:
            db.execute("CREATE TRIGGER fail_events BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'failure'); END")
        response = upload(self.client, multi_stage())
        self.assertEqual(response.status_code,503,response.text)
        self.assertEqual(self.client.get('/api/scans').json()['total'],0)
        self.assertEqual(len(SCANS),0)
        with repository.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],0)

    def test_failed_investigation_save_restores_state(self):
        scan = self.imported()
        prefix = f"/api/scans/{scan['scan_id']}"
        with patch('app.main.repository.save', side_effect=sqlite3.OperationalError('disk full')):
            response = self.client.post(prefix+f"/incidents/{scan['incidents'][0]['id']}/investigate",json={'with_ai':False})
        self.assertEqual(response.status_code,503)
        self.assertEqual(self.client.get(prefix).json()['hypotheses'],scan['hypotheses'])
        SCANS.clear()
        self.assertEqual(self.client.get(prefix).json()['hypotheses'],scan['hypotheses'])

    def test_ai_unavailable_still_saves_and_exports(self):
        self.ai.stop()
        with patch('app.investigator.chat',side_effect=__import__('app.copilot',fromlist=['OllamaError']).OllamaError('offline')):
            scan=self.imported() # deterministic first
            prefix=f"/api/scans/{scan['scan_id']}"
            response=self.client.post(prefix+f"/incidents/{scan['incidents'][0]['id']}/investigate",json={'with_ai':True})
            self.assertEqual(response.json()['ai_status'],'unavailable')
            self.assertEqual(response.json()['report']['tool_calls'],3)
            SCANS.clear()
            self.assertEqual(self.client.get(prefix+f"/incidents/{scan['incidents'][0]['id']}/report.md").status_code,200)

    def test_saved_ai_is_exported_after_reload_and_readonly_round(self):
        from app.models import AIAnalysis, IncidentInvestigationResult
        scan=self.imported();incident_id=scan['incidents'][0]['id'];prefix=f"/api/scans/{scan['scan_id']}"
        store=scan_store(scan['scan_id'])
        analysis=AIAnalysis(summary='AI inference: operator identity remains unknown.',
            assessment=[{'text':'Logs record repeated failures in a short period.','evidence_ids':[incident_id]}],
            recommendations=[{'text':'Compare account owner login records.','evidence_ids':[incident_id]}],
            missing_evidence=['Attribution evidence is missing.'],confidence=0.4)
        result=IncidentInvestigationResult(incident_id=incident_id,report=store.hypothesis_reports[incident_id],
                                         ai_status='completed',ai_analysis=analysis)
        with patch('app.main.run_hypothesis_investigation',return_value=result):
            self.assertEqual(self.client.post(prefix+f'/incidents/{incident_id}/investigate',json={'with_ai':True}).status_code,200)
        SCANS.clear()
        restored=self.client.get(prefix).json()
        self.assertEqual(restored['investigation_results'][incident_id]['ai_analysis'],analysis.model_dump(mode='json'))
        self.client.post(prefix+f'/incidents/{incident_id}/investigate',json={'with_ai':False,'tool_budget':1})
        SCANS.clear()
        markdown=self.client.get(prefix+f'/incidents/{incident_id}/report.md').text
        self.assertIn('AI inference: operator identity remains unknown.',markdown)
        self.assertIn('AI assessment (model-generated inference)',markdown)

    def test_deleted_snapshot_cannot_be_resurrected(self):
        scan=self.imported()
        store=scan_store(scan['scan_id'])
        self.client.delete(f"/api/scans/{scan['scan_id']}")
        with self.assertRaises(LookupError):repository.save(store)
        self.assertEqual(self.client.get('/api/scans').json()['total'],0)

    def test_external_provenance_and_all_references(self):
        directory=FIXTURES/'external'
        manifest=json.loads((directory/'provenance.json').read_text())
        for name,metadata in manifest['files'].items():
            self.assertEqual(hashlib.sha256((directory/name).read_bytes()).hexdigest(),metadata['sha256'])
        content=(directory/'OpenSSH_2k.log').read_bytes()
        self.assertEqual(len(content.splitlines()),2000)
        scan=self.imported([('OpenSSH_2k.log','ssh',content)])
        counts=scan['file_results'][0]
        self.assertEqual(counts['accepted_lines']+counts['rejected_lines'],2000)
        self.assertGreater(counts['rejected_lines'],0) # unsupported operational SSH telemetry is explicit
        store=scan_store(scan['scan_id'])
        self.assertTrue(all(set(e.evidence_ids)<=store.ids for e in store.graph.edges))

    def test_controlled_lab_request_capture(self):
        scan=self.imported([('lab_access.log','nginx',(FIXTURES/'lab/access.log').read_bytes())])
        self.assertEqual(scan['event_count'],4)
        self.assertEqual({a['alert_type'] for a in scan['alerts']},{'sqli_attempt','xss_attempt'})
        self.assertEqual(len(scan['alerts']),2)
        self.assertTrue(all('attempt' in a['summary'] for a in scan['alerts']))


if __name__=='__main__':unittest.main()
