"""Offline, reproducible measurements. Only known labels receive precision/recall."""
import argparse
import json
import os
import platform
import tempfile
import time
from pathlib import Path
from importlib.metadata import version
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app, SCANS, scan_store
from app.copilot import OllamaError

ROOT=Path(__file__).resolve().parents[1]
FIXTURES=ROOT/'backend/tests/fixtures'


def evaluate():
    cases=[
        ('synthetic_multistage', 'synthetic', [('nginx',ROOT/'samples/scenarios/multi_stage_access.log'),('ssh',ROOT/'samples/scenarios/multi_stage_auth.log')]),
        ('synthetic_benign', 'synthetic', [('nginx',ROOT/'samples/normal.log'),('ssh',ROOT/'samples/ssh/normal.log')]),
        ('external_openssh', 'external_unlabeled', [('ssh',FIXTURES/'external/OpenSSH_2k.log')]),
        ('controlled_http', 'controlled_lab_pattern_labeled', [('nginx',FIXTURES/'lab/access.log')]),
    ]
    output={'environment':{'python':platform.python_version(),'platform':platform.platform(),
                'fastapi':version('fastapi'),'sqlite':__import__('sqlite3').sqlite_version,
                'ollama':'disabled','ssh_year':2026,'log_timezone':os.getenv('LOG_TIMEZONE','Asia/Taipei')},
            'cases':[],'definitions':{'parser_rate':'accepted input lines / total lines; unsupported SSH telemetry counts as skipped',
                'latency':'one measured local TestClient request including import, graph, hypotheses and transactional SQLite write',
                'labels':'only controlled HTTP request intent labels; no compromise/exploitation ground truth',
                'grouping':'synthetic rule expectation only; no externally labeled campaign grouping'}}
    with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{'COPILOT_DB_PATH':str(Path(directory)/'eval.sqlite3')}), \
         patch('app.investigator.chat', side_effect=AssertionError('AI disabled')), TestClient(app) as client:
        SCANS.clear()
        for name,group,sources in cases:
            started=time.perf_counter()
            response=client.post('/api/scans/upload',files=[('files',(path.name,path.read_bytes(),'text/plain')) for source,path in sources],
                                 data={'source_types':[source for source,path in sources],'ssh_year':'2026','with_ai':'false'})
            elapsed=time.perf_counter()-started
            assert response.status_code==200,response.text
            scan=response.json();store=scan_store(scan['scan_id'])
            graph=client.get(f"/api/scans/{scan['scan_id']}/graph").json()
            refs=[ref for edge in graph['edges'] for ref in edge['evidence_ids']]
            for report in scan['hypotheses']:
                refs += [ref for fact in report['observed_facts'] for ref in fact['evidence_ids']]
                for h in report['hypotheses']:
                    for field in ('supporting_evidence_ids','contradicting_evidence_ids','neutral_evidence_ids'):
                        refs += h[field]
                # Full investigate/export path; remains read-only and offline.
                investigate=client.post(f"/api/scans/{scan['scan_id']}/incidents/{report['incident_id']}/investigate",json={'with_ai':False,'tool_budget':4})
                assert investigate.status_code==200
                refs += [ref for q in investigate.json()['report']['questions'] for ref in q['evidence_ids']]
                export=client.get(f"/api/scans/{scan['scan_id']}/incidents/{report['incident_id']}/report.md")
                assert export.status_code==200
            total=sum(r['line_count'] for r in scan['file_results']);accepted=sum(r['accepted_lines'] for r in scan['file_results'])
            result=dict(name=name,group=group,total_lines=total,accepted_lines=accepted,skipped_lines=total-accepted,
                        parser_accept_rate=round(accepted/total,6),unique_events=scan['event_count'],
                        alerts=len(scan['alerts']),incidents=len(scan['incidents']),import_latency_ms=round(elapsed*1000,2),
                        evidence_references_checked=len(refs),invalid_evidence_references=sum(ref not in store.ids for ref in refs))
            assert result['invalid_evidence_references']==0
            if name=='synthetic_multistage':
                # Print actual deterministic labels; exact membership expected for one fixture group.
                result['rule_expectation_grouping_exact_match']= (len(store.incidents)==1
                    and set(store.incidents[0].alert_ids)=={a.id for a in store.alerts}
                    and {(a.alert_type,a.source_ip) for a in store.alerts}=={('web_enumeration','10.0.0.8'),('ssh_brute_force','10.0.0.8'),('suspicious_login','10.0.0.8')})
            if name=='synthetic_benign':result['benign_expected_zero_alerts']=len(store.alerts)==0
            if name=='controlled_http':
                labels=json.loads((FIXTURES/'lab/labels.json').read_text())['cases']
                expected={(r['target'],r['expected']) for r in labels if r['expected']!='benign'}
                actual={(e.request_target,a.alert_type) for a in store.alerts for e in a.related_events}
                tp=len(actual & expected);fp=len(actual-expected);fn=len(expected-actual)
                result['labeled_pattern_metrics']=dict(tp=tp,fp=fp,fn=fn,precision=tp/(tp+fp) if tp+fp else None,
                                                      recall=tp/(tp+fn) if tp+fn else None,note='4-request controlled pattern fixture only; not production accuracy')
            output['cases'].append(result)
        SCANS.clear()
    return output


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path)
    args=parser.parse_args();data=evaluate();text=json.dumps(data,indent=2,ensure_ascii=False)+'\n'
    if args.output:args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(text)
    print(text)
