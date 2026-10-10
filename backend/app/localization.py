"""Refresh legacy presentation text without changing evidence or detection decisions."""
from hashlib import sha256
from app.detectors.ssh import detect_ssh_alerts
from app.detectors.nginx import detect_nginx_alerts
from app.incidents import correlate_incidents
from app.language import CJK


IMPORT_ISSUES = {
    '檔案為空或只有空白。': 'File is empty or contains only whitespace.',
    '檔案必須使用 UTF-8 編碼。': 'File must use UTF-8 encoding.',
    '檔案只有空白，沒有可解析事件。': 'File contains only whitespace and no parseable events.',
    '單行超過長度上限。': 'Line exceeds the length limit.',
    '空白行。': 'Blank line.',
    '日期、時區或欄位無效。': 'Invalid date, timezone, or field.',
    'SSH 非支援的認證事件或格式／日期無效；目前只解析 Failed password 與 Accepted 登入。':
        'Unsupported SSH event or invalid format/date. Only Failed password and Accepted authentication are parsed.',
    '不符合 Nginx combined access log 格式或日期無效。': 'Invalid Nginx combined access log format or date.',
}


def english_sample_label(label):
    prefix = '本機匯入：'
    return 'Local import: ' + label[len(prefix):].lstrip() if label.startswith(prefix) else label


def refresh_legacy_labels(result, events):
    if result.presentation_version >= 2:
        return
    # Match by stable evidence identity. Copy only presentation fields, never verdicts.
    fresh = detect_ssh_alerts([e for e in events if e.source == 'auth.log'])
    fresh += detect_nginx_alerts([e for e in events if e.source == 'nginx.access.log'])
    labels = {}
    for alert in fresh:
        key = alert.alert_type + '|' + '|'.join(sorted(e.id for e in alert.related_events))
        identifier = alert.id.rsplit('-', 1)[0] + '-' + sha256(key.encode()).hexdigest()[:12]
        labels[identifier] = alert
    for alert in result.alerts:
        if alert.id in labels:
            current = labels[alert.id]
            for field in ('title', 'summary', 'recommendation', 'evidence'):
                setattr(alert, field, getattr(current, field))
        elif any(CJK.search(text) for text in (alert.title, alert.summary, alert.recommendation, *alert.evidence)):
            alert.title = alert.alert_type.replace('_', ' ').capitalize()
            alert.summary = 'This rule alert was saved by an earlier version. Review its original evidence; it does not confirm compromise.'
            alert.recommendation = 'Review the associated log records and verify account and host activity.'
            alert.evidence = [f'{len(alert.related_events)} associated event records; see original evidence IDs.']
    incidents = {i.id: i for i in correlate_incidents(result.alerts)}
    for incident in result.incidents:
        if incident.id in incidents:
            incident.title = incidents[incident.id].title
            incident.correlation_reason = incidents[incident.id].correlation_reason
        elif CJK.search(incident.title + incident.correlation_reason):
            incident.title = 'Previously saved security investigation'
            incident.correlation_reason = 'This saved investigation groups related rule alerts. Correlation does not confirm a shared attacker or compromise.'
    result.sample = english_sample_label(result.sample)
    for file in result.file_results:
        for issue in file.get('issues', []):
            issue['reason'] = IMPORT_ISSUES.get(issue['reason'], 'The earlier import skipped this line or file. Check its format and encoding.' if CJK.search(issue['reason']) else issue['reason'])
    if result.ai_error:
        result.ai_error = 'A previous AI request failed. Run AI comparison again to see the current error or an English assessment.'
    if result.ai_warnings:
        result.ai_warnings = ['Previous analysis warnings were recorded in the earlier language. Run AI comparison for an updated assessment.']
    for report in result.hypotheses:
        # The loader fills English labels from its fresh evidence-derived report next.
        report.confidence_note = 'Scores represent uncalibrated evidence support, not compromise probabilities, and need not sum to 1.'


def refresh_legacy_reports(store, result):
    if result.presentation_version >= 2:
        return
    from app.investigator import _execute_question
    for old in result.hypotheses:
        fresh = store.hypothesis_reports.get(old.incident_id)
        if fresh is None:
            continue
        new_hypotheses = {h.id: h for h in fresh.hypotheses}
        for h in old.hypotheses:
            new = new_hypotheses.get(h.id)
            if new:
                h.title, h.description, h.missing_evidence = new.title, new.description, new.missing_evidence
                if h.confidence_origin == 'rule':
                    h.inference = new.inference
        old.observed_facts = fresh.observed_facts
        old.uncertainty, old.missing_evidence = fresh.uncertainty, fresh.missing_evidence
        questions = {q.id: q for q in fresh.questions}
        calls = old.tool_calls
        for q in old.questions:
            new = questions.get(q.id)
            if new is None:
                continue
            q.question = new.question
            if q.status == 'answered' and q.answerable:
                # Reformat a bounded query over the same immutable snapshot. No AI or host access.
                _execute_question(store, old, q, [], 'language_refresh')
            elif not q.answerable:
                q.answer = new.answer
            elif q.status == 'error':
                q.answer = 'The earlier query failed. This does not establish the absence of activity.'
        old.tool_calls = calls
        if old.stop_reason == 'not_run':
            old.stop_explanation = fresh.stop_explanation
        else:
            old.stop_explanation = {
                'tool_budget_exhausted': 'The tool budget was exhausted. Answerable questions may remain; start another round manually.',
                'iteration_limit': 'The single-round query limit was reached. Start another round manually if needed.',
                'unavailable_telemetry': 'Remaining questions require unavailable telemetry, attribution, or historical baselines.',
                'all_answerable_checked': 'All currently answerable questions have been checked.',
                'no_new_distinguishing_evidence': 'No new evidence is available to distinguish the hypotheses.',
            }.get(old.stop_reason, fresh.stop_explanation)
        for investigation in result.investigation_results.values():
            if investigation.incident_id == old.incident_id:
                investigation.report = old
                if investigation.ai_error:
                    investigation.ai_error = 'The earlier AI request failed. Run comparison again for an English assessment.'
                investigation.ai_warnings = []
    result.content_language = 'en'
    result.presentation_version = 2
