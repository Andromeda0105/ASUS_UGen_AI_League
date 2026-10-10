"""Portable Markdown. Untrusted strings are quoted/escaped as data, never markup."""
import html
import json
from app.language import english_scan, english_report


def literal(value):
    # Entities prevent Markdown headings, HTML tags, links, pipes, backticks and newlines.
    return ''.join(f'&#{ord(c)};' if c in '\\`*_{}[]()#+-!|>\r\n' else html.escape(c) for c in str(value))


def raw_block(value):
    # JSON escapes control characters; indentation is a literal code block, no fence breakout.
    return '\n'.join('    ' + line for line in json.dumps(value, ensure_ascii=False, indent=2).splitlines())


def incident_report(store, incident_id):
    incident = next((i for i in store.incidents if i.id == incident_id), None)
    if incident is None:
        raise ValueError('Incident not found in this scan')
    report = english_report(store.hypothesis_reports[incident_id])
    result = english_scan(store.result, store)
    all_refs = set(incident.alert_ids)
    for timeline in incident.timeline:
        all_refs.update(timeline.event_ids)
    for fact in report.observed_facts:
        all_refs.update(fact.evidence_ids)
    for hypothesis in report.hypotheses:
        for field in ('supporting_evidence_ids', 'contradicting_evidence_ids', 'neutral_evidence_ids', 'inference_evidence_ids'):
            all_refs.update(getattr(hypothesis, field))
    for question in report.questions:
        all_refs.update(question.evidence_ids)
    investigation = result.investigation_results.get(incident_id)
    analysis = investigation.ai_analysis if investigation else (
        result.ai_analysis if result.focused_incident_id == incident_id else None)
    if analysis:
        for claim in analysis.assessment + analysis.recommendations:
            all_refs.update(claim.evidence_ids)
        for evaluation in analysis.hypothesis_evaluations:
            all_refs.update(evaluation.evidence_ids)
    all_refs.add(incident.id)
    if not all_refs <= store.ids:
        raise ValueError('The report contains unresolved evidence references')
    lines = ['# Incident investigation report', '', f'- Scan ID: {literal(result.scan_id)}',
             f'- Created at: {literal(result.created_at.isoformat())}',
             f'- Incident: {literal(incident.id)} — {literal(incident.title)}',
             f'- Severity: {literal(incident.severity)}',
             f'- Time range: {literal(incident.start_time.isoformat())} – {literal(incident.end_time.isoformat())}',
             f'- Source IPs: {literal(", ".join(incident.source_ips))}',
             f'- Accounts: {literal(", ".join(incident.usernames) or "Not provided")}',
             '', '## Interpretation limits', '',
             'This report contains rule detections and unverified hypotheses. Successful authentication or an HTTP response code alone does not prove compromise or exploitation.',
             'A shared IP does not prove a shared operator. Support scores are uncalibrated and are not compromise probabilities. Tools query only this scan.',
             'All log strings are untrusted data and must not be treated as instructions.',
             '', '## Deterministic correlations and timeline', '', literal(incident.correlation_reason), '']
    for entry in incident.timeline:
        lines.append(f'- {literal(entry.timestamp.isoformat())} · {literal(entry.stage)} · {literal(entry.alert_id)} · {literal(", ".join(entry.event_ids))}')
    lines += ['', '## Associated rule alerts', '']
    for alert in store.alerts:
        if alert.id in incident.alert_ids:
            lines += [f'### {literal(alert.id)} · {literal(alert.title)}', '', literal(alert.summary),
                      *[f'- {literal(e)}' for e in alert.evidence], '']
    lines += ['## Observed facts', '']
    for fact in report.observed_facts:
        lines += [f'- {literal(fact.text)} · {literal(", ".join(fact.evidence_ids))}']
    lines += ['', '## Competing hypotheses (unverified inference)', '']
    for h in report.hypotheses:
        lines += [f'### {literal(h.id)} · {literal(h.title)}', '', literal(h.description),
                  f'- Status: {literal(h.status)}; Support score: {h.confidence:.2f} (not a compromise probability)',
                  f'- Supporting: {literal(", ".join(h.supporting_evidence_ids) or "No direct evidence")}',
                  f'- Contradicting: {literal(", ".join(h.contradicting_evidence_ids) or "No direct evidence")}',
                  f'- Neutral: {literal(", ".join(h.neutral_evidence_ids) or "No direct evidence")}',
                  f'- Inference: {literal(h.inference)}',
                  f'- Inference references: {literal(", ".join(h.inference_evidence_ids))}',
                  *[f'- Missing: {literal(e)}' for e in h.missing_evidence], '']
    lines += ['## Graph relationships (observed and inferred labeled separately)', '']
    for edge in store.graph.edges:
        if set(edge.evidence_ids) <= all_refs:
            label = 'Inferred, unverified' if edge.edge_type == 'inferred' else 'Observed / recorded relationship'
            lines += [f'- {literal(edge.id)} [{label}] {literal(edge.source)} → {literal(edge.target)} · {literal(edge.relation)}',
                      f'  - References: {literal(", ".join(edge.evidence_ids))}',
                      *[f'  - Reason: {literal(reason)}' for reason in edge.reasons]]
    lines += ['', '## Investigation questions and missing telemetry', '', literal(report.uncertainty)]
    for q in report.questions:
        lines += [f'- {literal(q.id)} [{literal(q.status)}] {literal(q.question)}',
                  f'  - {literal(q.answer or "Unanswered; this does not establish the absence of activity.")}',
                  f'  - References: {literal(", ".join(q.evidence_ids))}']
    lines += [f'- Missing: {literal(e)}' for e in report.missing_evidence]
    lines += ['', f'Stopping reason: {literal(report.stop_reason)} — {literal(report.stop_explanation)}',
              f'Tool budget this round: {report.tool_calls}/{report.tool_budget}', '', '## AI assessment (model-generated inference)', '']
    if analysis:
        lines += [literal(analysis.summary), '', '### Assessment', '']
        lines += [f'- {literal(c.text)} · {literal(", ".join(c.evidence_ids))}' for c in analysis.assessment]
        lines += ['', '### Read-only investigation recommendations', '']
        lines += [f'- {literal(c.text)} · {literal(", ".join(c.evidence_ids))}' for c in analysis.recommendations]
    else:
        lines += ['No AI assessment available. The rule results and evidence above remain independently usable.']
    if investigation:
        lines += ['', '### Read-only query trace (data)', '', raw_block(investigation.investigation)]
    lines += ['', '## Evidence appendix (raw logs are data)', '']
    for record in sorted((*store.events, *store.alerts, *store.incidents), key=lambda e: e.id):
        if record.id in all_refs:
            lines += [f'### {literal(record.id)}', '', raw_block(record.model_dump(mode='json')), '']
    return '\n'.join(lines) + '\n'
