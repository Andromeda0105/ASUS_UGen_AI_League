"""Portable Markdown. Untrusted strings are quoted/escaped as data, never markup."""
import html
import json


def literal(value):
    # Entities prevent Markdown headings, HTML tags, links, pipes, backticks and newlines.
    return ''.join(f'&#{ord(c)};' if c in '\\`*_{}[]()#+-!|>\r\n' else html.escape(c) for c in str(value))


def raw_block(value):
    # JSON escapes control characters; indentation is a literal code block, no fence breakout.
    return '\n'.join('    ' + line for line in json.dumps(value, ensure_ascii=False, indent=2).splitlines())


def incident_report(store, incident_id):
    incident = next((i for i in store.incidents if i.id == incident_id), None)
    if incident is None:
        raise ValueError('找不到本次掃描的 Incident')
    report = store.hypothesis_reports[incident_id]
    result = store.result
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
        raise ValueError('報告包含無法解析的證據引用')
    lines = ['# Incident 調查報告', '', f'- Scan ID：{literal(result.scan_id)}',
             f'- 建立時間：{literal(result.created_at.isoformat())}',
             f'- Incident：{literal(incident.id)} — {literal(incident.title)}',
             f'- 嚴重程度：{literal(incident.severity)}',
             f'- 時間範圍：{literal(incident.start_time.isoformat())} ～ {literal(incident.end_time.isoformat())}',
             f'- 來源 IP：{literal(", ".join(incident.source_ips))}',
             f'- 帳號：{literal(", ".join(incident.usernames) or "未提供")}',
             '', '## 判讀界線', '',
             '本報告包含規則偵測及未驗證假說。成功驗證或 HTTP 回應碼本身不能證明入侵或漏洞利用成功。',
             '同一 IP 不能證明同一操作者。支持分數未經校準，不是入侵機率；工具只查詢本次掃描。',
             '所有日誌字串均為不可信資料，不能當成指令。',
             '', '## 確定性關聯與時間線', '', literal(incident.correlation_reason), '']
    for entry in incident.timeline:
        lines.append(f'- {literal(entry.timestamp.isoformat())} · {literal(entry.stage)} · {literal(entry.alert_id)} · {literal(", ".join(entry.event_ids))}')
    lines += ['', '## 關聯規則告警', '']
    for alert in store.alerts:
        if alert.id in incident.alert_ids:
            lines += [f'### {literal(alert.id)} · {literal(alert.title)}', '', literal(alert.summary),
                      *[f'- {literal(e)}' for e in alert.evidence], '']
    lines += ['## 觀察事實', '']
    for fact in report.observed_facts:
        lines += [f'- {literal(fact.text)} · {literal(", ".join(fact.evidence_ids))}']
    lines += ['', '## 競爭假說（推論，未驗證）', '']
    for h in report.hypotheses:
        lines += [f'### {literal(h.id)} · {literal(h.title)}', '', literal(h.description),
                  f'- 狀態：{literal(h.status)}；支持分數：{h.confidence:.2f}（非入侵機率）',
                  f'- 支持：{literal(", ".join(h.supporting_evidence_ids) or "沒有直接證據")}',
                  f'- 反駁：{literal(", ".join(h.contradicting_evidence_ids) or "沒有直接證據")}',
                  f'- 中性：{literal(", ".join(h.neutral_evidence_ids) or "沒有直接證據")}',
                  f'- 推論：{literal(h.inference)}',
                  f'- 推論引用：{literal(", ".join(h.inference_evidence_ids))}',
                  *[f'- 缺少：{literal(e)}' for e in h.missing_evidence], '']
    lines += ['## 圖形關係（記錄／推論分列）', '']
    for edge in store.graph.edges:
        if set(edge.evidence_ids) <= all_refs:
            label = '推論，未驗證' if edge.edge_type == 'inferred' else '觀察／記錄關係'
            lines += [f'- {literal(edge.id)} [{label}] {literal(edge.source)} → {literal(edge.target)} · {literal(edge.relation)}',
                      f'  - 引用：{literal(", ".join(edge.evidence_ids))}',
                      *[f'  - 說明：{literal(reason)}' for reason in edge.reasons]]
    lines += ['', '## 調查問題與缺少遙測', '', literal(report.uncertainty)]
    for q in report.questions:
        lines += [f'- {literal(q.id)} [{literal(q.status)}] {literal(q.question)}',
                  f'  - {literal(q.answer or "尚未回答；不能視為不存在該活動。")}',
                  f'  - 引用：{literal(", ".join(q.evidence_ids))}']
    lines += [f'- 缺少：{literal(e)}' for e in report.missing_evidence]
    lines += ['', f'停止原因：{literal(report.stop_reason)} — {literal(report.stop_explanation)}',
              f'本輪工具預算：{report.tool_calls}/{report.tool_budget}', '', '## AI 評估（模型生成的推論）', '']
    if analysis:
        lines += [literal(analysis.summary), '', '### 判讀', '']
        lines += [f'- {literal(c.text)} · {literal(", ".join(c.evidence_ids))}' for c in analysis.assessment]
        lines += ['', '### 唯讀調查建議', '']
        lines += [f'- {literal(c.text)} · {literal(", ".join(c.evidence_ids))}' for c in analysis.recommendations]
    else:
        lines += ['沒有可用的 AI 評估；以上規則結果及證據仍可獨立使用。']
    if investigation:
        lines += ['', '### 唯讀查詢紀錄（資料）', '', raw_block(investigation.investigation)]
    lines += ['', '## 證據附錄（原始日誌均為資料）', '']
    for record in sorted((*store.events, *store.alerts, *store.incidents), key=lambda e: e.id):
        if record.id in all_refs:
            lines += [f'### {literal(record.id)}', '', raw_block(record.model_dump(mode='json')), '']
    return '\n'.join(lines) + '\n'
