"""Trusted hypotheses and questions derived from graph evidence, never an LLM story."""
from collections import defaultdict
from datetime import timedelta
from app.graph import entity_id
from app.intelligence_models import InvestigationHypothesis, InvestigationQuestion, HypothesisReport, ObservedFact

ATTRIBUTION = "來源 IP 的 NAT／代理／實際使用者歸屬資料"
POST_LOGIN = "登入後程序、命令、sudo／權限提升與網路活動（auditd 等遙測）"
OWNER = "帳號擁有者確認與歷史登入來源基線（本次樣本不是歷史基線）"


def build_hypothesis_report(store, incident) -> HypothesisReport:
    alerts = [a for a in store.alerts if a.id in incident.alert_ids]
    events = sorted({e.id: e for a in alerts for e in a.related_events}.values(), key=lambda e: (e.timestamp, e.id))
    ids = sorted({incident.id, *incident.alert_ids, *(e.id for e in events)})
    group_edges = [edge for edge in store.graph.edges if set(edge.evidence_ids) & set(ids)]
    progress = [edge for edge in group_edges if edge.relation == "POSSIBLE_ATTACK_PROGRESSION"]
    login_alerts = [a for a in alerts if a.alert_type == "suspicious_login"]
    recon = [a for a in alerts if a.alert_type == "web_enumeration"]
    brute = [a for a in alerts if a.alert_type == "ssh_brute_force"]
    patterned = bool(login_alerts and recon and brute)
    required_pairs = {(r.id, b.id) for r in recon for b in brute} | {(b.id, l.id) for b in brute for l in login_alerts}
    required_pairs |= {(r.id, l.id) for r in recon for l in login_alerts}
    has_order = patterned and any((r.id, b.id) in {(e.source, e.target) for e in progress}
                                  and (b.id, l.id) in {(e.source, e.target) for e in progress}
                                  for r in recon for b in brute for l in login_alerts)
    contradictory = [edge for edge in group_edges if edge.relation == "FOLLOWED_BY"
                     and (edge.target, edge.source) in required_pairs] if patterned and not has_order else []
    first = InvestigationHypothesis(
        id=entity_id("hyp", incident.id + "|campaign"), incident_id=incident.id,
        template="possible_single_attacker_campaign" if patterned else "possible_attack_activity",
        title="H1 · 可能由單一攻擊者進行相關活動",
        description="同一攻擊者可能先進行 Web 探測、再猜測 SSH 憑證、最後完成驗證。" if patterned
                    else "記錄中的攻擊嘗試可能屬於惡意活動；尚未識別來源身份或利用結果。",
        status="contradicted" if contradictory else ("weak" if patterned and not has_order else "plausible"),
        supporting_evidence_ids=sorted(incident.alert_ids),
        contradicting_evidence_ids=sorted({ref for edge in contradictory for ref in edge.evidence_ids}),
        supporting_edge_ids=[e.id for e in progress], contradicting_edge_ids=[e.id for e in contradictory],
        missing_evidence=[ATTRIBUTION, POST_LOGIN] if login_alerts else [ATTRIBUTION, "應用程式／主機的利用結果與合法測試授權資料"],
        confidence=0.1 if contradictory else (0.55 if has_order else 0.4),
    )
    first.supporting_evidence_ids = sorted(set(ids) - set(first.contradicting_evidence_ids) - {incident.id})
    first.neutral_evidence_ids = [incident.id]
    second = InvestigationHypothesis(
        id=entity_id("hyp", incident.id + "|shared"), incident_id=incident.id,
        template="possible_shared_source_activity", title="H2 · 共享 IP／NAT 下的不同活動",
        description="同一 IP 可能代表 NAT、代理或不同使用者，相關事件不一定由同一人執行。",
        status="insufficient_evidence", neutral_evidence_ids=ids,
        neutral_edge_ids=[e.id for e in group_edges], missing_evidence=[ATTRIBUTION, "連線／session 對應與來源設備識別資料"],
        confidence=0.2,
    )
    hypotheses = [first, second]
    successes = [e for e in events if e.event_type == "authentication_success"]
    if successes:
        login_ids = sorted({*(e.id for e in successes), *(a.id for a in login_alerts)})
        hypotheses.append(InvestigationHypothesis(
            id=entity_id("hyp", incident.id + "|legitimate"), incident_id=incident.id,
            template="possible_legitimate_successful_login", title="H3 · 攻擊嘗試後出現合法登入",
            description="先前有攻擊嘗試，但成功驗證可能是帳號擁有者的合法操作；成功驗證不識別操作者身份。",
            status="plausible", supporting_evidence_ids=login_ids,
            neutral_evidence_ids=sorted(set(ids) - set(login_ids)),
            supporting_edge_ids=[e.id for e in group_edges if e.relation == "AUTHENTICATED_AS"],
            neutral_edge_ids=[e.id for e in group_edges if e.relation != "AUTHENTICATED_AS"],
            missing_evidence=[OWNER, POST_LOGIN, ATTRIBUTION], confidence=0.35,
        ))
    all_hypotheses = [h.id for h in hypotheses]
    facts = []
    failures = defaultdict(list)
    for event in events:
        if event.event_type == "authentication_failed":
            failures[event.username].append(event)
        elif event.event_type == "authentication_success":
            facts.append(ObservedFact(text=f"{event.timestamp.isoformat()}：日誌記錄 {event.source_ip} 成功驗證為 {event.username}；不表示操作者已被識別。", evidence_ids=[event.id]))
    for user, group in sorted(failures.items(), key=lambda pair: pair[0] or ""):
        facts.append(ObservedFact(text=f"本 Incident 相關日誌中，來源 {incident.source_ips[0]} 對帳號 {user} 有 {len(group)} 筆 SSH 失敗認證。", evidence_ids=[e.id for e in group]))
    http = [e for e in events if e.event_type == "http_request"]
    if http:
        facts.append(ObservedFact(text=f"相關 access log 記錄 {len(http)} 筆 HTTP 請求，其中 {sum(e.status_code == 404 for e in http)} 筆回應 404；不能由此確認敏感資料存取或腳本執行。", evidence_ids=[e.id for e in http]))
    questions = []

    def question(key, text, kind, tool=None, arguments=None):
        questions.append(InvestigationQuestion(
            id=entity_id("q", incident.id + "|" + key), hypothesis_ids=all_hypotheses,
            question=text, evidence_type=kind, answerable=tool is not None, suggested_tool=tool,
            tool_arguments=arguments or {}, status="pending" if tool else "unavailable",
            answer=None if tool else "本次 SSH／Nginx 日誌沒有這類遙測，不能由空結果推論不存在該活動。"))

    if successes:
        last = successes[-1]
        question("after-login", "本次掃描是否記錄成功登入後同一來源的其他 SSH／HTTP 活動？", "post_login_ssh_http",
                 "search_events", {"source_ip": last.source_ip, "start": (last.timestamp + timedelta(microseconds=1)).isoformat(), "limit": 100})
        question("user-logins", f"本次樣本中帳號 {last.username} 的成功驗證來自哪些來源？", "current_scan_authentication",
                 "get_user_logins", {"username": last.username, "limit": 100})
    else:
        question("source-context", "本次掃描中同一來源在 Incident 附近還有哪些正常或異常事件？", "current_scan_source_context",
                 "search_events", {"source_ip": incident.source_ips[0], "start": incident.start_time.isoformat(),
                                   "end": (incident.end_time + timedelta(minutes=10)).isoformat(), "limit": 100})
        question("timeline", "本 Incident 的觀察時間順序為何？", "incident_timeline",
                 "get_incident_timeline", {"incident_id": incident.id, "limit": 100})
    question("related-alerts", "本次樣本中同一來源還包含哪些規則告警？", "current_scan_alerts", "get_related_alerts",
             {"source_ip": incident.source_ips[0], "limit": 100})
    question("attribution", "同一 IP 是否代表 NAT／代理後的不同使用者或設備？", "source_attribution")
    question("owner", "帳號擁有者是否確認這次操作，且有歷史來源基線可比對？", "historical_baseline_and_owner")
    question("process", "登入後是否出現命令執行、sudo／權限提升或資料外洩？", "process_audit_network")
    report = HypothesisReport(
        incident_id=incident.id, hypotheses=hypotheses, observed_facts=facts, questions=questions,
        missing_evidence=list(dict.fromkeys(item for h in hypotheses for item in h.missing_evidence)),
        uncertainty="現有 SSH／Nginx 日誌不能區分 H1 的操作者身份與 H3 的合法登入，也不能證明 H2 的 NAT 歸屬。"
                    if successes else "現有日誌能描述嘗試，不能確認操作者身份、測試授權或成功利用結果。",
    )
    for hypothesis in hypotheses:
        if not set(hypothesis.supporting_evidence_ids + hypothesis.contradicting_evidence_ids + hypothesis.neutral_evidence_ids) <= store.ids:
            raise ValueError("Hypothesis references unknown evidence")
    return report
