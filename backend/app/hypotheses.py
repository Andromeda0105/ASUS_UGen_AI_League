"""Trusted hypotheses and questions derived from graph evidence, never an LLM story."""
from collections import defaultdict
from datetime import timedelta
from app.graph import entity_id
from app.intelligence_models import InvestigationHypothesis, InvestigationQuestion, HypothesisReport, ObservedFact

ATTRIBUTION = "Source IP attribution: NAT, proxy, device, and actual user"
POST_LOGIN = "Post-login processes, commands, sudo/privilege escalation, and network activity (such as auditd)"
OWNER = "Account owner confirmation and historical login-source baseline (this scan is not a historical baseline)"


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
        title="H1 · Possible activity by a single attacker",
        description="A single attacker may have performed web reconnaissance, guessed SSH credentials, and then authenticated." if patterned
                    else "Recorded attempts may be malicious; source identity and exploitation outcomes remain unknown.",
        status="contradicted" if contradictory else ("weak" if patterned and not has_order else "plausible"),
        supporting_evidence_ids=sorted(incident.alert_ids),
        contradicting_evidence_ids=sorted({ref for edge in contradictory for ref in edge.evidence_ids}),
        supporting_edge_ids=[e.id for e in progress], contradicting_edge_ids=[e.id for e in contradictory],
        missing_evidence=[ATTRIBUTION, POST_LOGIN] if login_alerts else [ATTRIBUTION, "Application/host exploitation outcomes and authorization for legitimate testing"],
        confidence=0.1 if contradictory else (0.55 if has_order else 0.4),
    )
    first.supporting_evidence_ids = sorted(set(ids) - set(first.contradicting_evidence_ids) - {incident.id})
    first.neutral_evidence_ids = [incident.id]
    second = InvestigationHypothesis(
        id=entity_id("hyp", incident.id + "|shared"), incident_id=incident.id,
        template="possible_shared_source_activity", title="H2 · Separate activities behind a shared IP/NAT",
        description="One IP may represent NAT, a proxy, or different users. Related events need not share an operator.",
        status="insufficient_evidence", neutral_evidence_ids=ids,
        neutral_edge_ids=[e.id for e in group_edges], missing_evidence=[ATTRIBUTION, "Connection/session mapping and source device identity"],
        confidence=0.2,
    )
    hypotheses = [first, second]
    successes = [e for e in events if e.event_type == "authentication_success"]
    if successes:
        login_ids = sorted({*(e.id for e in successes), *(a.id for a in login_alerts)})
        hypotheses.append(InvestigationHypothesis(
            id=entity_id("hyp", incident.id + "|legitimate"), incident_id=incident.id,
            template="possible_legitimate_successful_login", title="H3 · Legitimate login following attack attempts",
            description="Earlier attempts occurred, but successful authentication may belong to the legitimate account owner. Authentication does not identify the operator.",
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
            facts.append(ObservedFact(text=f"{event.timestamp.isoformat()}: the log records successful authentication from {event.source_ip} as {event.username}; it does not identify the operator.", evidence_ids=[event.id]))
    for user, group in sorted(failures.items(), key=lambda pair: pair[0] or ""):
        facts.append(ObservedFact(text=f"Logs related to this incident record {len(group)} failed SSH authentications from {incident.source_ips[0]} for account {user}.", evidence_ids=[e.id for e in group]))
    http = [e for e in events if e.event_type == "http_request"]
    if http:
        facts.append(ObservedFact(text=f"Related access logs record {len(http)} HTTP requests, including {sum(e.status_code == 404 for e in http)} responses with status 404. This does not confirm sensitive-data access or script execution.", evidence_ids=[e.id for e in http]))
    questions = []

    def question(key, text, kind, tool=None, arguments=None):
        questions.append(InvestigationQuestion(
            id=entity_id("q", incident.id + "|" + key), hypothesis_ids=all_hypotheses,
            question=text, evidence_type=kind, answerable=tool is not None, suggested_tool=tool,
            tool_arguments=arguments or {}, status="pending" if tool else "unavailable",
            answer=None if tool else "These SSH/Nginx logs lack this telemetry. Empty results cannot establish the absence of activity."))

    if successes:
        last = successes[-1]
        question("after-login", "Does this scan record other SSH/HTTP activity from the same source after successful authentication?", "post_login_ssh_http",
                 "search_events", {"source_ip": last.source_ip, "start": (last.timestamp + timedelta(microseconds=1)).isoformat(), "limit": 100})
        question("user-logins", f"Which sources successfully authenticated as {last.username} in this scan?", "current_scan_authentication",
                 "get_user_logins", {"username": last.username, "limit": 100})
    else:
        question("source-context", "What other normal or unusual events from this source occur near this incident?", "current_scan_source_context",
                 "search_events", {"source_ip": incident.source_ips[0], "start": incident.start_time.isoformat(),
                                   "end": (incident.end_time + timedelta(minutes=10)).isoformat(), "limit": 100})
        question("timeline", "What is the observed timeline of this incident?", "incident_timeline",
                 "get_incident_timeline", {"incident_id": incident.id, "limit": 100})
    question("related-alerts", "What other rule alerts involve this source in the current scan?", "current_scan_alerts", "get_related_alerts",
             {"source_ip": incident.source_ips[0], "limit": 100})
    question("attribution", "Could this IP represent different users or devices behind NAT or a proxy?", "source_attribution")
    question("owner", "Has the account owner confirmed this activity, and is a historical source baseline available?", "historical_baseline_and_owner")
    question("process", "Was there post-login command execution, sudo/privilege escalation, or data exfiltration?", "process_audit_network")
    report = HypothesisReport(
        incident_id=incident.id, hypotheses=hypotheses, observed_facts=facts, questions=questions,
        missing_evidence=list(dict.fromkeys(item for h in hypotheses for item in h.missing_evidence)),
        uncertainty="Current SSH/Nginx logs cannot distinguish the operator in H1 from a legitimate login in H3, or prove NAT attribution in H2."
                    if successes else "Current logs describe attempts, but cannot confirm operator identity, testing authorization, or successful exploitation.",
    )
    for hypothesis in hypotheses:
        if not set(hypothesis.supporting_evidence_ids + hypothesis.contradicting_evidence_ids + hypothesis.neutral_evidence_ids) <= store.ids:
            raise ValueError("Hypothesis references unknown evidence")
    return report
