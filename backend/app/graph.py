"""Deterministic, evidence-backed graph. Temporal sequence is never a causal fact."""
from hashlib import sha256
from urllib.parse import urlsplit
from app.intelligence_models import EvidenceGraph, GraphEdge, GraphNode


def entity_id(kind: str, value: str) -> str:
    return kind.upper() + "-" + sha256(value.encode()).hexdigest()[:16]


def build_evidence_graph(store) -> EvidenceGraph:
    nodes, edges = {}, {}

    def node(identifier, kind, label, properties=None):
        nodes[identifier] = GraphNode(id=identifier, node_type=kind, label=label, properties=properties or {})
        return identifier

    def edge(source, target, relation, evidence_ids, *, inferred=False, confidence=None, reasons=()):
        kind = "inferred" if inferred else "observed"
        identifier = entity_id("edge", f"{source}|{target}|{relation}|{kind}")
        if identifier in edges:
            edges[identifier].evidence_ids = sorted(set(edges[identifier].evidence_ids) | set(evidence_ids))
        else:
            edges[identifier] = GraphEdge(id=identifier, source=source, target=target, relation=relation,
                                         edge_type=kind, evidence_ids=sorted(set(evidence_ids)),
                                         confidence=confidence, reasons=list(reasons))

    for event in sorted(store.events, key=lambda e: e.id):
        event_id = node(event.id, "event", event.event_type,
                        event.model_dump(mode="json", exclude_none=True, exclude={"raw_log", "user_agent", "metadata"}))
        ip = node(entity_id("ip", event.source_ip), "ip", event.source_ip)
        edge(ip, event_id, "GENERATED", [event.id], reasons=["Source field recorded in the log; it does not identify the person behind the source."])
        if event.username:
            user = node(entity_id("user", event.username), "user", event.username)
            relation = "AUTHENTICATED_AS" if event.event_type == "authentication_success" else "TARGETED"
            edge(ip, user, relation, [event.id])
            edge(event_id, user, relation, [event.id])
        if event.request_target:
            try:
                path = urlsplit(event.request_target).path or "/"
            except ValueError:
                path = event.request_target
            endpoint = node(entity_id("endpoint", path), "endpoint", path)
            edge(ip, endpoint, "REQUESTED", [event.id])
            edge(event_id, endpoint, "REQUESTED", [event.id])

    for alert in sorted(store.alerts, key=lambda a: a.id):
        node(alert.id, "alert", alert.title, alert.model_dump(mode="json", exclude={"related_events"}))
        ip = node(entity_id("ip", alert.source_ip), "ip", alert.source_ip)
        edge(ip, alert.id, "GENERATED", [alert.id], reasons=["The recorded alert source_ip association does not establish attacker identity."])
        for event in alert.related_events:
            edge(alert.id, event.id, "SUPPORTED_BY", [event.id, alert.id])

    alert_index = {a.id: a for a in store.alerts}
    for incident in sorted(store.incidents, key=lambda i: i.id):
        node(incident.id, "incident", incident.title,
             incident.model_dump(mode="json", exclude={"timeline"}))
        group = sorted((alert_index[key] for key in incident.alert_ids), key=lambda a: (a.timestamp, a.id))
        for alert in group:
            edge(incident.id, alert.id, "CONTAINS", [incident.id, alert.id], reasons=["Rule-generated group membership does not confirm a single attack campaign."])
        for first, second in zip(group, group[1:]):
            if first.timestamp < second.timestamp:
                edge(first.id, second.id, "FOLLOWED_BY", [first.id, second.id], reasons=["Alert timestamp order does not establish causation."])
        for first in group:
            for second in group:
                if first.source_ip != second.source_ip or first.timestamp >= second.timestamp:
                    continue
                sequence = (first.alert_type, second.alert_type)
                if sequence == ("web_enumeration", "ssh_brute_force"):
                    if first.timestamp >= min((e.timestamp for e in second.related_events), default=second.timestamp):
                        continue
                    score = 0.6
                    reason = ["Same recorded source IP", "Same analysis host and 10-minute group", "Web reconnaissance precedes the SSH alert"]
                elif sequence == ("ssh_brute_force", "suspicious_login") and sum(
                    e.username == second.username and e.timestamp < second.timestamp for e in first.related_events
                ) >= 5:
                    score = 0.7
                    reason = ["Same recorded source IP", "At least five failures target the same account as the successful authentication", "The failed-authentication alert precedes successful authentication"]
                else:
                    continue
                edge(first.id, second.id, "POSSIBLE_ATTACK_PROGRESSION", [first.id, second.id],
                     inferred=True, confidence=score,
                     reasons=reason + ["Source attribution and post-login activity evidence are missing. This relationship remains inferred."])

    graph = EvidenceGraph(nodes=sorted(nodes.values(), key=lambda n: n.id),
                          edges=sorted(edges.values(), key=lambda e: e.id))
    if any(not set(e.evidence_ids) <= store.ids for e in graph.edges):
        raise ValueError("Graph references unknown scan evidence")
    return graph
