"""SQLite snapshots; graph reconstruction preserves deterministic evidence identities."""
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from app.evidence import EvidenceStore
from app.models import LogEvent, ScanResult

DEFAULT_PATH = Path(__file__).resolve().parents[2] / 'data' / 'copilot.sqlite3'


class ScanRepository:
    @contextmanager
    def connect(self):
        path = Path(os.getenv('COPILOT_DB_PATH', str(DEFAULT_PATH)))
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Open with restrictive permissions from creation; never interpolate data into SQL.
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        connection = sqlite3.connect(path, timeout=15)
        connection.execute('PRAGMA foreign_keys = ON')
        try:
            connection.executescript('''
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, sample TEXT NOT NULL,
                    source_types TEXT NOT NULL, event_count INTEGER NOT NULL,
                    alert_count INTEGER NOT NULL, incident_count INTEGER NOT NULL,
                    payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(scan_id, id));
            ''')
            yield connection
        finally:
            connection.close()

    def save(self, store):
        result = store.result
        result.hypotheses = list(store.hypothesis_reports.values())
        with self.connect() as db, db:
            db.execute('BEGIN IMMEDIATE')
            if getattr(store, 'persisted', False) and db.execute('SELECT id FROM scans WHERE id=?', (result.scan_id,)).fetchone() is None:
                raise LookupError('The scan was deleted.')
            db.execute('''INSERT INTO scans VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET payload=excluded.payload''',
                (result.scan_id, result.created_at.isoformat(), result.sample,
                 json.dumps(result.source_types), result.event_count, len(result.alerts),
                 len(result.incidents), result.model_dump_json()))
            db.execute('DELETE FROM events WHERE scan_id=?', (result.scan_id,))
            db.executemany('INSERT INTO events VALUES (?,?,?)',
                          [(result.scan_id, e.id, e.model_dump_json()) for e in store.events])

        store.persisted = True

    def load(self, scan_id):
        with self.connect() as db:
            db.execute('BEGIN')
            row = db.execute('SELECT payload FROM scans WHERE id=?', (scan_id,)).fetchone()
            if row is None:
                return None
            result = ScanResult.model_validate_json(row[0])
            events = [LogEvent.model_validate_json(row[0]) for row in
                      db.execute('SELECT payload FROM events WHERE scan_id=? ORDER BY id', (scan_id,))]
        events.sort(key=lambda e: (e.timestamp, e.id))
        from app.localization import refresh_legacy_labels, refresh_legacy_reports
        refresh_legacy_labels(result, events)
        store = EvidenceStore(events, result.alerts, result.incidents)
        refresh_legacy_reports(store, result)
        # Persist answered questions, AI output and scores, not a newly reset investigation.
        store.hypothesis_reports = {r.incident_id: r for r in result.hypotheses}
        store.result = result
        store.persisted = True
        return store

    def history(self, limit=50, offset=0):
        from app.localization import english_sample_label
        with self.connect() as db:
            db.execute('BEGIN')
            total = db.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
            rows = db.execute('''SELECT id,created_at,sample,source_types,event_count,alert_count,incident_count
                FROM scans ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?''', (limit, offset)).fetchall()
        return {'items': [dict(scan_id=r[0], created_at=r[1], sample=english_sample_label(r[2]), source_types=json.loads(r[3]),
                              event_count=r[4], alert_count=r[5], incident_count=r[6]) for r in rows],
                'total': total, 'limit': limit, 'offset': offset}

    def delete(self, scan_id):
        with self.connect() as db, db:
            return db.execute('DELETE FROM scans WHERE id=?', (scan_id,)).rowcount > 0


repository = ScanRepository()
