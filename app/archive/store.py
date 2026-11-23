import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

from app.archive.manifest import canonical
from app.errors import InputError


class Archive:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.execute('CREATE TABLE IF NOT EXISTS monitoring (id TEXT PRIMARY KEY, packet TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS authorizations '
                       '(id TEXT PRIMARY KEY, run_id TEXT NOT NULL, packet TEXT NOT NULL)')
            db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_authorizations_run_hour '
                       "ON authorizations(run_id, json_extract(packet, '$.scope.hour'))")

    @contextmanager
    def connection(self):
        with closing(sqlite3.connect(self.path, timeout=15)) as db, db:
            yield db

    def lookup(self, run_id):
        with self.connection() as db:
            row = db.execute('SELECT packet FROM monitoring WHERE id = ?', (run_id,)).fetchone()
        return None if row is None else json.loads(row[0])

    def require(self, run_id):
        packet = self.lookup(run_id)
        if packet is None:
            raise InputError('RUN_UNKNOWN', '找不到监测留档', 404)
        return packet

    def commit(self, run_id, packet):
        with self.connection() as db:
            cursor = db.execute('INSERT INTO monitoring VALUES (?, ?) ON CONFLICT(id) DO NOTHING',
                                (run_id, canonical(packet)))
            reused = cursor.rowcount == 0
            record = db.execute('SELECT packet FROM monitoring WHERE id = ?', (run_id,)).fetchone()[0]
        return json.loads(record), reused

    def history(self):
        with self.connection() as db:
            return [json.loads(row[0]) for row in db.execute(
                "SELECT json_extract(packet, '$.manifest') FROM monitoring ORDER BY rowid DESC LIMIT 100")]

    def lookup_authorization(self, auth_id):
        with self.connection() as db:
            row = db.execute('SELECT packet FROM authorizations WHERE id = ?', (auth_id,)).fetchone()
        return None if row is None else json.loads(row[0])

    def find_authorization(self, run_id, hour):
        with self.connection() as db:
            row = db.execute(
                "SELECT packet FROM authorizations WHERE run_id = ? AND json_extract(packet, '$.scope.hour') = ?",
                (run_id, hour)).fetchone()
        return None if row is None else json.loads(row[0])

    def commit_authorization(self, auth_id, run_id, packet):
        # 同一次授权（run + 授权小时）只允许一份证据单。唯一索引保证并发重试也只会
        # 留下一行：冲突时整条复用既有证据，不覆盖、不新增。
        with self.connection() as db:
            cursor = db.execute(
                'INSERT INTO authorizations VALUES (?, ?, ?) '
                "ON CONFLICT(run_id, json_extract(packet, '$.scope.hour')) DO NOTHING",
                (auth_id, run_id, canonical(packet)))
            inserted = cursor.rowcount == 1
            row = db.execute(
                "SELECT packet FROM authorizations WHERE run_id = ? "
                "AND json_extract(packet, '$.scope.hour') = ?",
                (run_id, packet['scope']['hour'])).fetchone()
        return json.loads(row[0]), inserted

    def authorizations(self, run_id):
        with self.connection() as db:
            rows = db.execute(
                "SELECT packet FROM authorizations WHERE run_id = ? ORDER BY rowid", (run_id,)).fetchall()
        return [json.loads(row[0]) for row in rows]
