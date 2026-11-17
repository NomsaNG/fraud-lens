import os
import sqlite3
from contextlib import contextmanager


def db_path() -> str:
    return os.getenv("DATABASE_PATH", "fraud_lens.db")


@contextmanager
def connection():
    db = sqlite3.connect(db_path(), timeout=5)
    try:
        db.execute("CREATE TABLE IF NOT EXISTS events (channel TEXT NOT NULL, event_id TEXT NOT NULL, status TEXT NOT NULL, gateway_id TEXT, updated_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(channel,event_id))")
        db.commit()
        yield db
        db.commit()
    finally:
        db.close()


def claim(channel: str, event_id: str) -> bool:
    with connection() as db:
        cursor = db.execute("INSERT OR IGNORE INTO events(channel,event_id,status) VALUES(?,?,'processing')", (channel, event_id))
        return cursor.rowcount == 1


def mark(channel: str, event_id: str, status: str, gateway_id: str | None = None) -> None:
    with connection() as db:
        db.execute("UPDATE events SET status=?, gateway_id=?, updated_at=CURRENT_TIMESTAMP WHERE channel=? AND event_id=?", (status, gateway_id, channel, event_id))


def event_status(channel: str, event_id: str) -> str | None:
    with connection() as db:
        row = db.execute("SELECT status FROM events WHERE channel=? AND event_id=?", (channel, event_id)).fetchone()
        return row[0] if row else None


def delivery(message_id: str, status: str) -> None:
    with connection() as db:
        db.execute("UPDATE events SET status=?, updated_at=CURRENT_TIMESTAMP WHERE gateway_id=?", ("delivery:" + status[:40], message_id))
