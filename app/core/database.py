import json
import sqlite3
from pathlib import Path


DATA_DIR = Path("data")
DATABASE_PATH = DATA_DIR / "sla.db"


def get_connection():
    """
    Cria e retorna uma conexão com o banco SQLite.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """
    Cria as tabelas necessárias caso ainda não existam.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS capture_history (
            capture_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            capture_mode TEXT NOT NULL,
            packet_limit INTEGER NOT NULL,
            iface TEXT,
            protocol_filter TEXT,
            host_filter TEXT,
            started_at TEXT,
            stopped_at TEXT,
            error_message TEXT,
            total_packets INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            report_json TEXT NOT NULL
        )
        """
    )

    connection.commit()
    connection.close()


def save_capture_history_item(item: dict):
    """
    Salva uma captura no histórico do banco.
    """
    initialize_database()

    report_json = json.dumps(
        item["report"],
        ensure_ascii=False,
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT OR REPLACE INTO capture_history (
            capture_id,
            status,
            capture_mode,
            packet_limit,
            iface,
            protocol_filter,
            host_filter,
            started_at,
            stopped_at,
            error_message,
            total_packets,
            risk_level,
            report_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            item["capture_id"],
            item["status"],
            item["capture_mode"],
            item["packet_limit"],
            item["iface"],
            item["protocol_filter"],
            item["host_filter"],
            item["started_at"],
            item["stopped_at"],
            item["error_message"],
            item["total_packets"],
            item["risk_level"],
            report_json,
        ),
    )

    connection.commit()
    connection.close()


def load_capture_history(limit: int = 20) -> list[dict]:
    """
    Carrega o histórico resumido das últimas capturas.
    """
    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            capture_id,
            status,
            capture_mode,
            packet_limit,
            iface,
            protocol_filter,
            host_filter,
            started_at,
            stopped_at,
            error_message,
            total_packets,
            risk_level,
            report_json
        FROM capture_history
        ORDER BY started_at DESC
        LIMIT ?
        """,
        (limit,),
    )

    rows = cursor.fetchall()
    connection.close()

    history = []

    for row in rows:
        report = json.loads(row["report_json"])

        history.append(
            {
                "capture_id": row["capture_id"],
                "status": row["status"],
                "capture_mode": row["capture_mode"],
                "packet_limit": row["packet_limit"],
                "iface": row["iface"],
                "protocol_filter": row["protocol_filter"],
                "host_filter": row["host_filter"],
                "started_at": row["started_at"],
                "stopped_at": row["stopped_at"],
                "error_message": row["error_message"],
                "total_packets": row["total_packets"],
                "risk_level": row["risk_level"],
                "report": report,
            }
        )

    return history


def load_capture_report(capture_id: str) -> dict | None:
    """
    Carrega o relatório completo de uma captura específica.
    """
    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT report_json
        FROM capture_history
        WHERE capture_id = ?
        """,
        (capture_id,),
    )

    row = cursor.fetchone()
    connection.close()

    if row is None:
        return None

    return json.loads(row["report_json"])


def clear_capture_history():
    """
    Remove todo o histórico salvo no banco.
    """
    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("DELETE FROM capture_history")

    connection.commit()
    connection.close()