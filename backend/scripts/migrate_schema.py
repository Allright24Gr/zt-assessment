"""schema 마이그레이션 — 기존 DB에 빠진 컬럼만 ALTER로 추가 (idempotent)."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import text
from database import engine


MIGRATIONS = [
    # (테이블, 컬럼, 컬럼 타입)
    ("DiagnosisSession", "selected_tools", "JSON NULL"),
    ("DiagnosisSession", "extra",          "JSON NULL"),
]


def column_exists(conn, table: str, column: str) -> bool:
    row = conn.execute(text("""
        SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t AND COLUMN_NAME = :c
    """), {"t": table, "c": column}).scalar()
    return bool(row)


def run():
    with engine.begin() as conn:
        for table, column, coltype in MIGRATIONS:
            if column_exists(conn, table, column):
                print(f"[migrate] {table}.{column} 이미 존재 — 건너뜀")
                continue
            sql = f"ALTER TABLE `{table}` ADD COLUMN `{column}` {coltype}"
            print(f"[migrate] {sql}")
            conn.execute(text(sql))


if __name__ == "__main__":
    run()
