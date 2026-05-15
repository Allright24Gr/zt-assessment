"""schema 마이그레이션 — 기존 DB에 빠진 컬럼만 ALTER로 추가 (idempotent)."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import text
from database import engine


MIGRATIONS = [
    # (테이블, 컬럼, 컬럼 타입)
    ("DiagnosisSession", "selected_tools", "JSON NULL"),
    ("DiagnosisSession", "extra",          "JSON NULL"),
    # 회원가입 / 로그인용
    ("User",             "login_id",       "VARCHAR(100) NULL UNIQUE"),
    ("User",             "password_hash",  "VARCHAR(200) NULL"),
    ("User",             "profile",        "JSON NULL"),
]

# 한글 ENUM은 charset 미스매치 시 'Data truncated' 에러를 자주 일으킴.
# VARCHAR로 변환하여 안정성 확보.
ENUM_TO_VARCHAR = [
    ("DiagnosisSession", "status", "VARCHAR(20) NOT NULL DEFAULT '진행 중'"),
    ("DiagnosisResult",  "result", "VARCHAR(10) NOT NULL"),
    ("ImprovementGuide", "term",   "VARCHAR(10) NOT NULL"),
]


def column_exists(conn, table: str, column: str) -> bool:
    row = conn.execute(text("""
        SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t AND COLUMN_NAME = :c
    """), {"t": table, "c": column}).scalar()
    return bool(row)


def column_type(conn, table: str, column: str) -> str:
    row = conn.execute(text("""
        SELECT COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t AND COLUMN_NAME = :c
    """), {"t": table, "c": column}).scalar()
    return (row or "").lower()


def run():
    with engine.begin() as conn:
        # 1) 새 컬럼 추가
        for table, column, coltype in MIGRATIONS:
            if column_exists(conn, table, column):
                print(f"[migrate] {table}.{column} 이미 존재 — 건너뜀")
                continue
            sql = f"ALTER TABLE `{table}` ADD COLUMN `{column}` {coltype}"
            print(f"[migrate] {sql}")
            conn.execute(text(sql))

        # 2) ENUM → VARCHAR 변환 (한글 charset 문제 해결)
        for table, column, coltype in ENUM_TO_VARCHAR:
            current = column_type(conn, table, column)
            if not current.startswith("enum"):
                continue
            sql = f"ALTER TABLE `{table}` MODIFY COLUMN `{column}` {coltype}"
            print(f"[migrate] {sql}")
            conn.execute(text(sql))


if __name__ == "__main__":
    run()
