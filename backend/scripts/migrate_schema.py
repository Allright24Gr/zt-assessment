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
    # P0-5 약관·개인정보 처리방침 동의 시점
    ("User",             "tos_agreed_at",     "DATETIME NULL"),
    ("User",             "privacy_agreed_at", "DATETIME NULL"),
    # P1-7: 수동 증적 파일 업로드 메타데이터
    ("Evidence",         "file_path",         "VARCHAR(500) NULL"),
    ("Evidence",         "mime_type",         "VARCHAR(120) NULL"),
    ("Evidence",         "file_size",         "INT NULL"),
    ("Evidence",         "original_filename", "VARCHAR(255) NULL"),
]


# 신규 테이블 (CREATE IF NOT EXISTS). 도커 fresh start 시 SQLAlchemy create_all 이 처리하지만,
# 기존 환경 마이그레이션을 위해 명시 CREATE 도 함께.
NEW_TABLES = [
    ("AuthAuditLog", """
        CREATE TABLE IF NOT EXISTS `AuthAuditLog` (
            `audit_id`   INT NOT NULL AUTO_INCREMENT,
            `event_type` VARCHAR(50)  NOT NULL,
            `user_id`    INT NULL,
            `login_id`   VARCHAR(100) NULL,
            `source_ip`  VARCHAR(64)  NULL,
            `user_agent` VARCHAR(500) NULL,
            `success`    INT NOT NULL DEFAULT 1,
            `detail`     JSON NULL,
            `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (`audit_id`),
            KEY `idx_audit_event_type` (`event_type`),
            KEY `idx_audit_user_id`    (`user_id`),
            KEY `idx_audit_created_at` (`created_at`),
            CONSTRAINT `fk_audit_user_id`
              FOREIGN KEY (`user_id`) REFERENCES `User`(`user_id`) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """),
    # P1-11: 외부 공유 링크 토큰
    ("SharedResult", """
        CREATE TABLE IF NOT EXISTS `SharedResult` (
            `share_id`           INT NOT NULL AUTO_INCREMENT,
            `session_id`         INT NOT NULL,
            `token_hash`         VARCHAR(128) NOT NULL,
            `created_by_user_id` INT NOT NULL,
            `expires_at`         DATETIME NOT NULL,
            `revoked_at`         DATETIME NULL,
            `created_at`         DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (`share_id`),
            UNIQUE KEY `uq_shared_result_token` (`token_hash`),
            KEY `idx_shared_result_session` (`session_id`),
            KEY `idx_shared_result_token`   (`token_hash`),
            CONSTRAINT `fk_shared_result_session`
              FOREIGN KEY (`session_id`) REFERENCES `DiagnosisSession`(`session_id`) ON DELETE CASCADE,
            CONSTRAINT `fk_shared_result_user`
              FOREIGN KEY (`created_by_user_id`) REFERENCES `User`(`user_id`) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """),
    # 비밀번호 재설정 토큰 — 평문은 메일로 전송, DB에는 SHA-256 해시만 저장
    ("PasswordResetToken", """
        CREATE TABLE IF NOT EXISTS `PasswordResetToken` (
            `token_id`   INT NOT NULL AUTO_INCREMENT,
            `user_id`    INT NOT NULL,
            `token_hash` VARCHAR(128) NOT NULL,
            `expires_at` DATETIME NOT NULL,
            `used_at`    DATETIME NULL,
            `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (`token_id`),
            UNIQUE KEY `uq_password_reset_token` (`token_hash`),
            KEY `idx_password_reset_user` (`user_id`),
            CONSTRAINT `fk_password_reset_user`
              FOREIGN KEY (`user_id`) REFERENCES `User`(`user_id`) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """),
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

        # 3) 신규 테이블 (idempotent CREATE IF NOT EXISTS)
        for table_name, ddl in NEW_TABLES:
            print(f"[migrate] ensuring table {table_name}")
            conn.execute(text(ddl))


if __name__ == "__main__":
    run()
