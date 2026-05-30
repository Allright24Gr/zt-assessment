"""backup_db.py — DB 논리 백업/복구 (MAR-014).

외부 mysqldump 바이너리에 의존하지 않고 SQLAlchemy 메타데이터를 순회해 모든 테이블
행을 gzip JSON 으로 덤프한다(컨테이너 어디서나 동작). 복구는 트랜잭션 안에서 기존
행을 비우고 백업 내용을 재삽입한다.

CLI:
  python scripts/backup_db.py backup            # 백업 생성
  python scripts/backup_db.py list              # 백업 목록
  python scripts/backup_db.py restore <file>    # 복구 (주의: 덮어쓰기)
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from database import engine, Base
import models  # noqa: F401 — Base.metadata 채우기 위해 import 필요


def _backup_dir() -> Path:
    d = Path(os.getenv("ZTA_BACKUP_DIR", "/app/backups"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _json_default(o):
    if isinstance(o, (datetime,)):
        return o.isoformat()
    if isinstance(o, (bytes, bytearray)):
        return o.decode("utf-8", "replace")
    return str(o)


def create_backup(backup_dir: str | None = None) -> dict:
    """전체 테이블을 gzip JSON 으로 덤프. 메타데이터 dict 반환."""
    out_dir = Path(backup_dir) if backup_dir else _backup_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fname = f"zt_backup_{ts}.json.gz"
    fpath = out_dir / fname

    dump: dict = {"_meta": {"created_at": datetime.now(timezone.utc).isoformat(), "tables": []}, "tables": {}}
    total_rows = 0
    with engine.connect() as conn:
        for table in Base.metadata.sorted_tables:
            rows = []
            for row in conn.execute(select(table)).mappings():
                rows.append(dict(row))
            dump["tables"][table.name] = rows
            dump["_meta"]["tables"].append(table.name)
            total_rows += len(rows)

    raw = json.dumps(dump, ensure_ascii=False, default=_json_default).encode("utf-8")
    with gzip.open(fpath, "wb") as fp:
        fp.write(raw)

    return {
        "file": str(fpath),
        "filename": fname,
        "size_bytes": fpath.stat().st_size,
        "tables": len(dump["_meta"]["tables"]),
        "rows": total_rows,
        "created_at": dump["_meta"]["created_at"],
    }


def list_backups(backup_dir: str | None = None) -> list[dict]:
    out_dir = Path(backup_dir) if backup_dir else _backup_dir()
    if not out_dir.exists():
        return []
    items = []
    for p in sorted(out_dir.glob("zt_backup_*.json.gz"), reverse=True):
        st = p.stat()
        items.append({
            "filename": p.name,
            "size_bytes": st.st_size,
            "modified_at": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
        })
    return items


def prune_backups(keep: int = 14, backup_dir: str | None = None) -> int:
    """오래된 백업 정리 — 최신 keep 개만 보존. 삭제 건수 반환."""
    out_dir = Path(backup_dir) if backup_dir else _backup_dir()
    files = sorted(out_dir.glob("zt_backup_*.json.gz"), reverse=True)
    removed = 0
    for p in files[keep:]:
        try:
            p.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def restore_backup(path: str) -> dict:
    """백업 파일로 전체 복구. 기존 행을 비우고 재삽입(트랜잭션)."""
    fpath = Path(path)
    if not fpath.is_absolute():
        fpath = _backup_dir() / path
    if not fpath.is_file():
        raise FileNotFoundError(f"백업 파일 없음: {fpath}")
    with gzip.open(fpath, "rb") as fp:
        dump = json.loads(fp.read().decode("utf-8"))

    tables = dump.get("tables", {})
    restored = 0
    with engine.begin() as conn:
        # FK 제약 회피를 위해 자식→부모 역순 삭제, 부모→자식 정순 삽입.
        for table in reversed(Base.metadata.sorted_tables):
            if table.name in tables:
                conn.execute(table.delete())
        for table in Base.metadata.sorted_tables:
            rows = tables.get(table.name) or []
            if rows:
                conn.execute(table.insert(), rows)
                restored += len(rows)
    return {"file": str(fpath), "restored_rows": restored, "tables": len(tables)}


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "backup"
    if cmd == "backup":
        print(create_backup())
    elif cmd == "list":
        for it in list_backups():
            print(it)
    elif cmd == "restore":
        if len(sys.argv) < 3:
            print("usage: backup_db.py restore <file>")
            sys.exit(1)
        print(restore_backup(sys.argv[2]))
    else:
        print(f"unknown command: {cmd}")
        sys.exit(1)
