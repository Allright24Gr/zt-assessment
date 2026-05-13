"""
seed_checklist.py — 체크리스트 DB 적재 스크립트
데이터 소스: /root/projects/신뢰많이된다_체크리스트_매핑_v7.xlsx  시트: 체크리스트_도구매핑
실행: python backend/scripts/seed_checklist.py
"""
import sys
import os
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import openpyxl
except ImportError:
    print("openpyxl 미설치: pip install openpyxl")
    sys.exit(1)

from database import SessionLocal
from models import Checklist

# ─── 상수 ────────────────────────────────────────────────────────────────────

MATURITY_NUM = {"기존": 1, "초기": 2, "향상": 3, "최적화": 4}
MATURITY_SCORE = {"기존": 1, "초기": 2, "향상": 3, "최적화": 4}
MATURITY_WEIGHT = {"기존": 0.1, "초기": 0.2, "향상": 0.3, "최적화": 0.4}

TOOL_MAP = {
    "수동": "수동",
    "Keycloak": "keycloak",
    "Wazuh": "wazuh",
    "Nmap (래퍼 필요)": "nmap",
    "Trivy (래퍼 필요)": "trivy",
}

# xlsx 헤더 → 컬럼 인덱스 (0-based)
# ['구분', '항목', '성숙도', '세부 질문', '진단유형', '사용 도구', '증적',
#  '판정 기준', '추출 필드', '처리 로직 (분자/분모)', '예외 처리']
COL = {
    "pillar": 0,
    "category": 1,
    "maturity": 2,
    # '세부 질문' (index 3) → 저장하지 않음
    "diagnosis_type": 4,
    "tool": 5,
    "evidence": 6,
    "criteria": 7,
    "fields": 8,
    "logic": 9,
    "exceptions": 10,
}


def _find_xlsx() -> Path:
    candidates = [
        Path("/app/신뢰많이된다_체크리스트_매핑_v7.xlsx"),
        Path("/root/projects/신뢰많이된다_체크리스트_매핑_v7.xlsx"),
        Path(__file__).parent.parent.parent / "신뢰많이된다_체크리스트_매핑_v7.xlsx",
    ]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError(
        "xlsx 파일을 찾을 수 없습니다. 경로 확인: " + str(candidates[0])
    )


def _cell(row, col: int) -> str:
    val = row[col]
    if val is None:
        return ""
    return str(val).strip()


def load_rows(xlsx_path: Path) -> list:
    wb = openpyxl.load_workbook(xlsx_path, read_only=True, data_only=True)
    ws = wb["체크리스트_도구매핑"]

    rows = list(ws.iter_rows(min_row=2, values_only=True))
    wb.close()

    counter = defaultdict(int)
    result = []

    for raw in rows:
        if not any(raw):
            continue
        if len(raw) < 11:
            continue

        pillar = _cell(raw, COL["pillar"])
        category_full = _cell(raw, COL["category"])  # "1.1.1 사용자 인벤토리"
        maturity = _cell(raw, COL["maturity"])

        if not pillar or not category_full or maturity not in MATURITY_NUM:
            continue

        # 항목번호 추출 (예: "1.1.1")
        parts = category_full.split(" ", 1)
        item_num = parts[0]
        item_name = parts[1] if len(parts) > 1 else category_full

        maturity_num = MATURITY_NUM[maturity]
        base = f"{item_num}.{maturity_num}"
        counter[base] += 1
        item_id = f"{base}_{counter[base]}"

        tool_raw = _cell(raw, COL["tool"])
        tool = TOOL_MAP.get(tool_raw, tool_raw.lower() if tool_raw else "수동")

        result.append({
            "item_id": item_id,
            "item_num": item_num,
            "pillar": pillar,
            "category": category_full,
            "item_name": item_name,
            "maturity": maturity,
            "maturity_score": MATURITY_SCORE[maturity],
            "weight": MATURITY_WEIGHT[maturity],
            "diagnosis_type": _cell(raw, COL["diagnosis_type"]) or "수동",
            "tool": tool,
            "evidence": _cell(raw, COL["evidence"]) or None,
            "criteria": _cell(raw, COL["criteria"]) or None,
            "fields": _cell(raw, COL["fields"]) or None,
            "logic": _cell(raw, COL["logic"]) or None,
            "exceptions": _cell(raw, COL["exceptions"]) or None,
        })

    return result


def seed():
    xlsx_path = _find_xlsx()
    print(f"xlsx 파일 로드: {xlsx_path}")
    rows = load_rows(xlsx_path)
    print(f"파싱된 행 수: {len(rows)}")

    db = SessionLocal()
    inserted = 0
    updated = 0

    try:
        for d in rows:
            existing = db.query(Checklist).filter(
                Checklist.item_id == d["item_id"]
            ).first()

            if existing:
                for k, v in d.items():
                    setattr(existing, k, v)
                updated += 1
            else:
                db.add(Checklist(**d))
                inserted += 1

        db.commit()
        print(f"완료: {inserted}건 신규 삽입, {updated}건 업데이트 (총 {len(rows)}건)")
    except Exception as exc:
        db.rollback()
        print(f"오류: {exc}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed()
