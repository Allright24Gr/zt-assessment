"""체크리스트 ↔ 도구 매핑 학술 검증

xlsx(체크리스트_도구매핑 시트)와 우리 _full_mapping 결과를 대조해
1) 잘못된 item_id 매핑, 2) 자동 진단인데 매핑 없음, 3) 다중 매핑 분포를 출력.

실행: docker exec zt-assessment-zt-backend-1 python /app/scripts/validate_checklist_mapping.py
"""
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import openpyxl  # noqa: E402
from routers import assessment as A  # noqa: E402

MATURITY_NUM = {"기존": 1, "초기": 2, "향상": 3, "최적화": 4}


def _find_xlsx() -> Path:
    candidates = [
        Path("/app/zt-checklist.xlsx"),
        Path(__file__).parent.parent / "zt-checklist.xlsx",
        Path(__file__).parent.parent.parent / "zt-checklist.xlsx",
    ]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError("xlsx 파일을 찾을 수 없습니다.")


def load_xlsx_items():
    xlsx_path = _find_xlsx()
    wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    ws = wb["체크리스트_도구매핑"]
    counter = defaultdict(int)
    items = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not any(row) or len(row) < 11:
            continue
        pillar = str(row[0] or "").strip()
        category = str(row[1] or "").strip()
        maturity = str(row[2] or "").strip()
        diag_type = str(row[4] or "").strip()
        tool = str(row[5] or "").strip()
        if not pillar or not category or maturity not in MATURITY_NUM:
            continue
        item_num = category.split(" ", 1)[0]
        base = f"{item_num}.{MATURITY_NUM[maturity]}"
        counter[base] += 1
        items.append(
            {
                "item_id": f"{base}_{counter[base]}",
                "pillar": pillar,
                "category": category,
                "maturity": maturity,
                "tool": tool,
                "diagnosis_type": diag_type,
            }
        )
    wb.close()
    return items


def main():
    xlsx_items = load_xlsx_items()
    print(f"xlsx 총 항목: {len(xlsx_items)}")
    auto_n = sum(1 for x in xlsx_items if x["diagnosis_type"] == "자동")
    manual_n = len(xlsx_items) - auto_n
    print(f"  자동: {auto_n}  수동: {manual_n}")
    print(f"  tool 분포: {dict(Counter(x['tool'] for x in xlsx_items))}")

    print(f"\nALL_TOOLS({len(A.ALL_TOOLS)}): {A.ALL_TOOLS}")

    mapping_by_item: dict[str, set[str]] = defaultdict(set)
    for tool in A.ALL_TOOLS:
        try:
            m = A._full_mapping(tool)
        except Exception as exc:
            print(f"  ERROR {tool}: {exc}")
            continue
        print(f"  {tool}: {len(m)} 매핑")
        # _full_mapping 반환 형식: list[(callable, item_id, maturity)]
        for entry in m:
            if len(entry) >= 2:
                item_id = entry[1]
                mapping_by_item[item_id].add(tool)

    xlsx_ids = {x["item_id"] for x in xlsx_items}
    auto_ids = {x["item_id"] for x in xlsx_items if x["diagnosis_type"] == "자동"}

    # 검증 1: xlsx에 없는 item_id
    invalid = sorted(iid for iid in mapping_by_item if iid not in xlsx_ids)
    print(f"\n[검증 1] 잘못된 item_id (xlsx에 없는데 우리 매핑됨): {len(invalid)}건")
    for iid in invalid[:20]:
        tools = sorted(mapping_by_item[iid])
        print(f"  - {iid}  tools={tools}")

    # 검증 2: xlsx 자동인데 매핑 없음
    missing = sorted(auto_ids - set(mapping_by_item.keys()))
    print(f"\n[검증 2] xlsx 자동 진단인데 우리 매핑 없음: {len(missing)}건")
    pillar_missing = Counter()
    for iid in missing:
        info = next((x for x in xlsx_items if x["item_id"] == iid), None)
        if info:
            pillar_missing[info["pillar"]] += 1
            print(f"  - {iid}  xlsx_tool={info['tool']:8s} maturity={info['maturity']}  category={info['category']}")
    print(f"\n  pillar별 누락: {dict(pillar_missing)}")

    # 검증 3: 다중 매핑 분포 (의도된 IdP/SIEM/EDR/Cloud/ZTNA 공통 항목)
    multi = {iid: sorted(tools) for iid, tools in mapping_by_item.items() if len(tools) >= 2}
    print(f"\n[검증 3] 다중 도구 매핑 항목: {len(multi)}건")
    pattern_counter = Counter(tuple(t) for t in multi.values())
    for p, c in pattern_counter.most_common():
        print(f"  {c}건: {p}")

    # 검증 4: xlsx 수동 vs 우리 매핑 충돌 (수동인데 우리가 자동 처리하면 잘못)
    manual_ids = {x["item_id"] for x in xlsx_items if x["diagnosis_type"] != "자동"}
    conflict = sorted(manual_ids & set(mapping_by_item.keys()))
    print(f"\n[검증 4] xlsx 수동인데 우리 자동 매핑 (덮어쓰기 위험): {len(conflict)}건")
    for iid in conflict[:20]:
        info = next((x for x in xlsx_items if x["item_id"] == iid), None)
        tools = sorted(mapping_by_item[iid])
        if info:
            print(f"  - {iid}  xlsx_diag={info['diagnosis_type']}  우리매핑={tools}")

    print("\n=== 요약 ===")
    print(f"xlsx 자동:                  {len(auto_ids)}")
    print(f"우리 매핑 unique item_id:   {len(mapping_by_item)}")
    print(f"누락(매핑 추가 필요):       {len(missing)}")
    print(f"잘못된 매핑:                {len(invalid)}")
    print(f"수동인데 자동 매핑(충돌):   {len(conflict)}")
    print(f"다중 매핑(의도된 카테고리): {len(multi)}")


if __name__ == "__main__":
    main()
