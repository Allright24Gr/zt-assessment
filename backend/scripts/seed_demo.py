"""
seed_demo.py — 데모 촬영용 진단 데이터 생성
- Organization / User 1개
- 완료된 세션 1개 (결과/리포트 페이지용)
- 진행 중인 세션 1개 (InProgress 페이지용)

실행: python backend/scripts/seed_demo.py
중복 실행 시 데모 조직이 이미 있으면 건너뜀.
"""
import sys, os, random
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from database import SessionLocal
from models import (
    Organization, User, DiagnosisSession,
    Checklist, CollectedData, DiagnosisResult,
    MaturityScore, ScoreHistory, ImprovementGuide,
)
from scoring.engine import score_session, determine_maturity_level

# ─── 데모 분포 설정 ───────────────────────────────────────────────────────────
# check_id % 10 으로 결과 결정 → 매번 동일한 결과
TOOL_RESULT_TABLE = {
    # (0~9) → 결과
    "keycloak": [
        "충족","충족","충족","충족","충족",
        "충족","부분충족","부분충족","미충족","충족",
    ],
    "wazuh": [
        "충족","충족","충족","충족","부분충족",
        "충족","부분충족","미충족","충족","충족",
    ],
    "nmap": [
        "충족","부분충족","미충족","충족","부분충족",
        "충족","미충족","부분충족","충족","충족",
    ],
    "trivy": [
        "충족","부분충족","미충족","부분충족","충족",
        "미충족","충족","부분충족","충족","부분충족",
    ],
    "수동": [
        "충족","충족","부분충족","충족","미충족",
        "충족","충족","부분충족","충족","충족",
    ],
}

RESULT_WEIGHT = {"충족": 1.0, "부분충족": 0.5, "미충족": 0.0, "평가불가": 0.0}

RECOMMENDATION = {
    "충족": "",
    "부분충족": "설정 검토 및 보완이 필요합니다.",
    "미충족": "즉시 조치가 필요합니다. 담당자 지정 후 개선 계획을 수립하세요.",
    "평가불가": "진단 항목 재확인이 필요합니다.",
}


def _result_for(check_id: int, tool: str) -> str:
    table = TOOL_RESULT_TABLE.get(tool, TOOL_RESULT_TABLE["수동"])
    return table[check_id % 10]


def _mock_collected(check_id: int, tool: str, result: str):
    """결과에 맞는 가짜 수집 데이터 생성"""
    weight = RESULT_WEIGHT[result]
    if result == "충족":
        metric_value, threshold = 1.0, 1.0
    elif result == "부분충족":
        metric_value, threshold = 0.7, 1.0
    else:
        metric_value, threshold = 0.2, 1.0

    raw = {
        "demo": True,
        "tool": tool,
        "check_id": check_id,
        "observed": f"시뮬레이션 수집 결과 — {result}",
    }
    return dict(
        tool=tool,
        metric_key=f"demo_metric_{check_id}",
        metric_value=metric_value,
        threshold=threshold,
        raw_json=raw,
    )


def seed_demo():
    db = SessionLocal()
    try:
        # ── 중복 방지 ────────────────────────────────────────────────────────
        if db.query(Organization).filter(Organization.name == "데모_조직").first():
            print("[seed_demo] 데모 데이터 이미 존재 — 건너뜀")
            return

        # ── 조직 / 사용자 ─────────────────────────────────────────────────
        org = Organization(
            name="데모_조직",
            industry="금융",
            size="중견기업",
            cloud_type="하이브리드",
        )
        db.add(org)
        db.flush()

        user = User(
            org_id=org.org_id,
            name="데모 관리자",
            email="demo@readyz-t.local",
            role="admin",
            mfa_enabled=1,
        )
        db.add(user)
        db.flush()

        # ── 체크리스트 로드 ──────────────────────────────────────────────
        checklists = db.query(Checklist).all()
        if not checklists:
            print("[seed_demo] Checklist 테이블이 비어 있음. seed_checklist.py 먼저 실행하세요.")
            return

        # ════════════════════════════════════════════════════════════════════
        # 세션 1: 완료된 진단 (결과/리포트 페이지용)
        # ════════════════════════════════════════════════════════════════════
        started_at  = datetime.now(timezone.utc) - timedelta(hours=2)
        completed_at = datetime.now(timezone.utc) - timedelta(minutes=30)

        session1 = DiagnosisSession(
            org_id=org.org_id,
            user_id=user.user_id,
            status="완료",
            started_at=started_at,
            selected_tools={"keycloak": True, "wazuh": True, "nmap": True, "trivy": True},
            extra={
                "department":   "정보보안팀",
                "employees":    420,
                "servers":      62,
                "applications": 24,
                "note":         "분기별 정기 진단",
                "pillar_scope": {
                    "Identify": True, "Device": True, "Network": True,
                    "System": True, "Application": True, "Data": True,
                },
            },
        )
        db.add(session1)
        db.flush()

        # 수집 데이터 & 진단 결과 생성
        collected_for_engine = []
        for cl in checklists:
            result = _result_for(cl.check_id, cl.tool)
            cdata  = _mock_collected(cl.check_id, cl.tool, result)

            db.add(CollectedData(
                session_id=session1.session_id,
                check_id=cl.check_id,
                **cdata,
            ))

            score = cl.maturity_score * RESULT_WEIGHT[result]
            db.add(DiagnosisResult(
                session_id=session1.session_id,
                check_id=cl.check_id,
                result=result,
                score=score,
                recommendation=RECOMMENDATION[result],
            ))

            collected_for_engine.append({
                "check_id":     cl.check_id,
                "item_id":      cl.item_id,
                "pillar":       cl.pillar,
                "tool":         cl.tool,
                "metric_value": cdata["metric_value"],
                "threshold":    cdata["threshold"],
                "maturity_score": cl.maturity_score,
            })

        # 점수 계산 (scoring engine 재사용)
        checklist_meta = [
            {
                "check_id":     cl.check_id,
                "item_id":      cl.item_id,
                "pillar":       cl.pillar,
                "maturity_score": cl.maturity_score,
            }
            for cl in checklists
        ]
        output = score_session(session1.session_id, collected_for_engine, checklist_meta)

        # 필라별 pass/fail/na 집계
        pillar_counts: dict = {}
        for cr in output["checklist_results"]:
            p = cr.get("pillar", "미분류")
            c = pillar_counts.setdefault(p, {"pass": 0, "fail": 0, "na": 0})
            r = cr.get("result", "")
            if r == "충족":              c["pass"] += 1
            elif r in ("미충족","부분충족"): c["fail"] += 1
            else:                         c["na"]   += 1

        for pillar, score in output["pillar_scores"].items():
            c = pillar_counts.get(pillar, {"pass": 0, "fail": 0, "na": 0})
            db.add(MaturityScore(
                session_id=session1.session_id,
                pillar=pillar,
                score=score,
                level=determine_maturity_level(score),
                pass_cnt=c["pass"],
                fail_cnt=c["fail"],
                na_cnt=c["na"],
            ))

        db.add(ScoreHistory(
            session_id=session1.session_id,
            org_id=org.org_id,
            pillar_scores=output["pillar_scores"],
            total_score=output["total_score"],
            maturity_level=output["maturity_level"],
            assessed_at=completed_at,
        ))

        session1.status       = "완료"
        session1.level        = output["maturity_level"]
        session1.total_score  = output["total_score"]
        session1.completed_at = completed_at
        db.flush()

        # ════════════════════════════════════════════════════════════════════
        # 세션 2: 진행 중인 진단 (InProgress 페이지용)
        # ════════════════════════════════════════════════════════════════════
        session2 = DiagnosisSession(
            org_id=org.org_id,
            user_id=user.user_id,
            status="진행 중",
            started_at=datetime.now(timezone.utc) - timedelta(minutes=3),
            selected_tools={"keycloak": True, "wazuh": True, "nmap": True, "trivy": True},
            extra={"note": "자동 수집 시연용"},
        )
        db.add(session2)
        db.flush()

        # 자동수집 항목만 절반 수집된 상태로 시뮬레이션
        auto_items = [cl for cl in checklists if cl.tool != "수동"]
        partial    = auto_items[: len(auto_items) // 2]
        for cl in partial:
            result = _result_for(cl.check_id, cl.tool)
            cdata  = _mock_collected(cl.check_id, cl.tool, result)
            db.add(CollectedData(
                session_id=session2.session_id,
                check_id=cl.check_id,
                **cdata,
            ))

        db.commit()

        print(f"[seed_demo] 완료 세션 ID: {session1.session_id}  "
              f"(총점 {output['total_score']:.2f}, {output['maturity_level']})")
        print(f"[seed_demo] 진행 중 세션 ID: {session2.session_id}")
        print(f"[seed_demo] 조직 ID: {org.org_id}, 사용자 ID: {user.user_id}")

    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


if __name__ == "__main__":
    seed_demo()
