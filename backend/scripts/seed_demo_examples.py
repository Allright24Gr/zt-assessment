"""seed_demo_examples.py — 시연용 예시 데이터 일괄 생성.

수행 작업:
1) 기존 세션 데이터(DiagnosisSession / CollectedData / DiagnosisResult /
   MaturityScore / ScoreHistory) 전부 삭제
2) 인증 가능한 기본 계정 생성/업데이트:
   - admin / admin   (관리자, '시스템관리' 조직)
   - user1 / user1   (박기웅, '세종대학교' 조직)
3) 관리자 시점에 보일 다양한 조직의 완료된 예시 세션 4건
4) user1(세종대학교) 완료 세션 3건 + 진행 중 세션 1건

실행: python backend/scripts/seed_demo_examples.py
"""
import sys, os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import text
from database import SessionLocal, engine
from models import (
    Organization, User, DiagnosisSession,
    Checklist, CollectedData, DiagnosisResult,
    MaturityScore, ScoreHistory,
)
from scoring.engine import score_session, determine_maturity_level
from routers.auth import _hash_password


RESULT_WEIGHT = {"충족": 1.0, "부분충족": 0.5, "미충족": 0.0, "평가불가": 0.0}

RECOMMENDATION = {
    "충족": "",
    "부분충족": "설정 검토 및 보완이 필요합니다.",
    "미충족": "즉시 조치가 필요합니다. 담당자 지정 후 개선 계획을 수립하세요.",
    "평가불가": "진단 항목 재확인이 필요합니다.",
}

# ─── 결과 분포 프로파일 (score_seed별) ────────────────────────────────────────
# 0=낮음, 1=중하, 2=중상, 3=높음 으로 갈수록 충족 비율 ↑
PROFILES = {
    0: ["충족","부분충족","미충족","미충족","부분충족","미충족","충족","미충족","부분충족","미충족"],
    1: ["충족","충족","부분충족","미충족","부분충족","충족","부분충족","미충족","충족","부분충족"],
    2: ["충족","충족","충족","부분충족","충족","충족","충족","부분충족","충족","미충족"],
    3: ["충족","충족","충족","충족","충족","충족","부분충족","충족","충족","충족"],
}


def _result_for(check_id: int, profile_id: int) -> str:
    table = PROFILES.get(profile_id, PROFILES[1])
    return table[check_id % 10]


def _mock_collected(check_id: int, tool: str, result: str) -> dict:
    if result == "충족":
        metric_value, threshold = 1.0, 1.0
    elif result == "부분충족":
        metric_value, threshold = 0.7, 1.0
    else:
        metric_value, threshold = 0.2, 1.0
    return dict(
        tool=tool,
        metric_key=f"demo_metric_{check_id}",
        metric_value=metric_value,
        threshold=threshold,
        raw_json={"demo": True, "tool": tool, "check_id": check_id, "observed": result},
    )


def _wipe_session_data(db):
    """세션과 관련된 모든 행 삭제 (FK 순서 고려)."""
    print("[wipe] 기존 세션 데이터 삭제...")
    for tbl in ["CollectedData", "DiagnosisResult", "MaturityScore",
                "ScoreHistory", "Evidence"]:
        db.execute(text(f"DELETE FROM `{tbl}`"))
    db.execute(text("DELETE FROM `DiagnosisSession`"))
    db.commit()
    print("[wipe] 완료")


def _wipe_orgs_and_users(db, keep_login_ids: set[str]):
    """auth용 계정(keep_login_ids)을 제외한 모든 User/Organization 삭제.

    User는 login_id가 keep_login_ids에 들어있는 경우에만 살리고, 그 사용자가
    속한 조직도 함께 살린다. 나머지는 모두 삭제.
    """
    print(f"[wipe] login_id != {keep_login_ids} 인 사용자/조직 정리...")
    keep_users = db.query(User).filter(User.login_id.in_(list(keep_login_ids))).all()
    keep_user_ids = {u.user_id for u in keep_users}
    keep_org_ids = {u.org_id for u in keep_users}

    db.query(User).filter(~User.user_id.in_(keep_user_ids) if keep_user_ids else True).delete(synchronize_session=False)
    db.query(Organization).filter(
        ~Organization.org_id.in_(keep_org_ids) if keep_org_ids else True
    ).delete(synchronize_session=False)
    db.commit()
    print("[wipe] 완료")


def _upsert_org(db, name: str, **fields) -> Organization:
    org = db.query(Organization).filter(Organization.name == name).first()
    if not org:
        org = Organization(name=name, **fields)
        db.add(org)
        db.flush()
    else:
        for k, v in fields.items():
            if v is not None:
                setattr(org, k, v)
    return org


def _upsert_auth_user(
    db, *, login_id: str, password: str, name: str, role: str,
    org: Organization, profile: dict | None = None, email: str | None = None,
) -> User:
    email = email or f"{login_id}@local"
    user = db.query(User).filter(User.login_id == login_id).first()
    if not user:
        user = User(
            org_id=org.org_id,
            name=name,
            email=email,
            role=role,
            login_id=login_id,
            password_hash=_hash_password(password),
            profile=profile or None,
        )
        db.add(user)
    else:
        user.org_id = org.org_id
        user.name = name
        user.email = email
        user.role = role
        user.password_hash = _hash_password(password)
        user.profile = profile or None
    db.flush()
    return user


def _create_completed_session(
    db, *, org: Organization, user: User, profile_id: int,
    started_at: datetime, completed_at: datetime, extra: dict,
    selected_tools: dict | None = None,
) -> DiagnosisSession:
    """완료된 세션 1건 + 모든 관련 데이터 생성."""
    selected_tools = selected_tools or {"keycloak": True, "wazuh": True, "nmap": True, "trivy": True}

    session = DiagnosisSession(
        org_id=org.org_id,
        user_id=user.user_id,
        status="진행 중",  # 끝나면 완료로 업데이트
        started_at=started_at,
        selected_tools=selected_tools,
        extra=extra,
    )
    db.add(session)
    db.flush()

    checklists = db.query(Checklist).all()

    collected_for_engine = []
    for cl in checklists:
        result = _result_for(cl.check_id, profile_id)
        cdata = _mock_collected(cl.check_id, cl.tool, result)
        db.add(CollectedData(session_id=session.session_id, check_id=cl.check_id, **cdata))

        score = cl.maturity_score * RESULT_WEIGHT[result]
        db.add(DiagnosisResult(
            session_id=session.session_id, check_id=cl.check_id,
            result=result, score=score,
            recommendation=RECOMMENDATION[result],
        ))

        collected_for_engine.append({
            "check_id": cl.check_id, "item_id": cl.item_id, "pillar": cl.pillar,
            "tool": cl.tool, "metric_value": cdata["metric_value"],
            "threshold": cdata["threshold"], "maturity_score": cl.maturity_score,
        })

    checklist_meta = [
        {"check_id": cl.check_id, "item_id": cl.item_id, "pillar": cl.pillar,
         "maturity_score": cl.maturity_score}
        for cl in checklists
    ]
    output = score_session(session.session_id, collected_for_engine, checklist_meta)

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
            session_id=session.session_id, pillar=pillar, score=score,
            level=determine_maturity_level(score),
            pass_cnt=c["pass"], fail_cnt=c["fail"], na_cnt=c["na"],
        ))

    db.add(ScoreHistory(
        session_id=session.session_id, org_id=org.org_id,
        pillar_scores=output["pillar_scores"],
        total_score=output["total_score"],
        maturity_level=output["maturity_level"],
        assessed_at=completed_at,
    ))

    session.status = "완료"
    session.level = output["maturity_level"]
    session.total_score = output["total_score"]
    session.completed_at = completed_at
    db.flush()
    return session


def _create_inprogress_session(
    db, *, org: Organization, user: User, started_at: datetime,
    extra: dict, partial_ratio: float = 0.5, profile_id: int = 2,
) -> DiagnosisSession:
    session = DiagnosisSession(
        org_id=org.org_id, user_id=user.user_id,
        status="진행 중", started_at=started_at,
        selected_tools={"keycloak": True, "wazuh": True, "nmap": True, "trivy": True},
        extra=extra,
    )
    db.add(session)
    db.flush()

    auto_items = [cl for cl in db.query(Checklist).all() if cl.tool != "수동"]
    cutoff = max(1, int(len(auto_items) * partial_ratio))
    for cl in auto_items[:cutoff]:
        result = _result_for(cl.check_id, profile_id)
        cdata = _mock_collected(cl.check_id, cl.tool, result)
        db.add(CollectedData(session_id=session.session_id, check_id=cl.check_id, **cdata))
    db.flush()
    return session


# ─── 메인 ────────────────────────────────────────────────────────────────────

def seed(force: bool = False):
    db = SessionLocal()
    try:
        if not db.query(Checklist).first():
            print("[seed] Checklist가 비어있음. seed_checklist.py 먼저 실행하세요.")
            return

        # idempotent: admin/user1 상태에 따른 분기
        # - 2개 모두 존재: 스킵 (정상 운영)
        # - 0개: 신규 시드 (안전한 fresh install)
        # - 1개만 존재: 부분 손상. 그대로 wipe하면 가입한 일반 사용자까지 다 날아가므로 강제 중단.
        #   --force 플래그가 있을 때만 진행.
        if not force:
            existing_logins = {
                u.login_id for u in
                db.query(User).filter(User.login_id.in_(["admin", "user1"])).all()
            }
            if len(existing_logins) >= 2:
                print("[seed] admin/user1이 이미 존재 — 스킵 (--force로 강제 재생성)")
                return
            if len(existing_logins) == 1:
                missing = {"admin", "user1"} - existing_logins
                total_users = db.query(User).count()
                print(
                    f"[seed] WARNING: 부분 손상 감지 — {existing_logins} 존재, {missing} 누락.\n"
                    f"       현재 DB 전체 User 수: {total_users}건.\n"
                    f"       그대로 진행하면 모든 User/Organization이 삭제됩니다.\n"
                    f"       의도된 재시드라면 `python seed_demo_examples.py --force` 로 재실행하세요.\n"
                    f"       (실수로 admin/user1 중 하나만 삭제된 상황이면 해당 계정만 수동 복구 권장.)"
                )
                return

        # 1) 기존 데이터 삭제 (admin/user1 둘 다 없거나, --force 모드)
        _wipe_session_data(db)
        _wipe_orgs_and_users(db, keep_login_ids=set())  # 모두 삭제

        # 2) 인증 계정 + 조직
        org_admin = _upsert_org(db, "시스템관리", industry="IT", size="중소기업", cloud_type="온프레미스")
        admin = _upsert_auth_user(
            db, login_id="admin", password="admin", name="관리자",
            role="admin", org=org_admin,
        )

        org_sejong = _upsert_org(db, "세종대학교", industry="교육", size="대기업", cloud_type="하이브리드")
        user1_profile = {
            "org_name":     "세종대학교",
            "department":   "정보화지원팀",
            "contact":      "02-3408-0000",
            "org_type":     "교육",
            "infra_type":   "하이브리드",
            "employees":    1200,
            "servers":      85,
            "applications": 32,
            "note":         "학사 시스템 + 연구실 네트워크 통합 진단",
        }
        user1 = _upsert_auth_user(
            db, login_id="user1", password="user1", name="박기웅",
            role="user", org=org_sejong, profile=user1_profile,
        )

        # 3) 관리자 시점 예시 — 다양한 조직/점수 분포 4건
        now = datetime.now(timezone.utc)
        admin_examples = [
            ("ABC 핀테크",     "금융",   "대기업",    "퍼블릭",   3, 8,  "정보보안실",  "이수정", 950,   55, 28),
            ("XYZ 메디컬",     "의료",   "중견기업",  "온프레미스", 1, 14, "ISMS팀",      "정민호", 480,   30, 17),
            ("국가데이터센터", "공공",   "대기업",    "프라이빗", 2, 21, "보안운영팀",  "김재훈", 1700,  140, 45),
            ("스타트업 K",     "IT",     "중소기업",  "퍼블릭",   0, 30, "DevSecOps",   "한지호", 45,    8,  6),
        ]
        for org_name, industry, size, cloud, profile_id, days_ago, dept, manager_name, employees, servers, apps in admin_examples:
            ex_org = _upsert_org(db, org_name, industry=industry, size=size, cloud_type=cloud)
            ex_user = db.query(User).filter(
                User.org_id == ex_org.org_id, User.login_id.is_(None)
            ).first()
            if not ex_user:
                ex_user = User(
                    org_id=ex_org.org_id, name=manager_name,
                    email=f"{org_name}_{manager_name}@local", role="user",
                )
                db.add(ex_user)
                db.flush()
            started = now - timedelta(days=days_ago, hours=2)
            completed = now - timedelta(days=days_ago)
            _create_completed_session(
                db, org=ex_org, user=ex_user, profile_id=profile_id,
                started_at=started, completed_at=completed,
                extra={
                    "department": dept, "contact": "", "employees": employees,
                    "servers": servers, "applications": apps,
                    "note": f"{org_name} 정기 진단 예시",
                    "pillar_scope": {
                        "Identify": True, "Device": True, "Network": True,
                        "System": True, "Application": True, "Data": True,
                    },
                },
            )

        # 4) user1(박기웅·세종대) 완료 세션 3건 + 진행 중 1건
        user1_completed = [
            (90, 1, "1차 진단 — 시작점 측정"),
            (60, 2, "2차 진단 — 1분기 개선 후"),
            (15, 2, "3차 진단 — 운영 안정화"),
        ]
        for days_ago, profile_id, note in user1_completed:
            _create_completed_session(
                db, org=org_sejong, user=user1, profile_id=profile_id,
                started_at=now - timedelta(days=days_ago, hours=2),
                completed_at=now - timedelta(days=days_ago),
                extra={
                    **user1_profile, "note": note,
                    "pillar_scope": {
                        "Identify": True, "Device": True, "Network": True,
                        "System": True, "Application": True, "Data": True,
                    },
                },
            )

        # 진행 중 세션 (영상 시연용)
        inprogress = _create_inprogress_session(
            db, org=org_sejong, user=user1,
            started_at=now - timedelta(minutes=2),
            extra={**user1_profile, "note": "시연용 진행중 진단"},
            partial_ratio=0.4, profile_id=2,
        )

        db.commit()

        print()
        print("──── 시드 결과 ────")
        print(f"admin / admin → org={org_admin.org_id}, user_id={admin.user_id}")
        print(f"user1 / user1 → 박기웅 ({org_sejong.name}), user_id={user1.user_id}")
        print(f"관리자 예시 세션: {len(admin_examples)}건")
        print(f"user1 완료 세션: {len(user1_completed)}건 + 진행 중 {inprogress.session_id}")
        total = db.query(DiagnosisSession).count()
        print(f"총 세션 수: {total}")

    except Exception as e:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    force = "--force" in sys.argv
    seed(force=force)
