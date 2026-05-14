from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional
from datetime import datetime, timezone
import httpx
import os

from database import get_db
from models import (
    DiagnosisSession, Checklist, CollectedData,
    DiagnosisResult, MaturityScore, ScoreHistory, Organization, User,
)
from scoring.engine import score_session, determine_maturity_level

router = APIRouter()

SHUFFLE_URL     = os.getenv("SHUFFLE_URL", "")
SHUFFLE_API_KEY = os.getenv("SHUFFLE_API_KEY", "")
SELF_BASE_URL   = os.getenv("SELF_BASE_URL", "http://zt-backend:8000")

# 도구별 개별 워크플로우 ID (Shuffle UI에서 워크플로우 만든 후 입력)
SHUFFLE_WF = {
    "keycloak": os.getenv("SHUFFLE_WORKFLOW_KEYCLOAK", ""),
    "wazuh":    os.getenv("SHUFFLE_WORKFLOW_WAZUH",    ""),
    "nmap":     os.getenv("SHUFFLE_WORKFLOW_NMAP",     ""),
    "trivy":    os.getenv("SHUFFLE_WORKFLOW_TRIVY",    ""),
}


class AssessmentRunRequest(BaseModel):
    org_name: str = "기본 조직"
    manager: str = "담당자"
    email: str = "manager@example.com"
    department: Optional[str] = None
    contact: Optional[str] = None
    org_type: Optional[str] = None
    infra_type: Optional[str] = None
    employees: Optional[str] = None
    servers: Optional[str] = None
    applications: Optional[str] = None
    note: Optional[str] = None
    # 기업에서 사용 중인 도구 선택. 비어있으면 모든 도구 자동 수집.
    tool_scope: dict = {}


@router.post("/run")
def run_assessment(
    req: AssessmentRunRequest,
    db: Session = Depends(get_db),
):
    org = db.query(Organization).filter(Organization.name == req.org_name).first()
    if not org:
        org = Organization(name=req.org_name)
        db.add(org)
        db.flush()

    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        user = User(org_id=org.org_id, name=req.manager, email=req.email)
        db.add(user)
        db.flush()

    session = DiagnosisSession(
        org_id=org.org_id,
        user_id=user.user_id,
        status="진행 중",
        started_at=datetime.now(timezone.utc),
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    # tool_scope 가 비어있으면 전체 도구 자동 수집
    tool_scope = req.tool_scope if req.tool_scope else {
        "keycloak": True, "wazuh": True, "nmap": True, "trivy": True
    }

    selected_tools = [t for t, enabled in tool_scope.items() if enabled]

    # Shuffle 워크플로우가 하나라도 등록돼 있으면 Shuffle 경로 사용
    has_shuffle = SHUFFLE_URL and any(SHUFFLE_WF.get(t) for t in selected_tools)

    if has_shuffle:
        _trigger_shuffle_workflows(session.session_id, selected_tools)
    elif selected_tools:
        import threading
        thread = threading.Thread(
            target=_run_collectors,
            args=(session.session_id, tool_scope),
            daemon=True,
        )
        thread.start()

    return {
        "session_id": session.session_id,
        "status": "진행 중",
        "message": "진단이 시작되었습니다.",
        "started_at": session.started_at.isoformat(),
    }


@router.get("/status/{session_id}")
def get_assessment_status(session_id: int, db: Session = Depends(get_db)):
    """자동 수집 진행 상태를 반환한다 (프론트 폴링용)."""
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")

    collected_count = db.query(func.count(CollectedData.data_id)).filter(
        CollectedData.session_id == session_id
    ).scalar()

    auto_total = db.query(func.count(Checklist.check_id)).filter(
        Checklist.diagnosis_type != "수동"
    ).scalar()

    return {
        "session_id": session_id,
        "status": session.status,
        "collected_count": collected_count,
        "auto_total": auto_total,
        "collection_done": collected_count >= auto_total if auto_total > 0 else True,
    }


@router.post("/finalize")
def finalize_assessment(session_id: int, db: Session = Depends(get_db)):
    """수동 제출 완료 후 채점을 명시적으로 트리거한다."""
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    if session.status == "완료":
        return {"status": "already_completed", "session_id": session_id}
    _trigger_scoring(session_id, db)
    return {"status": "ok", "session_id": session_id}


@router.post("/webhook")
def assessment_webhook(payload: dict, db: Session = Depends(get_db)):
    session_id = payload.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id가 필요합니다.")

    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")

    results = payload.get("results", [])
    for item in results:
        item_id_str = item.get("item_id")
        checklist = None
        if item_id_str:
            checklist = db.query(Checklist).filter(Checklist.item_id == item_id_str).first()
        check_id = checklist.check_id if checklist else None
        if not check_id:
            continue

        existing = db.query(CollectedData).filter(
            CollectedData.session_id == session_id,
            CollectedData.check_id == check_id,
        ).first()

        if existing:
            existing.tool = item.get("tool", existing.tool)
            existing.metric_key = item.get("metric_key", existing.metric_key)
            existing.metric_value = item.get("metric_value")
            existing.threshold = item.get("threshold")
            existing.raw_json = item.get("raw_json")
            existing.error = item.get("error")
            existing.collected_at = datetime.now(timezone.utc)
        else:
            db.add(CollectedData(
                session_id=session_id,
                check_id=check_id,
                tool=item.get("tool", "unknown"),
                metric_key=item.get("metric_key", ""),
                metric_value=item.get("metric_value"),
                threshold=item.get("threshold"),
                raw_json=item.get("raw_json"),
                error=item.get("error"),
            ))

    db.commit()
    return {"status": "ok", "saved": len(results)}


def _trigger_shuffle_workflows(session_id: int, selected_tools: list[str]):
    """선택된 도구에 해당하는 Shuffle 워크플로우만 개별 트리거한다."""
    payload = {
        "execution_argument": {
            "session_id": session_id,
            "webhook_url": f"{SELF_BASE_URL}/api/assessment/webhook",
        }
    }
    with httpx.Client(timeout=10.0) as client:
        for tool in selected_tools:
            wf_id = SHUFFLE_WF.get(tool, "")
            if not wf_id:
                continue
            try:
                client.post(
                    f"{SHUFFLE_URL}/api/v1/workflows/{wf_id}/execute",
                    headers={"Authorization": f"Bearer {SHUFFLE_API_KEY}"},
                    json=payload,
                )
            except Exception:
                pass


def _trigger_scoring(session_id: int, db: Session):
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        return

    collected_rows = db.query(CollectedData).filter(
        CollectedData.session_id == session_id
    ).all()

    check_ids = [r.check_id for r in collected_rows]
    meta_rows = db.query(Checklist).filter(Checklist.check_id.in_(check_ids)).all()

    checklist_meta = [
        {
            "check_id": m.check_id,
            "item_id": m.item_id,
            "pillar": m.pillar,
            "maturity_score": m.maturity_score,
            "category": m.category,
            "item_name": m.item_name,
        }
        for m in meta_rows
    ]

    collected_results = [
        {
            "check_id": r.check_id,
            "tool": r.tool,
            "metric_key": r.metric_key,
            "metric_value": r.metric_value,
            "threshold": r.threshold,
            "raw_json": r.raw_json,
            "error": r.error,
        }
        for r in collected_rows
    ]

    output = score_session(session_id, collected_results, checklist_meta)

    for cr in output["checklist_results"]:
        check_id = cr.get("check_id")
        if not check_id:
            continue
        existing = db.query(DiagnosisResult).filter(
            DiagnosisResult.session_id == session_id,
            DiagnosisResult.check_id == check_id,
        ).first()
        if existing:
            existing.result = cr["result"]
            existing.score = cr["score"]
            existing.recommendation = cr.get("recommendation", "")
        else:
            db.add(DiagnosisResult(
                session_id=session_id,
                check_id=check_id,
                result=cr["result"],
                score=cr["score"],
                recommendation=cr.get("recommendation", ""),
            ))

    db.query(MaturityScore).filter(MaturityScore.session_id == session_id).delete()
    for pillar, score in output["pillar_scores"].items():
        db.add(MaturityScore(session_id=session_id, pillar=pillar, score=score))

    db.add(ScoreHistory(
        session_id=session_id,
        org_id=session.org_id,
        pillar_scores=output["pillar_scores"],
        total_score=output["total_score"],
        maturity_level=output["maturity_level"],
    ))

    session.status = "완료"
    session.level = output["maturity_level"]
    session.total_score = output["total_score"]
    session.completed_at = datetime.now(timezone.utc)
    db.commit()


@router.get("/result")
def get_result(session_id: int, db: Session = Depends(get_db)):
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")

    org = db.query(Organization).filter(Organization.org_id == session.org_id).first()
    user = db.query(User).filter(User.user_id == session.user_id).first()

    maturity_rows = db.query(MaturityScore).filter(
        MaturityScore.session_id == session_id
    ).all()
    pillar_scores = [
        {
            "pillar": m.pillar,
            "score": round(m.score, 4),
            "level": determine_maturity_level(m.score),
        }
        for m in maturity_rows
    ]

    results = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(DiagnosisResult.session_id == session_id)
        .all()
    )

    checklist_results = []
    for dr, cl in results:
        checklist_results.append({
            "id": cl.item_id,
            "pillar": cl.pillar,
            "category": cl.category,
            "item": cl.item_name,
            "maturity": cl.maturity,
            "maturity_score": cl.maturity_score,
            "diagnosis_type": cl.diagnosis_type,
            "tool": cl.tool,
            "result": dr.result,
            "score": dr.score or 0.0,
            "evidence": cl.evidence or "",
            "criteria": cl.criteria or "",
            "fields": cl.fields or "",
            "logic": cl.logic or "",
            "exceptions": cl.exceptions or "",
            "recommendation": dr.recommendation or "",
        })

    overall = session.total_score or 0.0

    return {
        "session": {
            "id": session.session_id,
            "org": org.name if org else "",
            "date": session.started_at.isoformat() if session.started_at else "",
            "manager": user.name if user else "",
            "user_id": session.user_id,
            "level": session.level or "",
            "status": session.status,
            "score": session.total_score,
            "errors": [],
        },
        "pillar_scores": pillar_scores,
        "overall_score": overall,
        "overall_level": session.level or determine_maturity_level(overall),
        "checklist_results": checklist_results,
    }


@router.get("/history")
def get_history(
    org_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    query = db.query(DiagnosisSession)
    if org_id is not None:
        query = query.filter(DiagnosisSession.org_id == org_id)
    sessions = query.order_by(DiagnosisSession.started_at.desc()).all()

    org_ids = list({s.org_id for s in sessions})
    user_ids = list({s.user_id for s in sessions})
    orgs = {o.org_id: o for o in db.query(Organization).filter(Organization.org_id.in_(org_ids)).all()}
    users = {u.user_id: u for u in db.query(User).filter(User.user_id.in_(user_ids)).all()}

    items = []
    for s in sessions:
        org = orgs.get(s.org_id)
        user = users.get(s.user_id)
        items.append({
            "id": s.session_id,
            "org": org.name if org else "",
            "date": s.started_at.isoformat() if s.started_at else "",
            "manager": user.name if user else "",
            "user_id": s.user_id,
            "level": s.level or "",
            "status": s.status,
            "score": s.total_score,
            "errors": [],
        })

    return {"sessions": items, "total": len(items)}


def _run_collectors(session_id: int, tool_scope: dict = None):
    """Shuffle 없이 직접 collector를 실행하는 fallback 디스패처."""
    if tool_scope is None:
        tool_scope = {"keycloak": True, "wazuh": True, "nmap": True, "trivy": True}

    use_keycloak = tool_scope.get("keycloak", False)
    use_wazuh = tool_scope.get("wazuh", False)
    use_nmap = tool_scope.get("nmap", False)
    use_trivy = tool_scope.get("trivy", False)

    if use_keycloak:
        from collectors.keycloak_collector import (
            collect_user_role_ratio, collect_idp_inventory, collect_client_group_inventory,
            collect_idp_registered, collect_active_idp_multi,
            collect_mfa_required, collect_otp_flow, collect_webauthn_status,
            collect_conditional_auth, collect_session_policy, collect_stepup_auth,
            collect_dynamic_auth_flow, collect_realm_count, collect_icam_inventory,
            collect_custom_auth_flow, collect_webauthn_users, collect_context_policy,
            collect_authz_clients, collect_rbac_policy, collect_session_policy_advanced,
            collect_aggregate_policy, collect_resource_permission, collect_password_policy,
            collect_role_change_events, collect_central_authz_policy, collect_abac_policy,
            collect_central_authz_ratio, collect_mfa_required_actions,
            collect_webauthn_credential_users, collect_sso_clients, collect_conditional_policy,
        )
        KC = [
            (collect_user_role_ratio,           "1.1.1.2_1",  "초기"),
            (collect_idp_inventory,             "1.1.1.3_1",  "향상"),
            (collect_client_group_inventory,    "1.1.1.4_2",  "최적화"),
            (collect_idp_registered,            "1.1.2.1_1",  "기존"),
            (collect_active_idp_multi,          "1.1.2.2_1",  "초기"),
            (collect_mfa_required,              "1.2.1.1_1",  "기존"),
            (collect_otp_flow,                  "1.2.1.2_1",  "초기"),
            (collect_webauthn_status,           "1.2.1.2_2",  "초기"),
            (collect_conditional_auth,          "1.2.1.3_1",  "향상"),
            (collect_session_policy,            "1.2.2.1_1",  "기존"),
            (collect_stepup_auth,               "1.2.2.2_1",  "초기"),
            (collect_dynamic_auth_flow,         "1.2.2.3_1",  "향상"),
            (collect_realm_count,               "1.3.1.1_1",  "기존"),
            (collect_icam_inventory,            "1.3.1.2_1",  "초기"),
            (collect_custom_auth_flow,          "1.3.1.2_2",  "초기"),
            (collect_webauthn_users,            "1.3.2.2_1",  "향상"),
            (collect_context_policy,            "1.3.2.2_2",  "향상"),
            (collect_authz_clients,             "1.4.1.1_3",  "기존"),
            (collect_rbac_policy,               "1.4.1.2_1",  "초기"),
            (collect_session_policy_advanced,   "1.4.1.3_1",  "향상"),
            (collect_aggregate_policy,          "1.4.1.3_2",  "향상"),
            (collect_resource_permission,       "1.4.1.3_3",  "향상"),
            (collect_password_policy,           "1.4.2.2_1",  "초기"),
            (collect_role_change_events,        "1.4.2.2_2",  "초기"),
            (collect_central_authz_policy,      "4.1.1.2_1",  "초기"),
            (collect_abac_policy,               "4.1.1.3_1",  "향상"),
            (collect_central_authz_ratio,       "4.1.1.4_2",  "최적화"),
            (collect_mfa_required_actions,      "4.2.2.2_2",  "초기"),
            (collect_webauthn_credential_users, "4.2.2.3_1",  "향상"),
            (collect_sso_clients,               "4.3.1.3_5",  "향상"),
            (collect_conditional_policy,        "6.2.1.3_1",  "향상"),
        ]
    else:
        KC = []

    if use_wazuh:
        from collectors.wazuh_collector import (
            collect_auth_failure_alerts, collect_active_response_auth, collect_agent_sca_ratio,
            collect_sca_average, collect_high_risk_alerts, collect_behavior_alerts,
            collect_activity_rules, collect_privilege_change_alerts, collect_sca_compliance,
            collect_policy_violation_alerts, collect_sca_auto_remediation, collect_os_inventory,
            collect_sca_access_control, collect_auto_block, collect_agent_registration,
            collect_agent_keepalive, collect_unauthorized_device_alerts,
            collect_vulnerability_summary, collect_realtime_monitoring, collect_os_distribution,
            collect_sca_policy_ratio, collect_continuous_monitoring, collect_auto_threat_response,
            collect_edr_agents, collect_threat_detection_alerts, collect_vuln_asset_list,
            collect_vuln_scan_ratio, collect_critical_unfixed_vulns,
            collect_segment_policy_alerts, collect_lateral_movement_alerts, collect_ids_alerts,
            collect_attack_response, collect_realtime_threat_alerts, collect_tls_cleartext_alerts,
            collect_backup_history, collect_agent_uptime, collect_policy_change_alerts,
            collect_privilege_escalation_alerts, collect_fim_status, collect_fim_collection_ratio,
            collect_dlp_alerts,
        )
        WZ = [
            (collect_auth_failure_alerts,         "1.1.1.3_2",  "향상"),
            (collect_active_response_auth,        "1.2.1.4_1",  "최적화"),
            (collect_agent_sca_ratio,             "1.2.2.1_2",  "기존"),
            (collect_sca_average,                 "1.3.1.2_3",  "초기"),
            (collect_high_risk_alerts,            "1.3.1.4_2",  "최적화"),
            (collect_behavior_alerts,             "1.3.2.3_1",  "향상"),
            (collect_activity_rules,              "1.4.1.1_1",  "기존"),
            (collect_privilege_change_alerts,     "1.4.2.3_2",  "향상"),
            (collect_sca_compliance,              "2.1.1.2_1",  "초기"),
            (collect_policy_violation_alerts,     "2.1.1.2_2",  "초기"),
            (collect_sca_auto_remediation,        "2.1.1.3_1",  "향상"),
            (collect_sca_access_control,          "2.1.1.3_2",  "향상"),
            (collect_os_inventory,                "2.2.1.1_1",  "기존"),
            (collect_auto_block,                  "2.2.1.4_1",  "최적화"),
            (collect_agent_registration,          "2.3.1.1_2",  "기존"),
            (collect_agent_keepalive,             "2.3.1.2_1",  "초기"),
            (collect_unauthorized_device_alerts,  "2.3.1.3_1",  "향상"),
            (collect_vulnerability_summary,       "2.3.1.3_2",  "향상"),
            (collect_realtime_monitoring,         "2.3.1.4_1",  "최적화"),
            (collect_os_distribution,             "2.3.2.1_1",  "기존"),
            (collect_sca_policy_ratio,            "2.3.2.1_2",  "기존"),
            (collect_continuous_monitoring,       "2.3.2.2_2",  "초기"),
            (collect_auto_threat_response,        "2.3.2.4_1",  "최적화"),
            (collect_edr_agents,                  "2.4.1.1_1",  "기존"),
            (collect_threat_detection_alerts,     "2.4.1.2_1",  "초기"),
            (collect_vuln_asset_list,             "2.4.2.1_2",  "기존"),
            (collect_vuln_scan_ratio,             "2.4.2.3_1",  "향상"),
            (collect_critical_unfixed_vulns,      "2.4.2.4_2",  "최적화"),
            (collect_segment_policy_alerts,       "3.1.1.2_1",  "초기"),
            (collect_lateral_movement_alerts,     "3.1.2.2_1",  "초기"),
            (collect_ids_alerts,                  "3.2.1.1_1",  "기존"),
            (collect_attack_response,             "3.2.1.2_1",  "초기"),
            (collect_realtime_threat_alerts,      "3.2.1.3_1",  "향상"),
            (collect_tls_cleartext_alerts,        "3.3.1.3_1",  "향상"),
            (collect_backup_history,              "3.5.1.1_2",  "기존"),
            (collect_agent_uptime,                "3.5.1.3_1",  "향상"),
            (collect_policy_change_alerts,        "4.1.1.2_3",  "초기"),
            (collect_privilege_escalation_alerts, "4.2.1.3_1",  "향상"),
            (collect_fim_status,                  "6.1.1.2_1",  "초기"),
            (collect_fim_collection_ratio,        "6.1.1.2_2",  "초기"),
            (collect_dlp_alerts,                  "6.5.1.2_1",  "초기"),
        ]
    else:
        WZ = []

    if use_nmap:
        from collectors.nmap_collector import (
            collect_host_discovery, collect_port_service_map, collect_subnet_topology,
            collect_subnet_traffic_map, collect_micro_segment_ports, collect_tls_ratio,
            collect_tls_services, collect_tls_advanced, collect_app_traffic_map,
            collect_network_redundancy, collect_subnet_segmentation, collect_perimeter_model,
            collect_system_subnet_separation, collect_vpn_ports,
        )
        NM = [
            (collect_host_discovery,           "2.1.1.1_1",  "기존"),
            (collect_port_service_map,         "2.4.2.2_1",  "초기"),
            (collect_subnet_topology,          "3.1.1.1_1",  "기존"),
            (collect_subnet_traffic_map,       "3.1.1.1_2",  "기존"),
            (collect_micro_segment_ports,      "3.1.2.1_1",  "기존"),
            (collect_tls_ratio,                "3.3.1.1_1",  "기존"),
            (collect_tls_services,             "3.3.1.1_2",  "기존"),
            (collect_tls_advanced,             "3.3.1.3_2",  "향상"),
            (collect_app_traffic_map,          "3.4.1.2_1",  "초기"),
            (collect_network_redundancy,       "3.5.1.2_3",  "초기"),
            (collect_subnet_segmentation,      "4.3.1.1_1",  "기존"),
            (collect_perimeter_model,          "4.3.1.1_2",  "기존"),
            (collect_system_subnet_separation, "4.3.1.2_1",  "초기"),
            (collect_vpn_ports,                "5.3.1.1_1",  "기존"),
        ]
    else:
        NM = []

    if use_trivy:
        from collectors.trivy_collector import (
            collect_image_scan, collect_cicd_scan_ratio, collect_integrity_check,
            collect_policy_compliance_scan, collect_full_component_scan, collect_fs_scan,
            collect_sbom, collect_dependency_scan, collect_sbom_full,
            collect_risk_scan, collect_supply_chain_scan,
        )
        TR = [
            (collect_image_scan,             "5.4.1.2_2",  "초기"),
            (collect_cicd_scan_ratio,        "5.4.1.2_3",  "초기"),
            (collect_integrity_check,        "5.4.1.2_4",  "초기"),
            (collect_policy_compliance_scan, "5.4.1.3_2",  "향상"),
            (collect_full_component_scan,    "5.4.1.3_4",  "향상"),
            (collect_fs_scan,                "5.5.1.2_1",  "초기"),
            (collect_sbom,                   "5.5.1.2_3",  "초기"),
            (collect_dependency_scan,        "5.5.1.3_1",  "향상"),
            (collect_sbom_full,              "5.5.1.3_2",  "향상"),
            (collect_risk_scan,              "5.5.2.2_1",  "초기"),
            (collect_supply_chain_scan,      "5.5.2.3_1",  "향상"),
        ]
    else:
        TR = []

    results = []

    for func, item_id, maturity in KC + WZ:
        try:
            results.append(func(item_id, maturity))
        except Exception as e:
            results.append({
                "item_id": item_id, "maturity": maturity, "tool": "unknown",
                "result": "평가불가", "metric_key": "error", "metric_value": 0.0,
                "threshold": 1.0, "raw_json": {}, "error": str(e),
                "collected_at": datetime.now(timezone.utc).isoformat(),
            })

    for func, item_id, maturity in NM:
        try:
            results.append(func())
        except Exception as e:
            results.append({
                "item_id": item_id, "maturity": maturity, "tool": "nmap",
                "result": "평가불가", "metric_key": "error", "metric_value": 0.0,
                "threshold": 1.0, "raw_json": {}, "error": str(e),
                "collected_at": datetime.now(timezone.utc).isoformat(),
            })

    for func, item_id, maturity in TR:
        try:
            results.append(func())
        except Exception as e:
            results.append({
                "item_id": item_id, "maturity": maturity, "tool": "trivy",
                "result": "평가불가", "metric_key": "error", "metric_value": 0.0,
                "threshold": 1.0, "raw_json": {}, "error": str(e),
                "collected_at": datetime.now(timezone.utc).isoformat(),
            })

    if results:
        try:
            httpx.post(
                f"{SELF_BASE_URL}/api/assessment/webhook",
                json={"session_id": session_id, "results": results},
                timeout=60,
            )
        except Exception:
            pass
