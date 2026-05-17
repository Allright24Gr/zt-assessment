"""
session.profile_select 기반 ImprovementGuide.task / steps 자동 맞춤.

4 오픈소스 도구만 지원 (Keycloak / Wazuh + Nmap / Trivy).
호출 측은 ImprovementGuide row 와 session.extra.profile_select 를 넘기면
새 task / new_recommended_tool 을 받는다. DB는 수정 안 함 — 응답 시점에 변환만.
"""

IDP_PROFILES = {
    "keycloak": {
        "label": "Keycloak",
        "mfa_action": "Keycloak Authentication Flow 에서 OTP/WebAuthn step 을 Required 로 추가",
        "conditional_action": "Keycloak Conditional Authenticator (script/aggregate) 정책 도입",
        "session_action": "Keycloak Realm Settings → Tokens → Session timeout 정책 강화",
        "rbac_action": "Keycloak Authorization Services 의 Resource·Permission 정책 활용",
        "password_action": "Keycloak Password Policy 강도/이력 정책 강화",
        "stepup_action": "Keycloak Step-up Authentication Flow 신설",
    },
    "none": {
        "label": "IdP 미선택",
        "mfa_action": "조직 표준 IdP 선정 후 MFA 강제 정책 도입",
        "conditional_action": "사용 IdP 의 Conditional Access 또는 Risk-based 정책 적용",
        "session_action": "세션 timeout 정책 도입",
        "rbac_action": "RBAC / Least Privilege 모델 적용",
        "password_action": "비밀번호 강도·이력·잠금 정책 강화",
        "stepup_action": "관리자/민감 작업에 step-up 인증 요구",
    },
}

SIEM_PROFILES = {
    "wazuh": {
        "label": "Wazuh",
        "alert_action": "Wazuh Custom Decoder/Rule 추가 + alert level threshold 조정",
        "compliance_action": "Wazuh SCA(Security Configuration Assessment) policy 적용",
        "response_action": "Active Response 스크립트 + Custom Command 등록",
    },
    "none": {
        "label": "SIEM 미선택",
        "alert_action": "조직 표준 SIEM 도입 후 알람 정책 수립",
        "compliance_action": "보안 설정 평가(SCA) 자동화 도구 도입",
        "response_action": "사고 대응 플레이북 표준화",
    },
}


def customize_guide(guide: dict, profile_select: dict | None) -> dict:
    """ImprovementGuide row (dict) 와 profile_select 받아 task / recommended_tool 치환.

    원본 변경 안 함 — 복사본 반환. DB row 자체는 그대로.
    """
    if not profile_select:
        return guide
    customized = dict(guide)  # 얕은 복사
    idp = (profile_select.get("idp_type") or "").lower()
    siem = (profile_select.get("siem_type") or "").lower()
    idp_prof = IDP_PROFILES.get(idp)
    siem_prof = SIEM_PROFILES.get(siem)

    task = guide.get("task") or ""
    pillar = (guide.get("pillar") or "").lower()
    # 권고 task 안의 일반 문구를 환경별로 보강.
    extra_hint = None

    # IdP 관련 키워드 매칭 → IdP 환경별 가이드 첨부
    if idp_prof and any(k in task for k in ["MFA", "다단계", "OTP", "WebAuthn"]):
        extra_hint = idp_prof["mfa_action"]
    elif idp_prof and any(k in task for k in ["조건부", "Conditional", "context"]):
        extra_hint = idp_prof["conditional_action"]
    elif idp_prof and any(k in task for k in ["세션", "Session", "session timeout"]):
        extra_hint = idp_prof["session_action"]
    elif idp_prof and any(k in task for k in ["권한", "RBAC", "Role", "ABAC"]):
        extra_hint = idp_prof["rbac_action"]
    elif idp_prof and any(k in task for k in ["비밀번호", "Password", "passw"]):
        extra_hint = idp_prof["password_action"]
    elif idp_prof and any(k in task for k in ["step-up", "단계 상승", "elevation"]):
        extra_hint = idp_prof["stepup_action"]
    # SIEM 관련
    elif siem_prof and any(k in task for k in ["알람", "alert", "탐지", "이상"]):
        extra_hint = siem_prof["alert_action"]
    elif siem_prof and any(k in task for k in ["설정 평가", "compliance", "SCA", "보안 설정"]):
        extra_hint = siem_prof["compliance_action"]
    elif siem_prof and any(k in task for k in ["대응", "response", "차단", "격리"]) and "기기" not in pillar:
        extra_hint = siem_prof["response_action"]

    if extra_hint:
        customized["task"] = f"{task}\n— 사용자 환경({idp_prof['label'] if idp_prof else (siem_prof['label'] if siem_prof else '범용')}) 가이드: {extra_hint}"

    # recommended_tool 도 IdP 라벨로 치환 가능
    rec_tool = guide.get("recommended_tool") or ""
    if idp_prof and rec_tool.lower() in ("idp", "iam", ""):
        customized["recommended_tool"] = idp_prof["label"]

    return customized
