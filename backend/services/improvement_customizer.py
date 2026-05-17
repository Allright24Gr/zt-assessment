"""
session.profile_select 기반 ImprovementGuide.task / steps 자동 맞춤.

치환 규칙:
- {IDP} 또는 IdP 일반 문구 → 사용자 IdP 이름 + 특화 가이드
- {SIEM} → 사용자 SIEM 이름 + 특화 가이드
- {EDR} → 사용자 EDR 이름 + 특화 가이드

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
    "entra": {
        "label": "MS Entra ID",
        "mfa_action": "Entra Conditional Access Policy 의 grantControls.MFA 강제",
        "conditional_action": "Conditional Access Policy 의 user/risk/group 조건 결합",
        "session_action": "CA Session Control 의 Sign-in Frequency 정책 추가",
        "rbac_action": "PIM(Privileged Identity Management) + Custom Role 도입",
        "password_action": "Authentication Methods Policy → Password protection 강화",
        "stepup_action": "Authentication Strength 정책으로 step-up MFA 요구",
    },
    "okta": {
        "label": "Okta",
        "mfa_action": "Okta MFA Enrollment Policy 와 Sign-on Policy 의 Factor Sequencing 도입",
        "conditional_action": "Sign-on Policy 의 Network Zone / Risk-based 조건 추가",
        "session_action": "Sign-on Policy Session Lifetime 단축",
        "rbac_action": "Okta Admin Role 의 Resource-set / Permission 세분화",
        "password_action": "Password Policy 의 min length / history / lockout 강화",
        "stepup_action": "Authentication Policy 의 step-up assurance 도입",
    },
    "ldap": {
        "label": "자체 LDAP/AD",
        "mfa_action": "Smart Card / 인증서 기반 MFA 도입 (msDS-Smartcard Logon Required)",
        "conditional_action": "Authentication Policy Silo + AuthN Policy 로 조건부 인증 구성",
        "session_action": "Kerberos Ticket Lifetime 정책 (Default Domain Policy) 조정",
        "rbac_action": "ESAE / Tiered Admin Model + JEA(Just Enough Admin) 도입",
        "password_action": "Fine-grained Password Policy(PSO) 로 Tier별 강도 차별화",
        "stepup_action": "Authentication Policy 로 Admin Tier 의 step-up 요구",
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
    "splunk": {
        "label": "Splunk",
        "alert_action": "Splunk ES Correlation Search + Notable Event 도입",
        "compliance_action": "Splunk ES Risk Framework 의 Risk-based Alerting 활용",
        "response_action": "Splunk SOAR (Phantom) 플레이북 자동 실행",
    },
    "elastic": {
        "label": "Elastic SIEM",
        "alert_action": "Elastic Security Detection Rule + Threshold 룰 추가",
        "compliance_action": "Elastic Endpoint Integration 의 Compliance posture 평가",
        "response_action": "Elastic Security Workflow 자동화 (osquery + response)",
    },
    "none": {
        "label": "SIEM 미선택",
        "alert_action": "조직 표준 SIEM 도입 후 알람 정책 수립",
        "compliance_action": "보안 설정 평가(SCA) 자동화 도구 도입",
        "response_action": "사고 대응 플레이북 표준화",
    },
}

EDR_PROFILES = {
    "crowdstrike": {
        "label": "CrowdStrike Falcon",
        "detect_action": "Falcon Custom IOA Rule + Real Time Response 활용",
        "isolate_action": "Falcon Network Containment 자동화",
        "vuln_action": "Falcon Spotlight 취약점 + ExPRT Rating 우선순위화",
    },
    "defender": {
        "label": "Defender for Endpoint",
        "detect_action": "MDE Custom Detection Rule + Advanced Hunting KQL 도입",
        "isolate_action": "Machine Action (Isolate / RestrictAppExecution) 자동화",
        "vuln_action": "Defender Vulnerability Management 우선순위 + 자동 remediation",
    },
    "none": {
        "label": "EDR 미선택",
        "detect_action": "EDR 도구 도입 후 행위 탐지 룰 정의",
        "isolate_action": "엔드포인트 자동 격리 정책 수립",
        "vuln_action": "취약점 관리 도구 + remediation 흐름 도입",
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
    edr = (profile_select.get("edr_type") or "").lower()
    idp_prof = IDP_PROFILES.get(idp)
    siem_prof = SIEM_PROFILES.get(siem)
    edr_prof = EDR_PROFILES.get(edr)

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
    # EDR 관련
    elif edr_prof and any(k in task for k in ["EDR", "엔드포인트", "endpoint"]):
        extra_hint = edr_prof["detect_action"]
    elif edr_prof and any(k in task for k in ["격리", "isolate", "containment"]):
        extra_hint = edr_prof["isolate_action"]
    elif edr_prof and any(k in task for k in ["취약점", "vuln", "patch"]):
        extra_hint = edr_prof["vuln_action"]

    if extra_hint:
        customized["task"] = f"{task}\n— 사용자 환경({idp_prof['label'] if idp_prof else (siem_prof['label'] if siem_prof else (edr_prof['label'] if edr_prof else '범용'))}) 가이드: {extra_hint}"

    # recommended_tool 도 IdP 라벨로 치환 가능
    rec_tool = guide.get("recommended_tool") or ""
    if idp_prof and rec_tool.lower() in ("idp", "iam", ""):
        customized["recommended_tool"] = idp_prof["label"]

    return customized
