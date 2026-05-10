from typing import Optional
from datetime import datetime, timezone
import os


CollectedResult = dict  # 반환 형식은 아래 구조를 따름
# {
#   "item_id": str,
#   "maturity": str,
#   "tool": str,
#   "result": str,          # 충족 / 부분충족 / 미충족 / 평가불가
#   "metric_key": str,
#   "metric_value": float,
#   "threshold": float,
#   "raw_json": dict,
#   "collected_at": str,
#   "error": str | None
# }

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "master")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "admin-cli")
KEYCLOAK_ADMIN = os.environ.get("KEYCLOAK_ADMIN", "")
KEYCLOAK_ADMIN_PASSWORD = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "")


def _get_admin_token() -> str:
    """Keycloak 관리자 토큰을 발급받는다."""
    # TODO: POST {KEYCLOAK_URL}/realms/master/protocol/openid-connect/token
    # TODO: grant_type=password, client_id=admin-cli, username/password 사용
    # TODO: access_token 반환
    raise NotImplementedError


def collect_user_inventory(item_id: str, maturity: str) -> CollectedResult:
    """
    cl-002 ~ cl-004: 사용자 인벤토리 (역할 부여 비율, 자동화 수준)
    GET /admin/realms/{realm}/users?enabled=true
    """
    # TODO: 전체 활성 사용자 조회
    # TODO: serviceAccountClientId=null 필터
    # TODO: 기본 역할(default-roles-*, offline_access, uma_authorization) 제외 역할 보유 비율 계산
    # TODO: threshold와 비교하여 결과 판정
    raise NotImplementedError


def collect_mfa_status(item_id: str, maturity: str) -> CollectedResult:
    """
    cl-005 ~ cl-008: MFA 적용 현황
    GET /admin/realms/{realm}/authentication/required-actions
    GET /admin/realms/{realm}/users (credentialTypes 확인)
    """
    # TODO: CONFIGURE_TOTP required action 활성화 여부 확인
    # TODO: 사용자별 OTP credential 보유 비율 계산
    raise NotImplementedError


def collect_session_policy(item_id: str, maturity: str) -> CollectedResult:
    """
    cl-009 ~ cl-012: 세션 정책 (토큰 만료, 유휴 세션 타임아웃)
    GET /admin/realms/{realm}
    """
    # TODO: accessTokenLifespan, ssoSessionIdleTimeout 조회
    # TODO: 기준값(threshold)과 비교하여 결과 판정
    raise NotImplementedError
