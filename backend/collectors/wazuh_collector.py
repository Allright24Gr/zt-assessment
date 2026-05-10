from typing import Optional
from datetime import datetime, timezone
import os


CollectedResult = dict

WAZUH_URL = os.environ.get("WAZUH_URL", "https://wazuh-manager:55000")
WAZUH_USER = os.environ.get("WAZUH_USER", "")
WAZUH_PASSWORD = os.environ.get("WAZUH_PASSWORD", "")


def _get_wazuh_token() -> str:
    """Wazuh API JWT 토큰을 발급받는다."""
    # TODO: POST {WAZUH_URL}/security/user/authenticate (Basic Auth)
    # TODO: data.token 반환
    raise NotImplementedError


def collect_agent_status(item_id: str, maturity: str) -> CollectedResult:
    """
    기기 에이전트 연결 상태 수집
    GET /agents?select=id,name,status,os,lastKeepAlive
    """
    # TODO: 전체 에이전트 목록 조회
    # TODO: active 상태 비율 계산
    # TODO: 결과 판정 후 CollectedResult 반환
    raise NotImplementedError


def collect_vulnerability_summary(item_id: str, maturity: str) -> CollectedResult:
    """
    취약점 스캔 결과 수집
    GET /vulnerability/{agent_id}/summary/severity
    """
    # TODO: 에이전트별 Critical/High 취약점 수 집계
    # TODO: threshold와 비교하여 결과 판정
    raise NotImplementedError


def collect_log_monitoring(item_id: str, maturity: str) -> CollectedResult:
    """
    로그 모니터링 자동화 상태 수집
    GET /manager/configuration?section=localfile
    GET /rules?status=enabled&limit=500
    """
    # TODO: 활성 로그 수집 설정 수 조회
    # TODO: 활성 탐지 룰 수 조회
    # TODO: 기준값과 비교하여 결과 판정
    raise NotImplementedError


def collect_syscheck_status(item_id: str, maturity: str) -> CollectedResult:
    """
    파일 무결성 모니터링(FIM) 상태 수집
    GET /syscheck/{agent_id}?limit=1
    """
    # TODO: FIM 결과 존재 여부로 활성화 확인
    # TODO: 마지막 스캔 시각 기준 freshness 판정
    raise NotImplementedError
