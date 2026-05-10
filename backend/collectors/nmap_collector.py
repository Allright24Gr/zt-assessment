from typing import Optional
from datetime import datetime, timezone
import os
import httpx


CollectedResult = dict

NMAP_WRAPPER_URL = os.environ.get("NMAP_WRAPPER_URL", "http://nmap-wrapper:5000")


def collect_open_ports(
    item_id: str,
    maturity: str,
    target_ip: str,
    ports: str = "1-1024",
) -> CollectedResult:
    """
    외부 노출 포트 스캔
    POST {NMAP_WRAPPER_URL}/scan/ports
    """
    # TODO: nmap-wrapper /scan/ports 호출
    # TODO: 불필요하게 열린 포트 수 집계
    # TODO: threshold와 비교하여 결과 판정
    raise NotImplementedError


def collect_tls_status(
    item_id: str,
    maturity: str,
    target_ip: str,
) -> CollectedResult:
    """
    TLS 적용 여부 스캔
    POST {NMAP_WRAPPER_URL}/scan/tls
    """
    # TODO: nmap-wrapper /scan/tls 호출
    # TODO: TLS 미적용 포트 비율 계산
    # TODO: 결과 판정 후 CollectedResult 반환
    raise NotImplementedError


def collect_subnet_topology(
    item_id: str,
    maturity: str,
    network_range: str,
) -> CollectedResult:
    """
    서브넷 탐지 및 마이크로 세그멘테이션 현황
    POST {NMAP_WRAPPER_URL}/scan/subnets
    """
    # TODO: nmap-wrapper /scan/subnets 호출
    # TODO: 발견된 서브넷·호스트 수 집계
    # TODO: 세그멘테이션 기준과 비교하여 결과 판정
    raise NotImplementedError
