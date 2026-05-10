from typing import Optional
from datetime import datetime, timezone
import os
import httpx


CollectedResult = dict

TRIVY_WRAPPER_URL = os.environ.get("TRIVY_WRAPPER_URL", "http://trivy-wrapper:5001")


def collect_image_vulnerabilities(
    item_id: str,
    maturity: str,
    image_name: str,
) -> CollectedResult:
    """
    컨테이너 이미지 취약점 스캔
    POST {TRIVY_WRAPPER_URL}/scan/image
    """
    # TODO: trivy-wrapper /scan/image 호출
    # TODO: Critical/High 취약점 수 집계
    # TODO: threshold와 비교하여 결과 판정
    raise NotImplementedError


def collect_filesystem_scan(
    item_id: str,
    maturity: str,
    scan_path: str,
) -> CollectedResult:
    """
    파일시스템 취약점 스캔
    POST {TRIVY_WRAPPER_URL}/scan/fs
    """
    # TODO: trivy-wrapper /scan/fs 호출
    # TODO: 심각도별 취약점 수 집계
    # TODO: 결과 판정 후 CollectedResult 반환
    raise NotImplementedError


def collect_sbom(
    item_id: str,
    maturity: str,
    image_name: str,
) -> CollectedResult:
    """
    SBOM(Software Bill of Materials) 생성
    POST {TRIVY_WRAPPER_URL}/scan/sbom
    """
    # TODO: trivy-wrapper /scan/sbom 호출
    # TODO: 컴포넌트 수, 라이선스 정보 집계
    # TODO: SBOM 존재 여부로 결과 판정
    raise NotImplementedError
