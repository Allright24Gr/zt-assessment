"""aws_security_hub_collector.py — AWS Security Hub 진단 함수 (Phase A: 15개)

entra_collector.py / defender_collector.py 와 동일한 추상을 가진 모듈.
AWS Security Hub API (boto3) 를 사용한다.

인증: 다음 우선순위로 자격을 해석한다.
  1) set_session_creds()로 주입된 dict (NewAssessment 사용자 입력)
  2) 환경변수 AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_REGION
  3) IAM role (EC2 instance profile) — boto3 가 자동으로 STS 자격 사용
하나라도 해석되지 않으면 _err 로 안전 fallback.

item_id 체계: {항목번호}.{성숙도번호}_{질문번호} — 다른 collector 와 동일하므로
dispatcher 자동매핑(_autodiscover) 에서 docstring 첫 줄로 자동 추출된다.

# ════════════════════════════════════════════════════════════════════════
# ASSESSMENT.PY 등록 가이드 (통합 시 참조)
# ════════════════════════════════════════════════════════════════════════
# 다른 작업자가 이 모듈을 assessment.py 에 등록할 때 아래 패치 포인트를 참조하라:
#
# ALL_TOOLS = (..., "aws_securityhub", "azure_defender")
# _TOOL_MODULE = {
#     ...,
#     "aws_securityhub": "collectors.aws_security_hub_collector",
#     "azure_defender":  "collectors.azure_defender_cloud_collector",
# }
#
# 새 카테고리: _CLOUD_TOOL_OF / _CLOUD_AUTO_TOOLS — ProfileSelect.cloud_type
#   - aws  → aws_securityhub
#   - azure→ azure_defender
#
# AssessmentRunRequest 필드 추가:
#   aws_creds: Optional[dict] = None           # {aws_access_key_id, aws_secret_access_key, aws_region}
#   azure_defender_creds: Optional[dict] = None # {tenant_id, client_id, client_secret, subscription_id}
#
# _mask_creds 가드 (assessment.py 안 함수에):
#   - aws_creds.aws_secret_access_key            → "***"
#   - azure_defender_creds.client_secret         → "***"
#
# set_session_creds 호출 위치 (_run_collectors):
#   - aws_security_hub_collector.set_session_creds(req.aws_creds)
#   - azure_defender_cloud_collector.set_session_creds(req.azure_defender_creds)
# ════════════════════════════════════════════════════════════════════════
"""
from typing import Optional, Any, Tuple, List
from datetime import datetime, timezone
import os
import logging

CollectedResult = dict
logger = logging.getLogger(__name__)

# boto3 는 requirements.txt 에 이미 있음 (SES 발송용). 지연 import 로 단위 테스트 환경
# 에서 모듈 부재 시에도 collector 모듈 import 자체는 실패하지 않도록 처리.
try:
    import boto3  # type: ignore
    from botocore.exceptions import (  # type: ignore
        BotoCoreError,
        ClientError,
        NoCredentialsError,
        EndpointConnectionError,
    )
    _BOTO3_AVAILABLE = True
except Exception:  # pragma: no cover - 환경 의존 fallback
    boto3 = None  # type: ignore
    BotoCoreError = Exception  # type: ignore
    ClientError = Exception  # type: ignore
    NoCredentialsError = Exception  # type: ignore
    EndpointConnectionError = Exception  # type: ignore
    _BOTO3_AVAILABLE = False

# fallback 환경변수 — 사용자가 NewAssessment 에서 자격을 직접 입력하지 않은 경우 사용.
# (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY 는 SES 와 공유될 수 있음 — .env.example 주석 참조)
AWS_ACCESS_KEY_ID     = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
AWS_REGION_ENV        = os.environ.get("AWS_REGION", "ap-northeast-2")

# ─── session-scoped credential override ──────────────────────────────────────
_session_creds: Optional[dict] = None
_client_cache: dict = {}  # {"securityhub": client, "config": client, "organizations": client}


def set_session_creds(creds: Optional[dict]) -> None:
    """세션 단위 AWS 자격을 모듈 전역에 주입. None 이면 해제 + 클라이언트 캐시 무효화."""
    global _session_creds, _client_cache
    _session_creds = creds or None
    _client_cache = {}


def _aws_region() -> str:
    if _session_creds and _session_creds.get("aws_region"):
        return str(_session_creds["aws_region"]).strip().lower()
    return (AWS_REGION_ENV or "").strip().lower()


def _aws_access_key() -> str:
    if _session_creds and _session_creds.get("aws_access_key_id"):
        return str(_session_creds["aws_access_key_id"])
    return AWS_ACCESS_KEY_ID


def _aws_secret_key() -> str:
    if _session_creds and _session_creds.get("aws_secret_access_key"):
        return str(_session_creds["aws_secret_access_key"])
    return AWS_SECRET_ACCESS_KEY


# ─────────────────────────── internal helpers ───────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_result(
    item_id: str,
    maturity: str,
    metric_key: str,
    metric_value: float,
    threshold: float,
    result: str,
    raw_json: dict,
    error: Optional[str] = None,
) -> CollectedResult:
    return {
        "item_id":      item_id,
        "maturity":     maturity,
        "tool":         "aws_securityhub",
        "result":       result,
        "metric_key":   metric_key,
        "metric_value": float(metric_value),
        "threshold":    float(threshold),
        "raw_json":     raw_json,
        "collected_at": _now_iso(),
        "error":        error,
    }


def _ok(item_id, maturity, result, metric_key, metric_value, threshold, raw_json) -> CollectedResult:
    return _make_result(item_id, maturity, metric_key, metric_value, threshold, result, raw_json or {}, None)


def _err(item_id, maturity, metric_key, threshold, error_msg, raw_json=None) -> CollectedResult:
    return _make_result(item_id, maturity, metric_key, 0.0, threshold, "평가불가", raw_json or {}, error_msg)


def _unavailable(item_id, maturity, metric_key, threshold, error_msg, raw_json=None) -> CollectedResult:
    return _err(item_id, maturity, metric_key, threshold, error_msg, raw_json)


def _mask_creds(creds: dict) -> dict:
    """모듈 내부에서 raw_json/디버그에 자격을 노출해야 할 때 사용하는 가드."""
    safe = dict(creds or {})
    if safe.get("aws_secret_access_key"):
        safe["aws_secret_access_key"] = "***"
    return safe


def _get_client(service: str):
    """boto3 client (securityhub / config / organizations / inspector2) 캐시 반환.

    (client, error) 튜플로 반환. error 가 있으면 client 는 None.
    IAM role 사용 가능 환경(EC2 instance profile) 에서는 access key 가 없어도 동작.
    """
    if not _BOTO3_AVAILABLE:
        return None, "boto3 모듈 사용 불가"
    if service in _client_cache:
        return _client_cache[service], None
    region = _aws_region()
    if not region:
        return None, "AWS region 미설정"
    ak = _aws_access_key()
    sk = _aws_secret_key()
    try:
        if ak and sk:
            client = boto3.client(
                service,
                region_name=region,
                aws_access_key_id=ak,
                aws_secret_access_key=sk,
            )
        else:
            # IAM role(EC2 instance profile) 자동 사용
            client = boto3.client(service, region_name=region)
        _client_cache[service] = client
        return client, None
    except (BotoCoreError, ClientError, NoCredentialsError) as exc:
        return None, f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # pragma: no cover - 방어
        return None, f"{type(exc).__name__}: {exc}"


def _classify_aws_error(exc: Exception) -> str:
    """AWS 예외를 사용자가 읽기 쉬운 한국어 메시지로 변환."""
    if isinstance(exc, NoCredentialsError):
        return "AWS 자격 미설정: access_key/secret 또는 IAM role 필요"
    if isinstance(exc, EndpointConnectionError):
        return "AWS region 미지원 또는 네트워크 단절"
    if isinstance(exc, ClientError):
        code = (getattr(exc, "response", {}) or {}).get("Error", {}).get("Code", "")
        msg = (getattr(exc, "response", {}) or {}).get("Error", {}).get("Message", str(exc))
        if code in ("AccessDeniedException", "UnauthorizedException", "AccessDenied"):
            return f"AWS 권한 부족: {msg}"
        if code in ("InvalidAccessException", "ResourceNotFoundException"):
            return f"AWS Security Hub 비활성 또는 리소스 없음: {msg}"
        if code == "ThrottlingException":
            return f"AWS API 쿼터 초과: {msg}"
        return f"AWS 오류({code}): {msg}"
    return f"{type(exc).__name__}: {exc}"


def _get_findings(filters: dict, max_results: int = 100) -> Tuple[Optional[List[dict]], Optional[str]]:
    """Security Hub get_findings 호출. 다중 페이지 일부만 가져옴(상한 max_results).

    Filters: AWS Security Hub Filter 구조 그대로 (예: {"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]})
    """
    client, err = _get_client("securityhub")
    if err:
        return None, err
    findings: list = []
    next_token: Optional[str] = None
    try:
        # 최대 2페이지(=200건) 까지만 — 카운트 지표는 충분, 비용도 통제
        for _ in range(2):
            kwargs = {"Filters": filters, "MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = client.get_findings(**kwargs)
            findings.extend(resp.get("Findings") or [])
            next_token = resp.get("NextToken")
            if not next_token or len(findings) >= max_results:
                break
    except Exception as exc:
        return None, _classify_aws_error(exc)
    return findings, None


def _filter_eq(field: str, values: List[str]) -> List[dict]:
    return [{"Value": v, "Comparison": "EQUALS"} for v in values]


# ─────────────────────────── collectors (15) ───────────────────────────

def collect_sca_compliance(item_id: str, maturity: str) -> CollectedResult:
    """2.1.1.2_1: Security Hub 활성 standards ≥ 1 → 충족 / 0 → 미충족"""
    MK, TH = "active_standards_count", 1.0
    client, err = _get_client("securityhub")
    if err:
        return _err(item_id, maturity, MK, TH, err)
    try:
        resp = client.describe_standards()
        # describe_standards 는 사용 가능 standards 전체를 반환. 활성 여부는 subscription 으로 판단.
        sub = client.get_enabled_standards()
        enabled = sub.get("StandardsSubscriptions") or []
        active = [
            s for s in enabled
            if str(s.get("StandardsStatus", "")).upper() == "READY"
        ]
        count = len(active)
    except Exception as exc:
        return _err(item_id, maturity, MK, TH, _classify_aws_error(exc))
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"active_standards": count,
                "standards_arns": [s.get("StandardsArn") for s in active][:5]})


def collect_policy_violation_alerts(item_id: str, maturity: str) -> CollectedResult:
    """2.1.1.2_2: 활성 + FAILED finding ≥ 1 → 충족(탐지 동작) / 0 → 미충족"""
    MK, TH = "policy_violation_findings", 1.0
    filters = {
        "RecordState":      _filter_eq("RecordState", ["ACTIVE"]),
        "ComplianceStatus": _filter_eq("ComplianceStatus", ["FAILED"]),
    }
    findings, err = _get_findings(filters, max_results=200)
    if err:
        return _err(item_id, maturity, MK, TH, err)
    count = len(findings or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"policy_violation_findings": count})


def collect_sca_auto_remediation(item_id: str, maturity: str) -> CollectedResult:
    """2.1.1.3_1: 자동 수정 가능 control 비율 ≥ 50% → 충족 / 20~50% → 부분충족"""
    MK, TH = "auto_remediation_ratio", 0.5
    client, err = _get_client("securityhub")
    if err:
        return _err(item_id, maturity, MK, TH, err)
    try:
        subs = client.get_enabled_standards().get("StandardsSubscriptions") or []
        if not subs:
            return _err(item_id, maturity, MK, TH, "활성 Standard 없음 (분모 0)")
        total_controls = 0
        with_remediation = 0
        # 첫 두 standard 만 점검 — API 호출 비용 통제
        for sub in subs[:2]:
            arn = sub.get("StandardsSubscriptionArn")
            if not arn:
                continue
            next_token: Optional[str] = None
            for _ in range(2):  # 2페이지 한도
                kwargs = {"StandardsSubscriptionArn": arn}
                if next_token:
                    kwargs["NextToken"] = next_token
                resp = client.describe_standards_controls(**kwargs)
                controls = resp.get("Controls") or []
                total_controls += len(controls)
                for c in controls:
                    if c.get("RemediationUrl"):
                        with_remediation += 1
                next_token = resp.get("NextToken")
                if not next_token:
                    break
    except Exception as exc:
        return _err(item_id, maturity, MK, TH, _classify_aws_error(exc))
    if total_controls == 0:
        return _err(item_id, maturity, MK, TH, "control 항목 없음 (분모 0)")
    ratio = with_remediation / total_controls
    if ratio >= TH:
        verdict = "충족"
    elif ratio >= 0.2:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, ratio, TH,
               {"total_controls": total_controls,
                "with_remediation": with_remediation})


def collect_agent_registration(item_id: str, maturity: str) -> CollectedResult:
    """2.3.1.1_2: Security Hub 활성 region 1개 이상 → 충족 (현재 region hub_arn 조회)"""
    MK, TH = "active_hub_count", 1.0
    client, err = _get_client("securityhub")
    if err:
        return _err(item_id, maturity, MK, TH, err)
    try:
        resp = client.describe_hub()
        hub_arn = resp.get("HubArn")
        count = 1 if hub_arn else 0
    except Exception as exc:
        return _err(item_id, maturity, MK, TH, _classify_aws_error(exc))
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"hub_arn": hub_arn, "region": _aws_region()})


def collect_ids_alerts(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.3_2: GuardDuty findings ≥ 1 → 충족(탐지 동작) / 0 → 미충족"""
    MK, TH = "guardduty_findings", 1.0
    filters = {
        "ProductName": _filter_eq("ProductName", ["GuardDuty"]),
        "RecordState": _filter_eq("RecordState", ["ACTIVE"]),
    }
    findings, err = _get_findings(filters, max_results=200)
    if err:
        return _err(item_id, maturity, MK, TH, err)
    count = len(findings or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"guardduty_findings": count})


def collect_threat_detection_alerts(item_id: str, maturity: str) -> CollectedResult:
    """5.2.1.4_2: HIGH/CRITICAL 심각도 findings ≥ 1 → 충족 / 0 → 미충족"""
    MK, TH = "high_severity_findings", 1.0
    filters = {
        "SeverityLabel": _filter_eq("SeverityLabel", ["HIGH", "CRITICAL"]),
        "RecordState":   _filter_eq("RecordState", ["ACTIVE"]),
    }
    findings, err = _get_findings(filters, max_results=200)
    if err:
        return _err(item_id, maturity, MK, TH, err)
    count = len(findings or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"high_severity_findings": count})


def collect_vuln_summary(item_id: str, maturity: str) -> CollectedResult:
    """5.5.2.2_1: Inspector findings ≥ 1 → 충족(취약점 인벤토리) / 0 → 미충족"""
    MK, TH = "inspector_findings", 1.0
    filters = {
        "ProductName": _filter_eq("ProductName", ["Inspector"]),
        "RecordState": _filter_eq("RecordState", ["ACTIVE"]),
    }
    findings, err = _get_findings(filters, max_results=200)
    if err:
        return _err(item_id, maturity, MK, TH, err)
    count = len(findings or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"inspector_findings": count})


def collect_critical_unfixed_vulns(item_id: str, maturity: str) -> CollectedResult:
    """5.5.1.3_1: CRITICAL + 활성 + 미해결(remediation 없음) findings ≤ 5 → 충족"""
    MK, TH = "critical_unfixed_findings", 5.0
    filters = {
        "SeverityLabel": _filter_eq("SeverityLabel", ["CRITICAL"]),
        "RecordState":   _filter_eq("RecordState", ["ACTIVE"]),
        "WorkflowStatus": _filter_eq("WorkflowStatus", ["NEW", "NOTIFIED"]),
    }
    findings, err = _get_findings(filters, max_results=200)
    if err:
        return _err(item_id, maturity, MK, TH, err)
    findings = findings or []
    # remediation 없음 = Remediation.Recommendation.Text 가 비어있는 항목
    unfixed = 0
    for f in findings:
        rec = ((f.get("Remediation") or {}).get("Recommendation") or {})
        if not rec.get("Text") and not rec.get("Url"):
            unfixed += 1
    # 임계 이하면 충족 (적을수록 좋음)
    if unfixed <= TH:
        verdict = "충족"
    elif unfixed <= TH * 2:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, float(unfixed), TH,
               {"critical_unfixed_findings": unfixed,
                "critical_total_active": len(findings)})


def collect_icam_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1.2_1: AWS Config IAM 관련 findings ≥ 1 → 충족(ICAM 인벤토리 가시성)"""
    MK, TH = "iam_findings", 1.0
    filters = {
        "ProductName": _filter_eq("ProductName", ["Config", "Security Hub"]),
        "ResourceType": _filter_eq("ResourceType",
                                    ["AwsIamUser", "AwsIamRole", "AwsIamPolicy", "AwsIamGroup"]),
    }
    findings, err = _get_findings(filters, max_results=200)
    if err:
        return _err(item_id, maturity, MK, TH, err)
    count = len(findings or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"iam_findings": count})


def collect_authz_clients(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.1_3: IAM User/Role 자원 findings (IAM 객체 식별 가능) ≥ 1 → 충족"""
    MK, TH = "iam_resource_findings", 1.0
    filters = {
        "ResourceType": _filter_eq("ResourceType", ["AwsIamUser", "AwsIamRole"]),
    }
    findings, err = _get_findings(filters, max_results=200)
    if err:
        return _err(item_id, maturity, MK, TH, err)
    findings = findings or []
    # 고유 IAM 자원 수 산정
    unique_resources = set()
    for f in findings:
        for r in (f.get("Resources") or []):
            rid = r.get("Id")
            if rid:
                unique_resources.add(rid)
    count = len(unique_resources)
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"unique_iam_resources": count,
                "total_iam_findings": len(findings)})


def collect_auto_block(item_id: str, maturity: str) -> CollectedResult:
    """2.2.1.4_1: 활성 standards 중 자동수정 control 비율 ≥ 30% → 충족 / 10~30% → 부분충족"""
    MK, TH = "auto_block_ratio", 0.3
    client, err = _get_client("securityhub")
    if err:
        return _err(item_id, maturity, MK, TH, err)
    try:
        subs = client.get_enabled_standards().get("StandardsSubscriptions") or []
        if not subs:
            return _err(item_id, maturity, MK, TH, "활성 Standard 없음 (분모 0)")
        total = 0
        with_action = 0
        for sub in subs[:2]:
            arn = sub.get("StandardsSubscriptionArn")
            if not arn:
                continue
            resp = client.describe_standards_controls(StandardsSubscriptionArn=arn)
            controls = resp.get("Controls") or []
            total += len(controls)
            for c in controls:
                # ControlStatus ENABLED 인 control 만 자동 차단 후보로 카운트
                status = str(c.get("ControlStatus", "")).upper()
                if status == "ENABLED" and c.get("RemediationUrl"):
                    with_action += 1
    except Exception as exc:
        return _err(item_id, maturity, MK, TH, _classify_aws_error(exc))
    if total == 0:
        return _err(item_id, maturity, MK, TH, "control 항목 없음 (분모 0)")
    ratio = with_action / total
    if ratio >= TH:
        verdict = "충족"
    elif ratio >= 0.1:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, ratio, TH,
               {"total_enabled_controls": total, "with_remediation_action": with_action})


def collect_tls_services(item_id: str, maturity: str) -> CollectedResult:
    """3.3.1.1_2: 미암호화 채널 findings (적을수록 좋음) ≤ 3 → 충족 / 3~10 → 부분충족"""
    MK, TH = "unencrypted_protocol_findings", 3.0
    # Title 에 'encryption' / 'TLS' / 'SSL' 가 들어간 활성 FAILED 항목으로 근사
    filters = {
        "RecordState":      _filter_eq("RecordState", ["ACTIVE"]),
        "ComplianceStatus": _filter_eq("ComplianceStatus", ["FAILED"]),
    }
    findings, err = _get_findings(filters, max_results=200)
    if err:
        return _err(item_id, maturity, MK, TH, err)
    findings = findings or []
    keywords = ("encryption", "tls", "ssl", "https", "http ", "in-transit")
    count = 0
    for f in findings:
        title = str(f.get("Title") or "").lower()
        desc = str(f.get("Description") or "").lower()
        if any(k in title or k in desc for k in keywords):
            count += 1
    # 적을수록 좋음 (반비례 평가)
    if count <= TH:
        verdict = "충족"
    elif count <= 10:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"unencrypted_protocol_findings": count,
                "total_failed_findings": len(findings)})


def collect_perimeter_model(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.1_2: VPC/SG/네트워크 노출 findings ≥ 1 → 충족(가시성 확보)"""
    MK, TH = "network_exposure_findings", 1.0
    filters = {
        "ResourceType": _filter_eq(
            "ResourceType",
            ["AwsEc2SecurityGroup", "AwsEc2Vpc", "AwsEc2NetworkAcl",
             "AwsEc2Subnet", "AwsElbv2LoadBalancer"],
        ),
    }
    findings, err = _get_findings(filters, max_results=200)
    if err:
        return _err(item_id, maturity, MK, TH, err)
    count = len(findings or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"network_exposure_findings": count})


def collect_central_authz_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.2_1: AWS Organizations 적용 (SCP 가능 상태) → 충족 / 단독 계정 → 미충족"""
    MK, TH = "org_attached", 1.0
    client, err = _get_client("organizations")
    if err:
        # organizations 클라이언트 자체 실패 시 (region/권한) — Security Hub finding 으로 우회
        filters = {
            "ProductName": _filter_eq("ProductName", ["Security Hub"]),
            "ResourceType": _filter_eq("ResourceType", ["AwsAccount"]),
        }
        findings, ferr = _get_findings(filters, max_results=50)
        if ferr:
            return _err(item_id, maturity, MK, TH, err)
        count = 1 if findings else 0
        verdict = "충족" if count >= TH else "미충족"
        return _ok(item_id, maturity, verdict, MK, float(count), TH,
                   {"source": "fallback_findings", "indicator": count})
    try:
        resp = client.describe_organization()
        org = resp.get("Organization") or {}
        attached = 1 if org.get("Id") else 0
    except Exception as exc:
        # AWSOrganizationsNotInUseException 등은 미충족으로 처리 (Organization 미가입)
        msg = _classify_aws_error(exc)
        if "AWSOrganizationsNotInUse" in str(exc):
            return _ok(item_id, maturity, "미충족", MK, 0.0, TH,
                       {"reason": "AWS Organizations 미가입"})
        return _err(item_id, maturity, MK, TH, msg)
    verdict = "충족" if attached >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(attached), TH,
               {"organization_id": org.get("Id"),
                "feature_set": org.get("FeatureSet")})


def collect_full_component_scan(item_id: str, maturity: str) -> CollectedResult:
    """5.4.1.3_4: Inspector + ECR scan coverage (Inspector 활성 + ECR 스캔 finding 존재) → 충족"""
    MK, TH = "full_scan_coverage", 2.0
    # 1) Inspector 활성 — Inspector 발생 finding 존재 여부로 근사
    inspector_filters = {
        "ProductName": _filter_eq("ProductName", ["Inspector"]),
    }
    insp_findings, err1 = _get_findings(inspector_filters, max_results=10)
    # 2) ECR 컨테이너 스캔 — ResourceType=AwsEcrContainerImage
    ecr_filters = {
        "ResourceType": _filter_eq("ResourceType",
                                    ["AwsEcrContainerImage", "AwsEcrRepository"]),
    }
    ecr_findings, err2 = _get_findings(ecr_filters, max_results=10)
    if err1 and err2:
        return _err(item_id, maturity, MK, TH, f"Inspector: {err1}; ECR: {err2}")
    score = 0
    if insp_findings is not None and len(insp_findings) > 0:
        score += 1
    if ecr_findings is not None and len(ecr_findings) > 0:
        score += 1
    if score >= TH:
        verdict = "충족"
    elif score >= 1:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, float(score), TH,
               {"inspector_active": bool(insp_findings),
                "ecr_active": bool(ecr_findings)})
