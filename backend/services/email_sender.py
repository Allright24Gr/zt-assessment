"""email_sender.py — AWS SES 기반 메일 발송.

설계 요지:
- 자격증명 우선순위는 boto3 기본 체인을 그대로 사용한다. EC2 IAM role → 환경변수 →
  ~/.aws/credentials 순으로 자동 탐색되므로 별도 분기 코드를 두지 않는다.
- DRY_RUN 모드(EMAIL_DRY_RUN=true 또는 AWS 자격증명 부재)에서는 실제 SES 호출을 생략하고
  콘솔에 본문을 출력한다. 로컬 개발/시연 환경에서 SES 권한 없이도 수신자 흐름을 검증할 수 있다.
- 템플릿은 Jinja2로 backend/services/email_templates/ 아래 <template>.txt + .html 쌍을 읽는다.
- audit logger 'zt.audit' 채널에 시도/성공/실패를 1줄 기록한다. 수신자는 마스킹.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape, TemplateNotFound

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("zt.audit")

_TEMPLATE_DIR = Path(__file__).parent / "email_templates"
_jinja_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(enabled_extensions=("html",), default=False),
)


def _mask_email(addr: str) -> str:
    """감사 로그 노출용 수신자 마스킹: 'alice@example.com' → 'a***@example.com'."""
    if not addr or "@" not in addr:
        return "***"
    local, _, domain = addr.partition("@")
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"


def _is_dry_run() -> bool:
    """DRY_RUN 판정.

    - EMAIL_DRY_RUN=true 명시 시 항상 DRY_RUN.
    - 그 외에는 AWS_ACCESS_KEY_ID 미설정이면 DRY_RUN. (EC2 IAM role 환경에서는
      EMAIL_DRY_RUN=false 로 명시해야 실제 발송된다 — 운영 배포 시 .env에 추가 필요.)
    """
    flag = os.getenv("EMAIL_DRY_RUN", "").strip().lower()
    if flag in {"true", "1", "yes", "on"}:
        return True
    if flag in {"false", "0", "no", "off"}:
        return False
    # 미지정 시: AWS_ACCESS_KEY_ID 없으면 DRY_RUN 으로 안전하게 분기
    return not os.getenv("AWS_ACCESS_KEY_ID")


def _render(template: str, context: dict[str, Any]) -> tuple[str, str]:
    """(text_body, html_body) 반환. .html 미존재 시 text를 <pre>로 감싼 fallback."""
    try:
        text_tpl = _jinja_env.get_template(f"{template}.txt")
    except TemplateNotFound as exc:
        raise ValueError(f"이메일 템플릿 없음: {template}.txt") from exc
    text_body = text_tpl.render(**context)

    try:
        html_tpl = _jinja_env.get_template(f"{template}.html")
        html_body = html_tpl.render(**context)
    except TemplateNotFound:
        # html이 없으면 text를 단순 감싸기 — 운영에선 두 파일 다 두는 것을 권장.
        html_body = f"<pre style=\"font-family:monospace;\">{text_body}</pre>"
    return text_body, html_body


def send_email(to: str, subject: str, template: str, context: dict) -> dict:
    """메일 발송. template은 email_templates/<template>.{txt,html} 파일명을 가리킨다.

    반환: {"status": "sent" | "dry_run", "message_id": str | None, "to": str}
    실패 시 예외 raise (호출 측에서 try/except로 흡수해야 함).
    """
    sender = os.getenv("EMAIL_FROM")
    if not sender:
        raise ValueError("EMAIL_FROM 환경변수가 설정되지 않았습니다.")

    text_body, html_body = _render(template, context or {})
    masked = _mask_email(to)
    audit_logger.info("[email] try template=%s to=%s subject=%s", template, masked, subject)

    if _is_dry_run():
        # 콘솔에 풀 본문 출력 — 개발자가 메일 내용을 즉시 검증할 수 있도록.
        banner = "=" * 60
        print(banner)
        print(f"[EMAIL DRY_RUN] from={sender} to={to}")
        print(f"subject: {subject}")
        print(f"template: {template}")
        print("-" * 60)
        print(text_body)
        print(banner)
        audit_logger.info("[email] dry_run ok template=%s to=%s", template, masked)
        return {"status": "dry_run", "message_id": None, "to": to}

    # 실제 SES 호출. boto3는 lazy import — DRY_RUN 경로에서는 패키지 없어도 동작하도록.
    try:
        import boto3  # type: ignore
        from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
    except ImportError as exc:
        audit_logger.warning("[email] boto3 미설치 to=%s err=%s", masked, exc)
        raise RuntimeError("boto3가 설치되지 않았습니다. requirements.txt 갱신 후 재설치하세요.") from exc

    region = os.getenv("AWS_REGION", "ap-northeast-2")
    try:
        client = boto3.client("ses", region_name=region)
        resp = client.send_email(
            Source=sender,
            Destination={"ToAddresses": [to]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {
                    "Text": {"Data": text_body, "Charset": "UTF-8"},
                    "Html": {"Data": html_body, "Charset": "UTF-8"},
                },
            },
        )
    except (BotoCoreError, ClientError) as exc:
        audit_logger.warning("[email] fail template=%s to=%s err=%s", template, masked, exc)
        logger.exception("SES send_email 실패: to=%s template=%s", masked, template)
        raise

    message_id: Optional[str] = resp.get("MessageId") if isinstance(resp, dict) else None
    audit_logger.info("[email] ok template=%s to=%s message_id=%s", template, masked, message_id)
    return {"status": "sent", "message_id": message_id, "to": to}
