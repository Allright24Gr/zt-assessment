"""입력 검증 회귀 방지 — scan_targets / IdP·SIEM URL/자격에 대한 메타문자 차단."""
from __future__ import annotations

import pytest

from routers.validators import (
    validate_nmap_target, validate_trivy_image, validate_https_url,
    validate_entra_tenant_id, validate_okta_domain,
)


# ─── nmap target ────────────────────────────────────────────────────────────


def test_nmap_target_domain_ok():
    assert validate_nmap_target("scanme.nmap.org") == "scanme.nmap.org"


def test_nmap_target_cidr_ok():
    assert validate_nmap_target("192.168.1.0/24") == "192.168.1.0/24"


def test_nmap_target_rejects_shell_meta():
    with pytest.raises(ValueError):
        validate_nmap_target("; rm -rf /")


def test_nmap_target_rejects_command_substitution():
    with pytest.raises(ValueError):
        validate_nmap_target("$(whoami)")


# ─── trivy image ────────────────────────────────────────────────────────────


def test_trivy_image_simple_ok():
    assert validate_trivy_image("nginx:1.25") == "nginx:1.25"


def test_trivy_image_registry_ok():
    assert validate_trivy_image("ghcr.io/foo/bar:v1.2.3") == "ghcr.io/foo/bar:v1.2.3"


def test_trivy_image_rejects_semicolon():
    with pytest.raises(ValueError):
        validate_trivy_image("nginx;ls")


def test_trivy_image_rejects_backtick():
    with pytest.raises(ValueError):
        validate_trivy_image("`whoami`")


# ─── https url ──────────────────────────────────────────────────────────────


def test_https_url_ok():
    assert validate_https_url("https://example.com:8443") == "https://example.com:8443"


def test_https_url_rejects_javascript_scheme():
    with pytest.raises(ValueError):
        validate_https_url("javascript:alert(1)")


def test_https_url_rejects_file_scheme():
    with pytest.raises(ValueError):
        validate_https_url("file:///etc/passwd")


# ─── entra tenant_id ────────────────────────────────────────────────────────


def test_entra_tenant_uuid_ok():
    uuid = "12345678-1234-1234-1234-123456789abc"
    assert validate_entra_tenant_id(uuid) == uuid


def test_entra_tenant_domain_ok():
    assert validate_entra_tenant_id("contoso.onmicrosoft.com") == "contoso.onmicrosoft.com"


def test_entra_tenant_rejects_shell_meta():
    with pytest.raises(ValueError):
        validate_entra_tenant_id("; ls")


# ─── okta domain ────────────────────────────────────────────────────────────


def test_okta_domain_ok():
    assert validate_okta_domain("dev-12345.okta.com") == "dev-12345.okta.com"


def test_okta_domain_rejects_shell_meta():
    with pytest.raises(ValueError):
        validate_okta_domain("; ls")


def test_okta_domain_rejects_javascript():
    with pytest.raises(ValueError):
        validate_okta_domain("javascript:alert(1)")
