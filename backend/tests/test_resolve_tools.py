"""profile_select(idp_type / siem_type) → 도구 활성/비활성 자동 보정 검증.

4 오픈소스 도구만 운영 — IdP=keycloak / SIEM=wazuh 만 자동, 나머지 환경은 수동 폴백.
"""
from __future__ import annotations

from routers.assessment import _resolve_supported_tools, ALL_TOOLS


def _all_enabled(requested=None):
    return requested or {t: True for t in ALL_TOOLS}


def test_no_profile_keeps_all_active():
    res = _resolve_supported_tools(None, _all_enabled())
    for t in ALL_TOOLS:
        assert res[t] is True, f"{t} should be active by default"


def test_idp_keycloak_keeps_keycloak():
    res = _resolve_supported_tools({"idp_type": "keycloak"}, _all_enabled())
    assert res["keycloak"] is True
    # 비-IDP 도구는 영향 없음
    assert res["wazuh"] is True
    assert res["nmap"] is True


def test_idp_none_disables_keycloak():
    res = _resolve_supported_tools({"idp_type": "none"}, _all_enabled())
    assert res["keycloak"] is False
    # 비-IDP 도구는 유지
    assert res["wazuh"] is True
    assert res["nmap"] is True
    assert res["trivy"] is True


def test_siem_wazuh_keeps_wazuh():
    res = _resolve_supported_tools({"siem_type": "wazuh"}, _all_enabled())
    assert res["wazuh"] is True
    assert res["keycloak"] is True


def test_siem_none_disables_wazuh():
    res = _resolve_supported_tools({"siem_type": "none"}, _all_enabled())
    assert res["wazuh"] is False
    assert res["keycloak"] is True
    assert res["nmap"] is True
