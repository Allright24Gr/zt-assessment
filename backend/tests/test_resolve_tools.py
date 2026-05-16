"""profile_select(idp_type / siem_type) → 도구 활성/비활성 자동 보정 검증."""
from __future__ import annotations

from routers.assessment import _resolve_supported_tools, ALL_TOOLS


def _all_enabled(requested=None):
    return requested or {t: True for t in ALL_TOOLS}


def test_no_profile_keeps_all_active():
    res = _resolve_supported_tools(None, _all_enabled())
    for t in ALL_TOOLS:
        assert res[t] is True, f"{t} should be active by default"


def test_idp_keycloak_disables_other_idps():
    res = _resolve_supported_tools({"idp_type": "keycloak"}, _all_enabled())
    assert res["keycloak"] is True
    assert res["entra"] is False
    assert res["okta"] is False


def test_idp_entra_disables_others():
    res = _resolve_supported_tools({"idp_type": "entra"}, _all_enabled())
    assert res["entra"] is True
    assert res["keycloak"] is False
    assert res["okta"] is False


def test_idp_okta_disables_others():
    res = _resolve_supported_tools({"idp_type": "okta"}, _all_enabled())
    assert res["okta"] is True
    assert res["keycloak"] is False
    assert res["entra"] is False


def test_idp_none_disables_all_idp_auto_tools():
    res = _resolve_supported_tools({"idp_type": "none"}, _all_enabled())
    assert res["keycloak"] is False
    assert res["entra"] is False
    assert res["okta"] is False
    # 비-IDP 도구는 유지
    assert res["nmap"] is True
    assert res["trivy"] is True


def test_siem_splunk_disables_wazuh():
    res = _resolve_supported_tools({"siem_type": "splunk"}, _all_enabled())
    assert res["splunk"] is True
    assert res["wazuh"] is False
