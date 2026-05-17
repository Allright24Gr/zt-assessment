"""
ZT 가이드라인 2.0 → NIST SP 800-207 / CIS Controls v8 매핑.

- NIST 800-207: 7대 원칙 (data sources / device identity / dynamic policy 등)
- CIS Controls v8: 18개 control (IG1/IG2/IG3 단계)

매핑은 pillar + category 기반 휴리스틱 + 명시 item_id 오버라이드.
한 항목이 여러 표준에 동시 매핑될 수 있음 (multi-mapping).
"""

# NIST SP 800-207 — 7대 원칙
NIST_800_207_TENETS = {
    "1": "All data sources and computing services are considered resources",
    "2": "All communication is secured regardless of network location",
    "3": "Access to individual enterprise resources is granted on a per-session basis",
    "4": "Access to resources is determined by dynamic policy",
    "5": "Enterprise monitors and measures the integrity and security posture of all owned and associated assets",
    "6": "All resource authentication and authorization are dynamic and strictly enforced",
    "7": "Enterprise collects as much information as possible about current state of assets, network infrastructure and communications",
}

# CIS Controls v8 — 18개 control
CIS_CONTROLS_V8 = {
    "01": "Inventory and Control of Enterprise Assets",
    "02": "Inventory and Control of Software Assets",
    "03": "Data Protection",
    "04": "Secure Configuration of Enterprise Assets and Software",
    "05": "Account Management",
    "06": "Access Control Management",
    "07": "Continuous Vulnerability Management",
    "08": "Audit Log Management",
    "09": "Email and Web Browser Protections",
    "10": "Malware Defenses",
    "11": "Data Recovery",
    "12": "Network Infrastructure Management",
    "13": "Network Monitoring and Defense",
    "14": "Security Awareness and Skills Training",
    "15": "Service Provider Management",
    "16": "Application Software Security",
    "17": "Incident Response Management",
    "18": "Penetration Testing",
}

# Pillar(한국 ZT 2.0) → NIST/CIS 매핑 (휴리스틱 기본)
PILLAR_TO_NIST = {
    "식별자 및 신원":       ["3", "4", "6"],  # per-session + dynamic policy + auth
    "기기 및 엔드포인트":   ["1", "5", "7"],
    "네트워크":             ["2", "7"],
    "시스템":               ["4", "5", "6"],
    "애플리케이션 및 워크로드": ["1", "4", "6"],
    "데이터":               ["1", "3"],
}

PILLAR_TO_CIS = {
    "식별자 및 신원":       ["05", "06"],
    "기기 및 엔드포인트":   ["01", "02", "04"],
    "네트워크":             ["12", "13"],
    "시스템":               ["04", "08", "17"],
    "애플리케이션 및 워크로드": ["02", "16", "07"],
    "데이터":               ["03", "11"],
}

# Category 키워드 기반 보강 (more specific)
CATEGORY_KEYWORDS_TO_CIS = {
    "사용자 인벤토리":  ["05"],
    "다중인증":         ["06"],
    "MFA":              ["06"],
    "세션":             ["06"],
    "권한":             ["06"],
    "패치":             ["07"],
    "취약점":           ["07"],
    "로그":             ["08"],
    "DLP":              ["03"],
    "악성":             ["10"],
    "백업":             ["11"],
    "세그멘테이션":     ["12"],
    "탐지":             ["13"],
    "공급망":           ["15"],
    "사고":             ["17"],
}


def map_item_to_standards(item_id: str, pillar: str, category: str = "", item_name: str = "") -> dict:
    """단일 진단 항목 → NIST/CIS 매핑 반환.

    반환:
        {
            "nist_800_207": [{"tenet": "3", "title": "Access granted on a per-session basis"}, ...],
            "cis_controls_v8": [{"control_id": "06", "title": "Access Control Management"}, ...]
        }
    """
    nist_ids = PILLAR_TO_NIST.get(pillar, [])
    cis_ids = list(PILLAR_TO_CIS.get(pillar, []))

    # category/item_name 키워드 보강
    haystack = f"{category} {item_name}"
    for keyword, extras in CATEGORY_KEYWORDS_TO_CIS.items():
        if keyword in haystack:
            for c in extras:
                if c not in cis_ids:
                    cis_ids.append(c)

    return {
        "nist_800_207": [{"tenet": t, "title": NIST_800_207_TENETS[t]} for t in nist_ids],
        "cis_controls_v8": [{"control_id": c, "title": CIS_CONTROLS_V8[c]} for c in cis_ids],
    }


def session_standards_summary(checklist_results: list[dict]) -> dict:
    """세션 전체 결과 → 표준별 충족/미충족 집계.

    각 NIST tenet, CIS control 별로:
        {"id": "06", "title": "...", "pass": 12, "fail": 3, "na": 5, "compliance_rate": 0.80}

    한 항목이 여러 표준에 매핑되면 모든 매핑에 동시 카운트.
    """
    from collections import defaultdict

    nist_agg = defaultdict(lambda: {"pass": 0, "fail": 0, "na": 0})
    cis_agg = defaultdict(lambda: {"pass": 0, "fail": 0, "na": 0})

    for r in checklist_results:
        result = r.get("result", "")
        mapping = map_item_to_standards(
            r.get("item_id", ""),
            r.get("pillar", ""),
            r.get("category", ""),
            r.get("item", "") or r.get("item_name", ""),
        )
        bucket = "pass" if result == "충족" else ("na" if result == "평가불가" else "fail")
        for n in mapping["nist_800_207"]:
            nist_agg[n["tenet"]][bucket] += 1
        for c in mapping["cis_controls_v8"]:
            cis_agg[c["control_id"]][bucket] += 1

    def _rate(agg):
        denom = agg["pass"] + agg["fail"]
        return round(agg["pass"] / denom, 4) if denom else None

    return {
        "nist_800_207": [
            {"tenet": tid, "title": NIST_800_207_TENETS[tid],
             "pass": v["pass"], "fail": v["fail"], "na": v["na"],
             "compliance_rate": _rate(v)}
            for tid, v in sorted(nist_agg.items())
        ],
        "cis_controls_v8": [
            {"control_id": cid, "title": CIS_CONTROLS_V8[cid],
             "pass": v["pass"], "fail": v["fail"], "na": v["na"],
             "compliance_rate": _rate(v)}
            for cid, v in sorted(cis_agg.items())
        ],
    }
