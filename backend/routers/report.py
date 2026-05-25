import asyncio
import io
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session

from database import get_db
from models import (
    DiagnosisSession, DiagnosisResult, MaturityScore,
    Checklist, Organization, User, ImprovementGuide, Evidence, CollectedData,
)
from scoring.engine import determine_maturity_level
from routers.auth import get_current_user, assert_session_access
from routers.assessment import build_evaluation_meta
from services.standards_mapping import map_item_to_standards, session_standards_summary

router = APIRouter()
logger = logging.getLogger("zt.report")

# ── 한글 폰트 등록 (NanumGothic, Dockerfile에서 fonts-nanum 설치) ──────────
_FONT_REGISTERED = False
_FONT_NAME = "Helvetica"  # fallback

def _ensure_font():
    global _FONT_REGISTERED, _FONT_NAME
    if _FONT_REGISTERED:
        return
    candidates = [
        "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
        "/usr/share/fonts/nanum/NanumGothic.ttf",
    ]
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont

        for path in candidates:
            if os.path.exists(path):
                pdfmetrics.registerFont(TTFont("NanumGothic", path))
                _FONT_NAME = "NanumGothic"
                break
        else:
            logger.warning(
                "[report] NanumGothic 폰트를 찾지 못해 Helvetica 폴백 사용. 후보: %s",
                candidates,
            )
    except Exception as e:
        logger.warning("[report] 폰트 등록 실패 — Helvetica 폴백 (%s)", e)
    _FONT_REGISTERED = True


def _first_step(steps) -> str:
    """ImprovementGuide.steps 가 list/dict/str 어떤 형태든 첫 step 문자열 반환."""
    if not steps:
        return ""
    if isinstance(steps, list):
        first = steps[0] if steps else ""
        if isinstance(first, dict):
            return str(first.get("description") or first.get("step") or first.get("text") or "")
        return str(first) if first else ""
    if isinstance(steps, dict):
        # {"1": "...", "2": "..."} 같은 형태 대응
        try:
            keys = sorted(steps.keys())
            return str(steps[keys[0]]) if keys else ""
        except Exception:
            return ""
    return str(steps)


# ── 공통 데이터 빌더 ────────────────────────────────────────────────────────

def _build_data(session_id: int, db: Session) -> dict:
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")

    org  = db.query(Organization).filter(Organization.org_id == session.org_id).first()
    user = db.query(User).filter(User.user_id == session.user_id).first()

    maturity_rows = db.query(MaturityScore).filter(
        MaturityScore.session_id == session_id
    ).all()
    pillar_scores = [
        {
            "pillar": m.pillar,
            "score": round(m.score or 0.0, 3),
            "level": determine_maturity_level(m.score or 0.0),
            "pass_cnt": m.pass_cnt or 0,
            "fail_cnt": m.fail_cnt or 0,
            "na_cnt": m.na_cnt or 0,
        }
        for m in maturity_rows
    ]

    results = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(DiagnosisResult.session_id == session_id)
        .all()
    )

    checklist_results, fail_items = [], []
    for dr, cl in results:
        item = {
            "item_id":       cl.item_id,
            "pillar":        cl.pillar,
            "category":      cl.category,
            "item_name":     cl.item_name,
            "maturity":      cl.maturity,
            "maturity_score": cl.maturity_score,
            "diagnosis_type": cl.diagnosis_type,
            "tool":          cl.tool,
            "result":        dr.result,
            "score":         dr.score or 0.0,
            "criteria":      cl.criteria or "",
            "recommendation": dr.recommendation or "",
        }
        checklist_results.append(item)
        if dr.result in ("미충족", "부분충족"):
            fail_items.append(item)

    # 개선권고 (check_id 기준으로 조회)
    fail_check_ids = [
        dr.check_id for dr, _ in results
        if dr.result in ("미충족", "부분충족")
    ]
    guide_rows = db.query(ImprovementGuide).filter(
        ImprovementGuide.check_id.in_(fail_check_ids)
    ).order_by(ImprovementGuide.priority, ImprovementGuide.term).all() if fail_check_ids else []

    improvements = [
        {
            "pillar":   g.pillar,
            "task":     g.task,
            "priority": g.priority,
            "term":     g.term,
            "tool":     g.recommended_tool or "",
            "solution": _first_step(g.steps),
        }
        for g in guide_rows
    ]

    total = len(checklist_results)
    pass_cnt    = sum(1 for r in checklist_results if r["result"] == "충족")
    partial_cnt = sum(1 for r in checklist_results if r["result"] == "부분충족")
    fail_cnt    = sum(1 for r in checklist_results if r["result"] == "미충족")
    na_cnt      = sum(1 for r in checklist_results if r["result"] == "평가불가")
    overall_score = session.total_score or 0.0
    overall_level = session.level or determine_maturity_level(overall_score)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "session": {
            "session_id":   session.session_id,
            "org":          org.name if org else "",
            "manager":      user.name if user else "",
            "started_at":   session.started_at.isoformat() if session.started_at else "",
            "completed_at": session.completed_at.isoformat() if session.completed_at else "",
            "status":       session.status,
        },
        "summary": {
            "overall_score": round(overall_score, 3),
            "overall_level": overall_level,
            "total_items":   total,
            "pass_cnt":      pass_cnt,
            "partial_cnt":   partial_cnt,
            "fail_cnt":      fail_cnt,
            "na_cnt":        na_cnt,
            "pass_rate":     round(pass_cnt / total, 3) if total > 0 else 0.0,
        },
        "pillar_scores":      pillar_scores,
        "checklist_results":  checklist_results,
        "improvement_targets": fail_items,
        "improvements":       improvements,
        # SKT 가이드 §3 §4 §7 §9 — PDF 표지에 표기할 평가 메타
        "evaluation_meta":    build_evaluation_meta(session),
    }


# ── PDF 생성 ────────────────────────────────────────────────────────────────

def _make_pdf(data: dict) -> bytes:
    _ensure_font()
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak,
    )
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics import renderPDF

    F = _FONT_NAME

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    W = A4[0] - 4*cm  # usable width

    def sty(name, **kw) -> ParagraphStyle:
        return ParagraphStyle(name, fontName=F, **kw)

    h1    = sty("h1",    fontSize=22, leading=28, textColor=colors.HexColor("#1e3a5f"), spaceAfter=6)
    h2    = sty("h2",    fontSize=14, leading=18, textColor=colors.HexColor("#1e3a5f"), spaceAfter=4)
    h3    = sty("h3",    fontSize=11, leading=14, textColor=colors.HexColor("#374151"), spaceAfter=3)
    body  = sty("body",  fontSize=9,  leading=13, textColor=colors.HexColor("#374151"))
    small = sty("small", fontSize=8,  leading=11, textColor=colors.HexColor("#6b7280"))
    cover_score = sty("cover_score", fontSize=48, leading=56, textColor=colors.HexColor("#2563eb"))

    RESULT_COLOR = {
        "충족":    colors.HexColor("#16a34a"),
        "부분충족": colors.HexColor("#d97706"),
        "미충족":  colors.HexColor("#dc2626"),
        "평가불가": colors.HexColor("#9ca3af"),
    }
    PRIORITY_COLOR = {
        "Critical": colors.HexColor("#dc2626"),
        "High":     colors.HexColor("#ea580c"),
        "Medium":   colors.HexColor("#ca8a04"),
        "Low":      colors.HexColor("#6b7280"),
    }
    TERM_COLOR = {
        "단기": colors.HexColor("#ef4444"),
        "중기": colors.HexColor("#f59e0b"),
        "장기": colors.HexColor("#3b82f6"),
    }

    s   = data["session"]
    sm  = data["summary"]
    ps  = data["pillar_scores"]
    cr  = data["checklist_results"]
    imps = data["improvements"]
    gen  = data["generated_at"][:10]
    em  = data.get("evaluation_meta") or {}

    story = []

    # ── 1. 표지 ──────────────────────────────────────────────────────────────
    story += [
        Spacer(1, 1.5*cm),
        Paragraph("제로트러스트 보안 진단 보고서", h1),
        Paragraph("Zero Trust Security Assessment Report", sty("sub", fontSize=11, leading=14, textColor=colors.HexColor("#6b7280"))),
        Spacer(1, 0.8*cm),
        HRFlowable(width=W, thickness=2, color=colors.HexColor("#2563eb"), spaceAfter=20),
    ]

    # ── 평가 메타 표기 ─────────────────────────────────────────────────────────
    # SKT 가이드 §3 §4 §7 §9 — 보고서 첫 장에 평가 기준 시점·범위·승인기록 고정.
    scan_mode_label = {"demo": "데모 (외부 시스템 미접근)", "live": "실 스캔 (외부 시스템 접근)"}.get(
        em.get("scan_mode") or "demo", em.get("scan_mode") or "demo"
    )
    sel_tools = em.get("selected_tools") or []
    exc_tools = em.get("excluded_tools") or []
    profile   = em.get("profile_select") or {}
    targets   = em.get("scan_targets") or {}
    consent   = em.get("scan_consent") or {}

    def _join(items):
        return ", ".join(items) if items else "(없음)"

    def _kv(key, value):
        return [key, value if value else "(미입력)"]

    cover_info = [
        ["진단 대상",  s["org"]],
        ["담당자",     s["manager"]],
        ["진단 시작",  s["started_at"][:10] if s["started_at"] else "-"],
        ["진단 완료",  s["completed_at"][:10] if s["completed_at"] else "-"],
        ["보고서 생성", gen],
        ["진단 모드",  scan_mode_label],
        ["사용 환경",  f"IdP: {profile.get('idp_type') or 'none'}  /  SIEM: {profile.get('siem_type') or 'none'}"],
        ["수행 도구",  _join(sel_tools)],
        ["제외 도구",  _join(exc_tools)],
    ]
    if targets:
        target_lines = []
        if targets.get("nmap"):  target_lines.append(f"Nmap: {targets['nmap']}")
        if targets.get("trivy"): target_lines.append(f"Trivy: {targets['trivy']}")
        if target_lines:
            cover_info.append(["스캔 대상", " · ".join(target_lines)])

    story.append(Table(
        cover_info,
        colWidths=[4*cm, W - 4*cm],
        style=TableStyle([
            ("FONTNAME",   (0,0), (-1,-1), F),
            ("FONTSIZE",   (0,0), (-1,-1), 10),
            ("TEXTCOLOR",  (0,0), (0,-1), colors.HexColor("#6b7280")),
            ("TEXTCOLOR",  (1,0), (1,-1), colors.HexColor("#111827")),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ]),
    ))

    # 외부 스캔 승인 기록 — 실 스캔이고 승인 메타가 있을 때만 별도 카드.
    if em.get("scan_mode") == "live" and consent:
        story += [Spacer(1, 0.5*cm)]
        story.append(Paragraph("외부 스캔 승인 기록", h3))
        consent_rows = [
            _kv("승인자",       consent.get("approver")),
            _kv("시간대",       consent.get("scheduled_window")),
            _kv("강도",         consent.get("intensity")),
            _kv("제외 경로",    consent.get("exclude_paths")),
            _kv("비상 연락처", consent.get("emergency_contact")),
        ]
        story.append(Table(
            consent_rows,
            colWidths=[3.2*cm, W - 3.2*cm],
            style=TableStyle([
                ("FONTNAME",      (0,0), (-1,-1), F),
                ("FONTSIZE",      (0,0), (-1,-1), 9),
                ("TEXTCOLOR",     (0,0), (0,-1), colors.HexColor("#6b7280")),
                ("TEXTCOLOR",     (1,0), (1,-1), colors.HexColor("#111827")),
                ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#fef9c3")),
                ("BOX",           (0,0), (-1,-1), 0.5, colors.HexColor("#facc15")),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("TOPPADDING",    (0,0), (-1,-1), 5),
                ("LEFTPADDING",   (0,0), (-1,-1), 8),
                ("RIGHTPADDING",  (0,0), (-1,-1), 8),
            ]),
        ))

    # SKT 가이드 §3 평가 착수 전 확정사항 — 4종 카드
    eval_ver  = em.get("evaluation_version") or {}
    scope_as  = em.get("evaluation_scope_assets") or []
    data_cls  = em.get("data_classifications") or []
    reviewers = em.get("reviewers") or {}

    if eval_ver:
        story += [Spacer(1, 0.4*cm)]
        story.append(Paragraph("평가 대상 버전", h3))
        ver_rows = [
            _kv("버전 라벨",          eval_ver.get("version_label")),
            _kv("Git commit",         eval_ver.get("git_commit")),
            _kv("Frontend deployment", eval_ver.get("frontend_deployment")),
            _kv("Backend deployment",  eval_ver.get("backend_deployment")),
        ]
        # 빈 값 행 제거
        ver_rows = [r for r in ver_rows if r[1] and r[1] != "(미입력)"]
        if ver_rows:
            story.append(Table(
                ver_rows, colWidths=[4*cm, W - 4*cm],
                style=TableStyle([
                    ("FONTNAME",  (0,0), (-1,-1), F),
                    ("FONTSIZE",  (0,0), (-1,-1), 9),
                    ("TEXTCOLOR", (0,0), (0,-1), colors.HexColor("#6b7280")),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ]),
            ))

    if scope_as:
        story += [Spacer(1, 0.3*cm)]
        story.append(Paragraph(f"평가 범위 자산 목록 ({len(scope_as)}건)", h3))
        rows = [["포함", "자산", "값"]]
        for a in scope_as:
            rows.append([
                "✓" if a.get("included") else "—",
                a.get("name", ""),
                a.get("value", ""),
            ])
        story.append(Table(
            rows, colWidths=[1.2*cm, 4*cm, W - 5.2*cm],
            style=TableStyle([
                ("FONTNAME",   (0,0), (-1,-1), F),
                ("FONTSIZE",   (0,0), (-1,-1), 8),
                ("BACKGROUND", (0,0), (-1,0),  colors.HexColor("#334155")),
                ("TEXTCOLOR",  (0,0), (-1,0),  colors.white),
                ("ALIGN",      (0,0), (0,-1),  "CENTER"),
                ("BOX",        (0,0), (-1,-1), 0.4, colors.HexColor("#e5e7eb")),
                ("INNERGRID",  (0,0), (-1,-1), 0.4, colors.HexColor("#e5e7eb")),
                ("TOPPADDING", (0,0), (-1,-1), 3),
                ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ]),
        ))

    if data_cls:
        story += [Spacer(1, 0.3*cm)]
        story.append(Paragraph(f"데이터 등급 분류 ({len(data_cls)}건)", h3))
        rows = [["민감도", "데이터 항목", "보관 위치"]]
        for d in data_cls:
            rows.append([d.get("sensitivity", ""), d.get("name", ""), d.get("storage_location", "")])
        sens_color = {"높음": colors.HexColor("#fee2e2"),
                      "중간": colors.HexColor("#fef9c3"),
                      "낮음": colors.HexColor("#f3f4f6")}
        ts = [
            ("FONTNAME",   (0,0), (-1,-1), F),
            ("FONTSIZE",   (0,0), (-1,-1), 8),
            ("BACKGROUND", (0,0), (-1,0),  colors.HexColor("#334155")),
            ("TEXTCOLOR",  (0,0), (-1,0),  colors.white),
            ("ALIGN",      (0,0), (0,-1),  "CENTER"),
            ("BOX",        (0,0), (-1,-1), 0.4, colors.HexColor("#e5e7eb")),
            ("INNERGRID",  (0,0), (-1,-1), 0.4, colors.HexColor("#e5e7eb")),
            ("TOPPADDING", (0,0), (-1,-1), 3),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3),
        ]
        for ri, d in enumerate(data_cls, start=1):
            sens = d.get("sensitivity", "")
            if sens in sens_color:
                ts.append(("BACKGROUND", (0, ri), (0, ri), sens_color[sens]))
        story.append(Table(
            rows, colWidths=[1.6*cm, 5*cm, W - 6.6*cm],
            style=TableStyle(ts),
        ))

    if reviewers:
        story += [Spacer(1, 0.3*cm)]
        story.append(Paragraph("판정자", h3))
        rv_rows = [
            _kv("App owner",       reviewers.get("app_owner")),
            _kv("Backend owner",   reviewers.get("backend_owner")),
            _kv("Cloud owner",     reviewers.get("cloud_owner")),
            _kv("Security reviewer", reviewers.get("security_reviewer")),
        ]
        rv_rows = [r for r in rv_rows if r[1] and r[1] != "(미입력)"]
        if rv_rows:
            story.append(Table(
                rv_rows, colWidths=[4*cm, W - 4*cm],
                style=TableStyle([
                    ("FONTNAME",      (0,0), (-1,-1), F),
                    ("FONTSIZE",      (0,0), (-1,-1), 9),
                    ("TEXTCOLOR",     (0,0), (0,-1), colors.HexColor("#6b7280")),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ]),
            ))

    story += [Spacer(1, 1.2*cm)]

    story.append(Paragraph(f"{sm['overall_score']:.2f} / 4.0", cover_score))
    story.append(Paragraph(f"종합 성숙도 등급: {sm['overall_level']}", h2))
    story += [Spacer(1, 0.6*cm)]

    score_bar_data = [
        [f"충족 {sm['pass_cnt']}건", f"부분충족 {sm['partial_cnt']}건",
         f"미충족 {sm['fail_cnt']}건", f"해당없음 {sm['na_cnt']}건"],
    ]
    story.append(Table(
        score_bar_data,
        colWidths=[W/4]*4,
        style=TableStyle([
            ("FONTNAME",    (0,0), (-1,-1), F),
            ("FONTSIZE",    (0,0), (-1,-1), 9),
            ("ALIGN",       (0,0), (-1,-1), "CENTER"),
            ("BACKGROUND",  (0,0), (0,0), colors.HexColor("#dcfce7")),
            ("BACKGROUND",  (1,0), (1,0), colors.HexColor("#fef3c7")),
            ("BACKGROUND",  (2,0), (2,0), colors.HexColor("#fee2e2")),
            ("BACKGROUND",  (3,0), (3,0), colors.HexColor("#f3f4f6")),
            ("TEXTCOLOR",   (0,0), (0,0), colors.HexColor("#15803d")),
            ("TEXTCOLOR",   (1,0), (1,0), colors.HexColor("#92400e")),
            ("TEXTCOLOR",   (2,0), (2,0), colors.HexColor("#b91c1c")),
            ("TEXTCOLOR",   (3,0), (3,0), colors.HexColor("#6b7280")),
            ("BOX",         (0,0), (-1,-1), 0.5, colors.HexColor("#e5e7eb")),
            ("INNERGRID",   (0,0), (-1,-1), 0.5, colors.HexColor("#e5e7eb")),
            ("TOPPADDING",  (0,0), (-1,-1), 8),
            ("BOTTOMPADDING",(0,0),(-1,-1), 8),
        ]),
    ))
    story.append(PageBreak())

    # ── 2. 필러별 점수 요약 ───────────────────────────────────────────────────
    story += [Paragraph("필러별 성숙도 점수", h2), Spacer(1, 0.3*cm)]

    if ps:
        # 막대 그래프 (Drawing)
        bar_h, bar_gap = 20, 8
        chart_h = len(ps) * (bar_h + bar_gap) + 20
        d = Drawing(W, chart_h)
        max_w = W - 5*cm
        for i, p in enumerate(ps):
            y = chart_h - (i + 1) * (bar_h + bar_gap) + bar_gap
            bar_len = (p["score"] / 4.0) * max_w
            # 배경 바
            d.add(Rect(4.5*cm, y, max_w, bar_h, fillColor=colors.HexColor("#f3f4f6"), strokeColor=None))
            # 점수 바
            bar_col = (
                colors.HexColor("#16a34a") if p["score"] >= 3.5 else
                colors.HexColor("#2563eb") if p["score"] >= 2.5 else
                colors.HexColor("#f59e0b") if p["score"] >= 1.5 else
                colors.HexColor("#ef4444")
            )
            d.add(Rect(4.5*cm, y, bar_len, bar_h, fillColor=bar_col, strokeColor=None))
            # 라벨
            d.add(String(0, y + bar_h/2 - 4, p["pillar"][:6], fontName=F, fontSize=8, fillColor=colors.HexColor("#374151")))
            d.add(String(4.5*cm + bar_len + 4, y + bar_h/2 - 4,
                         f"{p['score']:.2f} ({p['level']})", fontName=F, fontSize=8,
                         fillColor=colors.HexColor("#374151")))
        story.append(d)
        story.append(Spacer(1, 0.4*cm))

        # 점수 상세 테이블 (충족/실패(미충족+부분충족)/평가불가)
        hdr = ["필러", "점수", "등급", "충족", "실패", "평가불가"]
        rows = [hdr] + [
            [p["pillar"], f"{p['score']:.2f}", p["level"],
             str(p["pass_cnt"]), str(p["fail_cnt"]), str(p["na_cnt"])]
            for p in ps
        ]
        col_w = [W - 5*(1.5*cm)] + [1.5*cm]*5
        story.append(Table(rows, colWidths=col_w, style=TableStyle([
            ("FONTNAME",      (0,0), (-1,-1), F),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
            ("ALIGN",         (1,0), (-1,-1), "CENTER"),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
            ("BOX",           (0,0), (-1,-1), 0.5, colors.HexColor("#e5e7eb")),
            ("INNERGRID",     (0,0), (-1,-1), 0.5, colors.HexColor("#e5e7eb")),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ])))
    story.append(PageBreak())

    # ── 3. 체크리스트 세부 항목 (필러별) ──────────────────────────────────────
    story += [Paragraph("체크리스트 세부 항목", h2), Spacer(1, 0.2*cm)]

    by_pillar: dict[str, list] = {}
    for item in cr:
        by_pillar.setdefault(item["pillar"], []).append(item)

    for pillar, items in by_pillar.items():
        story += [Paragraph(pillar, h3), Spacer(1, 0.1*cm)]
        hdr = ["항목ID", "항목명", "성숙도", "진단유형", "결과", "점수"]
        rows = [hdr]
        for it in items:
            rows.append([
                it["item_id"],
                Paragraph(it["item_name"], sty("cell", fontSize=7, leading=9)),
                it["maturity"],
                it["diagnosis_type"],
                it["result"],
                f"{it['score']:.2f}",
            ])
        col_w = [2.2*cm, W - 2.2*cm - 1.8*cm - 1.6*cm - 1.6*cm - 1.2*cm, 1.8*cm, 1.6*cm, 1.6*cm, 1.2*cm]

        def _result_bg(result):
            return {
                "충족": colors.HexColor("#dcfce7"),
                "부분충족": colors.HexColor("#fef9c3"),
                "미충족": colors.HexColor("#fee2e2"),
            }.get(result, colors.white)

        ts = [
            ("FONTNAME",     (0,0), (-1,-1), F),
            ("FONTSIZE",     (0,0), (-1,-1), 7),
            ("BACKGROUND",   (0,0), (-1,0),  colors.HexColor("#334155")),
            ("TEXTCOLOR",    (0,0), (-1,0),  colors.white),
            ("ALIGN",        (2,0), (-1,-1), "CENTER"),
            ("BOX",          (0,0), (-1,-1), 0.4, colors.HexColor("#e5e7eb")),
            ("INNERGRID",    (0,0), (-1,-1), 0.4, colors.HexColor("#e5e7eb")),
            ("TOPPADDING",   (0,0), (-1,-1), 3),
            ("BOTTOMPADDING",(0,0), (-1,-1), 3),
        ]
        for row_i, it in enumerate(items, start=1):
            bg = _result_bg(it["result"])
            ts.append(("BACKGROUND", (4, row_i), (4, row_i), bg))

        story.append(Table(rows, colWidths=col_w, style=TableStyle(ts), repeatRows=1))
        story.append(Spacer(1, 0.3*cm))

    story.append(PageBreak())

    # ── 4. 개선 권고 (SKT 가이드 §8 30/60/90일 로드맵) ─────────────────────
    story += [Paragraph("개선 권고 — 30/60/90일 로드맵", h2), Spacer(1, 0.2*cm)]

    # SKT 가이드 §8 권장 활동 (각 단계별)
    term_label_map = {
        "단기": "단기 (30일 — quick win)",
        "중기": "중기 (60일 — 정착)",
        "장기": "장기 (90일 — 운영)",
    }
    term_guide_map = {
        "단기": (
            "권장 활동: 평가 범위 확정 · 데모/운영 데이터 분리 · 관리자 MFA 강제 · "
            "Vercel·Railway·Supabase·Notion·Drive 권한 목록 정리 · CORS·보안 헤더 검토",
            "완료 증거: 권한 표, 설정 캡처, deployment id, 보안 헤더 diff",
        ),
        "중기": (
            "권장 활동: API 인증/인가 점검 · Supabase RLS 검증 · Drive/Notion 공유 최소화 · "
            "secret rotation · dependency/Trivy 스캔 정례화",
            "완료 증거: 테스트 결과, rotation 로그, Trivy/SCA 리포트",
        ),
        "장기": (
            "권장 활동: audit log·보관 기간 정책 확정 · LLM 데이터 처리 정책 문서화 · "
            "incident runbook 작성 · Readyz-T 재평가 수행",
            "완료 증거: 정책 문서, 로그 샘플, 재평가 점수 비교표",
        ),
    }
    guide_box_sty = sty("guide_box", fontSize=7, leading=9, textColor=colors.HexColor("#374151"))

    if not imps:
        story.append(Paragraph("미충족·부분충족 항목에 대한 개선 권고가 없습니다.", body))
    else:
        for term in ["단기", "중기", "장기"]:
            term_items = [t for t in imps if t["term"] == term]
            if not term_items:
                continue
            term_label = term_label_map[term]
            story += [Paragraph(term_label, h3), Spacer(1, 0.1*cm)]
            # 가이드 §8 권장 활동 안내 박스
            guide_act, guide_ev = term_guide_map.get(term, ("", ""))
            if guide_act:
                guide_rows = [[
                    Paragraph(
                        f"<b>권장 활동</b><br/>{guide_act}<br/><font color='#6b7280'>{guide_ev}</font>",
                        guide_box_sty,
                    )
                ]]
                story.append(Table(
                    guide_rows,
                    colWidths=[W],
                    style=TableStyle([
                        ("FONTNAME",      (0,0), (-1,-1), F),
                        ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#f8fafc")),
                        ("BOX",           (0,0), (-1,-1), 0.4, colors.HexColor("#cbd5e1")),
                        ("LEFTPADDING",   (0,0), (-1,-1), 8),
                        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
                        ("TOPPADDING",    (0,0), (-1,-1), 5),
                        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                    ]),
                ))
                story.append(Spacer(1, 0.15*cm))

            hdr = ["필러", "개선 과제", "우선순위", "도구"]
            rows = [hdr]
            for t in term_items:
                rows.append([
                    t["pillar"][:5],
                    Paragraph(t["task"], sty("imp_cell", fontSize=7, leading=10)),
                    t["priority"],
                    t["tool"],
                ])
            col_w = [2.2*cm, W - 2.2*cm - 1.8*cm - 2.0*cm, 1.8*cm, 2.0*cm]

            ts_imp = [
                ("FONTNAME",     (0,0), (-1,-1), F),
                ("FONTSIZE",     (0,0), (-1,-1), 7),
                ("BACKGROUND",   (0,0), (-1,0),  TERM_COLOR[term]),
                ("TEXTCOLOR",    (0,0), (-1,0),  colors.white),
                ("ALIGN",        (2,0), (3,-1),  "CENTER"),
                ("BOX",          (0,0), (-1,-1), 0.4, colors.HexColor("#e5e7eb")),
                ("INNERGRID",    (0,0), (-1,-1), 0.4, colors.HexColor("#e5e7eb")),
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
                ("TOPPADDING",   (0,0), (-1,-1), 4),
                ("BOTTOMPADDING",(0,0), (-1,-1), 4),
                ("VALIGN",       (0,0), (-1,-1), "TOP"),
            ]
            for row_i, t in enumerate(term_items, start=1):
                pc = PRIORITY_COLOR.get(t["priority"], colors.HexColor("#6b7280"))
                ts_imp.append(("TEXTCOLOR", (2, row_i), (2, row_i), pc))

            story.append(Table(rows, colWidths=col_w, style=TableStyle(ts_imp), repeatRows=1))
            story.append(Spacer(1, 0.4*cm))

    # ── 꼬리말 ────────────────────────────────────────────────────────────────
    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(F, 8)
        canvas.setFillColor(colors.HexColor("#9ca3af"))
        canvas.drawString(2*cm, 1.2*cm, f"Readyz-T ZT Assessment Report  |  생성일: {gen}")
        canvas.drawRightString(A4[0] - 2*cm, 1.2*cm, f"Page {doc.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


# ── 라우터 ──────────────────────────────────────────────────────────────────

@router.get("/generate")
async def generate_report_by_query(
    session_id: int,
    fmt: str = Query(default="json", pattern="^(json|pdf)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = db.query(DiagnosisSession).filter(DiagnosisSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    assert_session_access(current_user, session)

    data = _build_data(session_id, db)
    if fmt == "pdf":
        # _make_pdf 는 reportlab CPU-bound — 이벤트 루프 블로킹 방지로 thread pool 위임.
        pdf_bytes = await asyncio.to_thread(_make_pdf, data)
        filename = f"zt-report-{session_id}-{data['generated_at'][:10]}.pdf"
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    return JSONResponse(content={
        "report_generated_at": data["generated_at"],
        "session": data["session"],
        "summary": data["summary"],
        "pillar_scores": data["pillar_scores"],
        "checklist_results": data["checklist_results"],
        "improvement_targets": data["improvement_targets"],
    })


@router.get("/generate/{session_id}")
async def generate_report(
    session_id: int,
    fmt: str = Query(default="json", pattern="^(json|pdf)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await generate_report_by_query(
        session_id=session_id, fmt=fmt, db=db, current_user=current_user,
    )


@router.get("/standards/{session_id}")
def get_standards_mapping(
    session_id: int,
    fmt: str = Query(default="json", pattern="^(json|csv)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """진단 세션의 NIST 800-207 / CIS Controls v8 매핑 export.

    fmt=json → 표준별 충족·미충족 집계 + 세부 매핑
    fmt=csv  → 표준별 1행씩, columns: standard, id, title, pass, fail, na, compliance_rate
    """
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    assert_session_access(current_user, session)

    rows = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(DiagnosisResult.session_id == session_id)
        .all()
    )
    checklist_results = [
        {
            "item_id": cl.item_id, "pillar": cl.pillar, "category": cl.category,
            "item": cl.item_name, "result": dr.result,
        }
        for dr, cl in rows
    ]

    summary = session_standards_summary(checklist_results)

    if fmt == "csv":
        import csv
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["standard", "id", "title", "pass", "fail", "na", "compliance_rate"])
        for n in summary["nist_800_207"]:
            w.writerow(["NIST 800-207", n["tenet"], n["title"], n["pass"], n["fail"], n["na"], n["compliance_rate"]])
        for c in summary["cis_controls_v8"]:
            w.writerow(["CIS Controls v8", c["control_id"], c["title"], c["pass"], c["fail"], c["na"], c["compliance_rate"]])
        return StreamingResponse(
            io.BytesIO(buf.getvalue().encode("utf-8-sig")),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="zt-standards-{session_id}.csv"'},
        )

    return JSONResponse(content={
        "session_id": session_id,
        "nist_800_207": summary["nist_800_207"],
        "cis_controls_v8": summary["cis_controls_v8"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })


# ─── 증적 목록 xlsx (가이드 §7 산출물) ──────────────────────────────────────
# 각 진단 결과에 연결된 Evidence(수동) + CollectedData(자동) 를 한 xlsx 로
# 정리. 컬럼: 항목/Pillar/결과/출처/증적유형/파일/위치/관찰내용/수집시각 등.
# 가이드 §7 산출물 "evidence_register.xlsx" 에 해당.

def _build_evidence_register_xlsx(session_id: int, db: Session) -> bytes:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment

    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    org = db.query(Organization).filter(Organization.org_id == session.org_id).first()
    user = db.query(User).filter(User.user_id == session.user_id).first()

    # 진단 결과 + Checklist join
    results = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(DiagnosisResult.session_id == session_id)
        .all()
    )
    # check_id → DiagnosisResult/Checklist 매핑
    by_check: dict[int, dict] = {}
    for dr, cl in results:
        by_check[cl.check_id] = {"dr": dr, "cl": cl}

    # 같은 세션의 모든 Evidence / CollectedData
    evidences = db.query(Evidence).filter(Evidence.session_id == session_id).all()
    collected = db.query(CollectedData).filter(CollectedData.session_id == session_id).all()
    coll_by_check: dict[int, CollectedData] = {c.check_id: c for c in collected}

    # check_id 별로 evidence 묶기 (없으면 [])
    ev_by_check: dict[int, list[Evidence]] = {}
    for ev in evidences:
        ev_by_check.setdefault(ev.check_id, []).append(ev)

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "증적 목록"

    header_font = Font(name="Arial", size=10, bold=True, color="FFFFFFFF")
    header_fill = PatternFill("solid", fgColor="FF1E3A5F")
    sub_font    = Font(name="Arial", size=9)
    sub_fill_a  = PatternFill("solid", fgColor="FFFFFFFF")
    sub_fill_b  = PatternFill("solid", fgColor="FFF8FAFC")
    result_fill = {
        "충족":      PatternFill("solid", fgColor="FFDCFCE7"),
        "부분충족":  PatternFill("solid", fgColor="FFFEF9C3"),
        "미충족":    PatternFill("solid", fgColor="FFFEE2E2"),
        "평가불가":  PatternFill("solid", fgColor="FFF3F4F6"),
    }
    wrap = Alignment(horizontal="left", vertical="top", wrap_text=True)

    # 헤더 (가이드 §7: 항목별 파일명, 캡처 위치, 담당자, 민감도, 만료 여부)
    headers = [
        "항목ID", "Pillar", "카테고리", "항목명", "성숙도",
        "진단결과", "점수", "출처(자동/수동)", "도구",
        "증적유형", "관찰 내용", "파일명", "파일크기(B)", "MIME",
        "위치/URL", "원인/근거", "영향도", "수집·등록 시각",
    ]
    for col, h in enumerate(headers, start=1):
        c = ws.cell(1, col, h)
        c.font = header_font
        c.fill = header_fill
        c.alignment = Alignment(horizontal="center", vertical="center")

    # 행 폭 설정
    widths = [12, 12, 22, 36, 8, 10, 6, 14, 10, 14, 50, 28, 12, 16, 36, 36, 8, 22]
    for col, w in enumerate(widths, start=1):
        ws.column_dimensions[ws.cell(1, col).column_letter].width = w

    row = 2
    # check_id 순회 — 결과가 있는 항목 우선
    for check_id in sorted(by_check.keys()):
        entry = by_check[check_id]
        cl = entry["cl"]
        dr = entry["dr"]
        evs = ev_by_check.get(check_id, [])
        coll = coll_by_check.get(check_id)
        tool = coll.tool if coll else ""
        source = "수동" if tool == "수동" else ("자동" if tool else "")
        coll_at = coll.collected_at.isoformat() if coll and coll.collected_at else ""

        # 자동 raw_json 요약 (수집된 metric_value/threshold/issues 등)
        auto_obs = ""
        if coll and isinstance(coll.raw_json, dict):
            rj = coll.raw_json
            parts = []
            if "score" in rj:
                parts.append(f"score={rj.get('score')}")
            if "metric_value" in rj or coll.metric_value is not None:
                mv = rj.get("metric_value", coll.metric_value)
                parts.append(f"{coll.metric_key}={mv}/{coll.threshold}")
            if rj.get("issues"):
                parts.append(f"issues={len(rj['issues'])}건")
            auto_obs = " · ".join(parts)

        def _write_row(r, ev: Optional[Evidence]):
            vals = [
                cl.item_id, cl.pillar, cl.category, cl.item_name, cl.maturity,
                dr.result, round(dr.score or 0.0, 2),
                source, tool,
                (ev.source if ev else "자동수집") if (ev or coll) else "",
                (ev.observed if ev and ev.observed else "") or auto_obs,
                ev.original_filename if ev and ev.original_filename else "",
                ev.file_size if ev and ev.file_size else "",
                ev.mime_type if ev and ev.mime_type else "",
                ev.location if ev and ev.location else "",
                ev.reason if ev and ev.reason else "",
                ev.impact if ev and ev.impact is not None else "",
                coll_at,
            ]
            fill_zebra = sub_fill_b if (r % 2 == 0) else sub_fill_a
            for col, v in enumerate(vals, start=1):
                c = ws.cell(r, col, v)
                c.font = sub_font
                c.alignment = wrap
                c.fill = fill_zebra
            # 결과 컬럼만 색깔로 강조
            rcell = ws.cell(r, 6)
            if dr.result in result_fill:
                rcell.fill = result_fill[dr.result]
                rcell.font = Font(name="Arial", size=9, bold=True)

        if evs:
            # 같은 check_id 에 evidence 가 여러 개면 각 evidence 별 한 행씩
            for ev in evs:
                _write_row(row, ev)
                row += 1
        else:
            _write_row(row, None)
            row += 1

    # 메타 정보 시트
    ws_meta = wb.create_sheet("메타")
    ws_meta.column_dimensions["A"].width = 20
    ws_meta.column_dimensions["B"].width = 60
    meta_rows = [
        ("기관",           org.name if org else ""),
        ("담당자",         user.name if user else ""),
        ("세션 ID",        session.session_id),
        ("진단 시작",      session.started_at.isoformat() if session.started_at else ""),
        ("진단 완료",      session.completed_at.isoformat() if session.completed_at else ""),
        ("상태",           session.status),
        ("총 항목 수",     len(by_check)),
        ("증적 파일 수",   sum(1 for ev in evidences if ev.file_path)),
        ("자동 수집 수",   len([c for c in collected if c.tool != "수동"])),
        ("수동 등록 수",   len([c for c in collected if c.tool == "수동"])),
        ("생성 시각",      datetime.now(timezone.utc).isoformat()),
    ]

    # SKT 가이드 §3 평가 착수 전 확정사항 — evidence_register 메타 시트에도 동기화.
    em = build_evaluation_meta(session)
    eval_ver = em.get("evaluation_version") or {}
    scope_as = em.get("evaluation_scope_assets") or []
    data_cls = em.get("data_classifications") or []
    reviewers_m = em.get("reviewers") or {}

    if em.get("scan_mode"):
        meta_rows.append(("진단 모드", em.get("scan_mode")))
    if em.get("selected_tools"):
        meta_rows.append(("수행 도구", ", ".join(em.get("selected_tools"))))
    if em.get("excluded_tools"):
        meta_rows.append(("제외 도구", ", ".join(em.get("excluded_tools"))))
    if eval_ver.get("version_label"):
        meta_rows.append(("버전 라벨", eval_ver["version_label"]))
    if eval_ver.get("git_commit"):
        meta_rows.append(("Git commit", eval_ver["git_commit"]))
    if eval_ver.get("frontend_deployment"):
        meta_rows.append(("Frontend deployment", eval_ver["frontend_deployment"]))
    if eval_ver.get("backend_deployment"):
        meta_rows.append(("Backend deployment", eval_ver["backend_deployment"]))
    if reviewers_m.get("app_owner"):
        meta_rows.append(("App owner", reviewers_m["app_owner"]))
    if reviewers_m.get("backend_owner"):
        meta_rows.append(("Backend owner", reviewers_m["backend_owner"]))
    if reviewers_m.get("cloud_owner"):
        meta_rows.append(("Cloud owner", reviewers_m["cloud_owner"]))
    if reviewers_m.get("security_reviewer"):
        meta_rows.append(("Security reviewer", reviewers_m["security_reviewer"]))

    for r, (k, v) in enumerate(meta_rows, start=1):
        ws_meta.cell(r, 1, k).font = Font(name="Arial", size=10, bold=True, color="FF617087")
        ws_meta.cell(r, 2, str(v) if v is not None else "")

    # SKT 가이드 §3 — 자산 목록 / 데이터 등급은 별도 작은 시트로 분리.
    if scope_as:
        ws_assets = wb.create_sheet("평가 범위 자산")
        ws_assets.column_dimensions["A"].width = 8
        ws_assets.column_dimensions["B"].width = 24
        ws_assets.column_dimensions["C"].width = 60
        ws_assets.cell(1, 1, "포함").font = Font(name="Arial", size=10, bold=True, color="FFFFFFFF")
        ws_assets.cell(1, 2, "자산").font = Font(name="Arial", size=10, bold=True, color="FFFFFFFF")
        ws_assets.cell(1, 3, "값").font = Font(name="Arial", size=10, bold=True, color="FFFFFFFF")
        for c in (ws_assets.cell(1, 1), ws_assets.cell(1, 2), ws_assets.cell(1, 3)):
            c.fill = PatternFill("solid", fgColor="FF1E3A5F")
        for ri, a in enumerate(scope_as, start=2):
            ws_assets.cell(ri, 1, "✓" if a.get("included") else "—")
            ws_assets.cell(ri, 2, a.get("name", ""))
            ws_assets.cell(ri, 3, a.get("value", ""))

    if data_cls:
        ws_data = wb.create_sheet("데이터 등급")
        ws_data.column_dimensions["A"].width = 10
        ws_data.column_dimensions["B"].width = 28
        ws_data.column_dimensions["C"].width = 40
        sens_fill = {"높음": "FFFEE2E2", "중간": "FFFEF9C3", "낮음": "FFF3F4F6"}
        ws_data.cell(1, 1, "민감도").font = Font(name="Arial", size=10, bold=True, color="FFFFFFFF")
        ws_data.cell(1, 2, "데이터 항목").font = Font(name="Arial", size=10, bold=True, color="FFFFFFFF")
        ws_data.cell(1, 3, "보관 위치").font = Font(name="Arial", size=10, bold=True, color="FFFFFFFF")
        for c in (ws_data.cell(1, 1), ws_data.cell(1, 2), ws_data.cell(1, 3)):
            c.fill = PatternFill("solid", fgColor="FF1E3A5F")
        for ri, d in enumerate(data_cls, start=2):
            sens = d.get("sensitivity", "")
            sc = ws_data.cell(ri, 1, sens)
            if sens in sens_fill:
                sc.fill = PatternFill("solid", fgColor=sens_fill[sens])
            ws_data.cell(ri, 2, d.get("name", ""))
            ws_data.cell(ri, 3, d.get("storage_location", ""))

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


@router.get("/evidence-register/{session_id}")
async def download_evidence_register(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """증적 목록 xlsx 다운로드 — 가이드 §7 산출물 "evidence_register.xlsx".

    각 진단 결과에 연결된 자동 수집(CollectedData) + 수동 등록 증적(Evidence)
    을 한 xlsx 로 정리. 컬럼: 항목/결과/출처/증적유형/파일/위치/관찰내용/시각 등.
    """
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    assert_session_access(current_user, session)

    try:
        data = await asyncio.to_thread(_build_evidence_register_xlsx, session_id, db)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("[report] evidence register build failed: %s", exc)
        raise HTTPException(status_code=500, detail="증적 목록 생성에 실패했습니다.")

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename = f"evidence-register-{session_id}-{today}.xlsx"
    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─── 판정 로그 markdown (가이드 §7 산출물 decision_log.md) ──────────────────
# "논쟁 가능 항목의 판단 근거와 리뷰어 의견" — 부분충족/평가불가 항목 중심으로
# 자동수집 metric / Evidence 관찰 내용 / 평가불가 사유 정리.
# 리뷰어 의견 자리는 빈 줄로 두어 사람이 추가 작성하도록.

def _build_decision_log_md(session_id: int, db: Session) -> str:
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    org = db.query(Organization).filter(Organization.org_id == session.org_id).first()
    user = db.query(User).filter(User.user_id == session.user_id).first()

    results = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(DiagnosisResult.session_id == session_id)
        .all()
    )
    evidences = db.query(Evidence).filter(Evidence.session_id == session_id).all()
    collected = db.query(CollectedData).filter(CollectedData.session_id == session_id).all()
    ev_by_check: dict[int, list[Evidence]] = {}
    for ev in evidences:
        ev_by_check.setdefault(ev.check_id, []).append(ev)
    coll_by_check: dict[int, CollectedData] = {c.check_id: c for c in collected}

    # 평가 메타
    eval_meta = build_evaluation_meta(session)

    # 집계
    total = len(results)
    pass_cnt    = sum(1 for dr, _ in results if dr.result == "충족")
    partial_cnt = sum(1 for dr, _ in results if dr.result == "부분충족")
    fail_cnt    = sum(1 for dr, _ in results if dr.result == "미충족")
    na_cnt      = sum(1 for dr, _ in results if dr.result == "평가불가")

    # 논쟁 가능 항목 = 부분충족 + 평가불가 (가이드 §7 의도)
    debate_results = [(dr, cl) for dr, cl in results
                      if dr.result in ("부분충족", "평가불가")]
    # Pillar 순 → item_id 순
    debate_results.sort(key=lambda x: (x[1].pillar or "", x[1].item_id or ""))

    lines: list[str] = []

    # ── 헤더 ──
    lines.append(f"# 판정 로그 — {org.name if org else '(미상)'}")
    lines.append("")
    lines.append(f"> 산출물 패키지 — `decision_log.md`")
    lines.append(f"> 논쟁 가능 항목(부분충족·평가불가)의 판단 근거와 리뷰어 의견을 기록합니다.")
    lines.append("")
    lines.append("## 1. 기본 정보")
    lines.append("")
    lines.append(f"- **세션 ID**: {session.session_id}")
    lines.append(f"- **담당자**: {user.name if user else '(미상)'}")
    lines.append(f"- **진단 시작**: {session.started_at.isoformat() if session.started_at else '-'}")
    lines.append(f"- **진단 완료**: {session.completed_at.isoformat() if session.completed_at else '-'}")
    lines.append(f"- **상태**: {session.status}")
    lines.append(f"- **생성 시각**: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")

    # ── 평가 메타 ──
    lines.append("## 2. 평가 범위 / 모드")
    lines.append("")
    lines.append(f"- **진단 모드**: {eval_meta.get('scan_mode', 'demo')}")
    lines.append(f"- **사용 환경**: IdP={eval_meta.get('profile_select', {}).get('idp_type', 'none')} / "
                 f"SIEM={eval_meta.get('profile_select', {}).get('siem_type', 'none')}")
    lines.append(f"- **수행 도구**: {', '.join(eval_meta.get('selected_tools') or ['(없음)'])}")
    lines.append(f"- **제외 도구**: {', '.join(eval_meta.get('excluded_tools') or ['(없음)'])}")
    tgt = eval_meta.get("scan_targets") or {}
    if tgt:
        lines.append(f"- **스캔 대상**: " + " · ".join(f"{k}={v}" for k, v in tgt.items()))
    consent = eval_meta.get("scan_consent") or {}
    if consent:
        lines.append(f"- **승인자**: {consent.get('approver', '(미입력)')}")
        lines.append(f"- **시간대**: {consent.get('scheduled_window', '(미입력)')}")
        lines.append(f"- **강도**: {consent.get('intensity', '(미입력)')}")
        lines.append(f"- **비상 연락처**: {consent.get('emergency_contact', '(미입력)')}")
    lines.append("")

    # SKT 가이드 §3 평가 착수 전 확정사항 4종
    eval_ver  = eval_meta.get("evaluation_version") or {}
    scope_as  = eval_meta.get("evaluation_scope_assets") or []
    data_cls  = eval_meta.get("data_classifications") or []
    reviewers = eval_meta.get("reviewers") or {}

    if eval_ver:
        lines.append("### 2.1 평가 대상 버전")
        lines.append("")
        if eval_ver.get("version_label"):
            lines.append(f"- **버전 라벨**: {eval_ver['version_label']}")
        if eval_ver.get("git_commit"):
            lines.append(f"- **Git commit**: `{eval_ver['git_commit']}`")
        if eval_ver.get("frontend_deployment"):
            lines.append(f"- **Frontend deployment**: {eval_ver['frontend_deployment']}")
        if eval_ver.get("backend_deployment"):
            lines.append(f"- **Backend deployment**: {eval_ver['backend_deployment']}")
        lines.append("")

    if scope_as:
        lines.append(f"### 2.2 평가 범위 자산 목록 ({len(scope_as)}건)")
        lines.append("")
        lines.append("| 포함 | 자산 | 값 |")
        lines.append("|---|---|---|")
        for a in scope_as:
            tag = "✓" if a.get("included") else "—"
            name = (a.get("name") or "").replace("|", "\\|")
            value = (a.get("value") or "").replace("|", "\\|")
            lines.append(f"| {tag} | {name} | `{value}` |")
        lines.append("")

    if data_cls:
        lines.append(f"### 2.3 데이터 등급 분류 ({len(data_cls)}건)")
        lines.append("")
        lines.append("| 민감도 | 데이터 항목 | 보관 위치 |")
        lines.append("|---|---|---|")
        for d in data_cls:
            name = (d.get("name") or "").replace("|", "\\|")
            loc = (d.get("storage_location") or "").replace("|", "\\|")
            lines.append(f"| {d.get('sensitivity', '')} | {name} | {loc} |")
        lines.append("")

    # ── 종합 결과 ──
    lines.append("## 3. 종합 결과")
    lines.append("")
    lines.append(f"- **총 항목**: {total}")
    lines.append(f"- **충족**: {pass_cnt}건 / **부분충족**: {partial_cnt}건 / "
                 f"**미충족**: {fail_cnt}건 / **평가불가**: {na_cnt}건")
    lines.append(f"- **종합 점수**: {round(session.total_score or 0.0, 2)} / 4.0  "
                 f"(레벨: {session.level or '-'})")
    lines.append("")

    # ── 논쟁 가능 항목 ──
    lines.append(f"## 4. 논쟁 가능 항목 ({len(debate_results)}건)")
    lines.append("")
    lines.append("> 자동 수집된 metric / Evidence 관찰 내용 / 평가불가 사유를 정리합니다.  ")
    lines.append("> *리뷰어 의견* 칸은 비어 있으니, 검토 후 직접 작성해주세요.")
    lines.append("")

    if not debate_results:
        lines.append("(논쟁 가능 항목 없음 — 모든 항목이 충족 또는 미충족으로 명확히 판정)")
        lines.append("")
    else:
        current_pillar = None
        for dr, cl in debate_results:
            pillar = cl.pillar or "(Pillar 미상)"
            if pillar != current_pillar:
                lines.append(f"### {pillar}")
                lines.append("")
                current_pillar = pillar

            coll = coll_by_check.get(cl.check_id)
            evs = ev_by_check.get(cl.check_id, [])

            # 판정 근거 빌드
            basis_lines: list[str] = []
            if coll:
                rj = coll.raw_json if isinstance(coll.raw_json, dict) else {}
                tool = coll.tool or "-"
                basis_lines.append(f"- **출처**: {'수동' if tool == '수동' else '자동'} ({tool})")
                if coll.metric_key:
                    basis_lines.append(
                        f"- **지표**: `{coll.metric_key}` = {coll.metric_value} (threshold {coll.threshold})"
                    )
                if coll.error:
                    basis_lines.append(f"- **오류**: {coll.error}")
                if rj.get("reason_code"):
                    basis_lines.append(
                        f"- **평가불가 사유**: `{rj.get('reason_code')}` — {rj.get('reason_label', '')}"
                    )
                if rj.get("issues"):
                    basis_lines.append(f"- **발견 이슈** ({len(rj['issues'])}건):")
                    for issue in rj["issues"][:5]:
                        basis_lines.append(f"  - {issue}")
                if rj.get("security_headers"):
                    sh = rj["security_headers"]
                    if isinstance(sh, dict) and sh.get("score") is not None:
                        basis_lines.append(
                            f"- **보안 헤더 종합**: {sh['score']:.2f}/1.0"
                        )

            for ev in evs:
                if ev.observed:
                    basis_lines.append(f"- **관찰 내용**: {ev.observed[:300]}")
                if ev.reason:
                    basis_lines.append(f"- **원인/근거**: {ev.reason[:300]}")
                if ev.original_filename:
                    basis_lines.append(f"- **증적 파일**: {ev.original_filename} ({ev.file_size or 0}B)")

            if not basis_lines:
                basis_lines.append("- (판정 근거 데이터 없음)")

            # 추천
            rec = (dr.recommendation or "").strip()

            lines.append(f"#### {cl.item_id} — {cl.item_name or '(항목명 미상)'} _({cl.maturity})_")
            lines.append("")
            lines.append(f"**결과**: `{dr.result}` (점수 {round(dr.score or 0.0, 2)})")
            lines.append("")
            lines.append("**판정 근거**:")
            lines.append("")
            for bl in basis_lines:
                lines.append(bl)
            lines.append("")
            if rec:
                lines.append(f"**권고**: {rec}")
                lines.append("")
            lines.append("**리뷰어 의견**:")
            lines.append("")
            lines.append("> _(여기에 검토 의견을 작성해주세요)_")
            lines.append("")
            lines.append("---")
            lines.append("")

    # ── 미사용 도구 (제외 사유) ──
    excluded = eval_meta.get("excluded_tools") or []
    if excluded:
        lines.append("## 5. 미사용 도구 (수행하지 않은 자동 진단)")
        lines.append("")
        for t in excluded:
            lines.append(f"- **{t}** — 사용자 환경 미선택 또는 비활성. 해당 도구 매핑 항목은 수동 진단으로 폴백됨.")
        lines.append("")

    # ── 리뷰어 ──
    lines.append("## 6. 리뷰어 서명")
    lines.append("")
    lines.append("> 수동 항목은 최소 2인 리뷰.")
    lines.append("")
    lines.append("| 역할 | 이름 | 검토 일자 | 서명 |")
    lines.append("|---|---|---|---|")
    lines.append(f"| App owner | {reviewers.get('app_owner', '')} |  |  |")
    lines.append(f"| Backend owner | {reviewers.get('backend_owner', '')} |  |  |")
    lines.append(f"| Cloud owner | {reviewers.get('cloud_owner', '')} |  |  |")
    lines.append(f"| Security reviewer | {reviewers.get('security_reviewer', '')} |  |  |")
    lines.append("")

    return "\n".join(lines)


@router.get("/decision-log/{session_id}")
async def download_decision_log(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """판정 로그 markdown 다운로드 — 가이드 §7 산출물 decision_log.md.

    부분충족·평가불가 항목의 판정 근거 + 리뷰어 의견(빈 칸) 정리.
    """
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    assert_session_access(current_user, session)

    try:
        text = await asyncio.to_thread(_build_decision_log_md, session_id, db)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("[report] decision log build failed: %s", exc)
        raise HTTPException(status_code=500, detail="판정 로그 생성에 실패했습니다.")

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename = f"decision-log-{session_id}-{today}.md"
    return StreamingResponse(
        io.BytesIO(text.encode("utf-8")),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
