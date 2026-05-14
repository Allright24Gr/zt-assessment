from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import io
import os

from database import get_db
from models import (
    DiagnosisSession, DiagnosisResult, MaturityScore,
    Checklist, Organization, User, ImprovementGuide,
)
from scoring.engine import determine_maturity_level

router = APIRouter()

# ── 한글 폰트 등록 (NanumGothic, Dockerfile에서 fonts-nanum 설치) ──────────
_FONT_REGISTERED = False
_FONT_NAME = "Helvetica"  # fallback

def _ensure_font():
    global _FONT_REGISTERED, _FONT_NAME
    if _FONT_REGISTERED:
        return
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont

        candidates = [
            "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
            "/usr/share/fonts/nanum/NanumGothic.ttf",
        ]
        for path in candidates:
            if os.path.exists(path):
                pdfmetrics.registerFont(TTFont("NanumGothic", path))
                _FONT_NAME = "NanumGothic"
                break
    except Exception:
        pass
    _FONT_REGISTERED = True


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
            "solution": g.steps[0] if g.steps else "",
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

    story = []

    # ── 1. 표지 ──────────────────────────────────────────────────────────────
    story += [
        Spacer(1, 1.5*cm),
        Paragraph("제로트러스트 보안 진단 보고서", h1),
        Paragraph("Zero Trust Security Assessment Report", sty("sub", fontSize=11, leading=14, textColor=colors.HexColor("#6b7280"))),
        Spacer(1, 0.8*cm),
        HRFlowable(width=W, thickness=2, color=colors.HexColor("#2563eb"), spaceAfter=20),
    ]

    cover_info = [
        ["진단 대상",  s["org"]],
        ["담당자",     s["manager"]],
        ["진단 시작",  s["started_at"][:10] if s["started_at"] else "-"],
        ["진단 완료",  s["completed_at"][:10] if s["completed_at"] else "-"],
        ["보고서 생성", gen],
    ]
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

    # ── 4. 개선 권고 ──────────────────────────────────────────────────────────
    story += [Paragraph("개선 권고", h2), Spacer(1, 0.2*cm)]

    if not imps:
        story.append(Paragraph("미충족·부분충족 항목에 대한 개선 권고가 없습니다.", body))
    else:
        for term in ["단기", "중기", "장기"]:
            term_items = [t for t in imps if t["term"] == term]
            if not term_items:
                continue
            term_label = {"단기": "단기 (0–6개월)", "중기": "중기 (6–18개월)", "장기": "장기 (18개월+)"}[term]
            story += [Paragraph(term_label, h3), Spacer(1, 0.1*cm)]

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
def generate_report_by_query(
    session_id: int,
    fmt: str = Query(default="json", pattern="^(json|pdf)$"),
    db: Session = Depends(get_db),
):
    data = _build_data(session_id, db)
    if fmt == "pdf":
        pdf_bytes = _make_pdf(data)
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
def generate_report(
    session_id: int,
    fmt: str = Query(default="json", pattern="^(json|pdf)$"),
    db: Session = Depends(get_db),
):
    return generate_report_by_query(session_id=session_id, fmt=fmt, db=db)
