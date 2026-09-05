"""Stage 5 report generation (spec Section 9, P3-T4 + P3-T5)."""

import pypdf
import pytest

from reporting import aggregate, render


def test_executive_pdf_produced_for_three_sessions(sessions, weak_session, tmp_path):
    """Spec done-criteria: 3 sessions with findings -> 1-2 page PDF with score
    and top 3 findings."""
    three = sessions + [weak_session]
    pdf = render.write_executive_pdf(three, tmp_path / "exec.pdf", capture_name="lab.pcap")

    assert pdf.read_bytes().startswith(b"%PDF")
    pages = len(pypdf.PdfReader(str(pdf)).pages)
    assert 1 <= pages <= 2, f"executive report must be 1-2 pages, got {pages}"


def test_executive_html_shows_score_and_top_findings(sessions):
    html = render.render_executive_html(sessions, capture_name="lab.pcap")
    summary = aggregate.summarise(sessions)

    assert str(summary["posture_score"]) in html
    assert "lab.pcap" in html
    # Top findings are rendered with their plain-English gloss, not raw rule text.
    for entry in summary["top_findings"]:
        assert entry["finding"].description in html
    assert len(summary["top_findings"]) <= 3


def test_executive_states_ml_limits(sessions):
    """CLAUDE.md requires honest ML reporting in anything shown to judges."""
    html = render.render_executive_html(sessions)
    assert "probabilistic" in html.lower()
    assert "indicative" in html.lower()


def test_clean_fleet_reports_no_findings(clean_session):
    html = render.render_executive_html([clean_session])
    assert "No security findings" in html
    assert "100" in html


def test_technical_html_has_full_decode_cve_links_and_diffs(sessions, weak_session):
    html = render.render_technical_html(sessions)

    # every IKE field appears in the decode table
    for field in weak_session.ike.model_dump():
        assert field in html
    # CVE links resolve to NVD
    assert "https://nvd.nist.gov/vuln/detail/CVE-2016-2183" in html
    # standards link out
    assert "rfc-editor.org/rfc/rfc8247" in html
    # vendor config diff is present in a monospace block
    assert "crypto ikev2 policy" in html
    assert "<pre>" in html


def test_technical_lists_every_session_and_finding(sessions):
    html = render.render_technical_html(sessions)
    for session in sessions:
        assert session.session_id in html
        for finding in session.security_assessment.findings:
            assert finding.rule_id in html


def test_technical_pdf_renders(sessions, tmp_path):
    pdf = render.write_technical_pdf(sessions, tmp_path / "tech.pdf")
    assert pdf.read_bytes().startswith(b"%PDF")
    assert len(pypdf.PdfReader(str(pdf)).pages) >= 1


def test_technical_html_written_to_disk(sessions, tmp_path):
    out = render.write_technical_html(sessions, tmp_path / "tech.html")
    assert out.read_text().lstrip().startswith("<html")


def test_technical_handles_absent_confusion_matrix(sessions, monkeypatch, tmp_path):
    """Stage 4b is owned by Block A and may not be trained yet; the report must
    say so rather than crash or silently imply a model exists."""
    monkeypatch.setattr(render, "CONFUSION_MATRIX_PATH", tmp_path / "missing.json")
    html = render.render_technical_html(sessions)
    assert "has not been trained yet" in html


def test_technical_embeds_confusion_matrix_when_present(sessions, monkeypatch, tmp_path):
    matrix = tmp_path / "confusion_matrix.json"
    matrix.write_text(
        '{"labels": ["VoIP", "Web"], "matrix": [[8, 2], [1, 9]], '
        '"accuracy": 0.85, "model_version": "rf-v1"}'
    )
    monkeypatch.setattr(render, "CONFUSION_MATRIX_PATH", matrix)
    html = render.render_technical_html(sessions)
    assert "85.0%" in html
    assert "has not been trained yet" not in html


def test_technical_discloses_lab_clean_and_chat_substitution(sessions):
    """Both callouts are mandated by CLAUDE.md."""
    html = render.render_technical_html(sessions)
    assert "lab-clean" in html
    assert "Chat" in html and "approximated" in html


def test_templates_reject_undefined_variables(sessions):
    """StrictUndefined is on, so a template typo fails loudly instead of
    rendering an empty string into a security report."""
    from jinja2 import StrictUndefined

    assert render._env().undefined is StrictUndefined


def test_html_is_escaped_against_injected_session_data(clean_session):
    """Session fields come from parsed packets -- untrusted input."""
    clean_session.ike.vendor = "<script>alert(1)</script>"
    html = render.render_technical_html([clean_session])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


@pytest.mark.parametrize("count", [0, 1])
def test_reports_render_for_degenerate_fleets(sessions, count, tmp_path):
    subset = sessions[:count]
    assert render.write_executive_pdf(subset, tmp_path / f"e{count}.pdf").exists()
    assert render.render_technical_html(subset)


def test_stylesheet_is_not_html_escaped(sessions):
    """Regression: autoescape is on for untrusted session fields, but escaping
    the injected stylesheet mangles every quoted CSS value -- font stacks and
    the @page footer -- silently downgrading the PDF to Times New Roman."""
    html = render.render_executive_html(sessions)
    assert "&#34;" not in html.split("</style>")[0]
    assert '"Helvetica Neue"' in html


def test_pdf_embeds_the_requested_sans_font(sessions, tmp_path):
    import pypdf

    pdf = render.write_executive_pdf(sessions, tmp_path / "font.pdf")
    fonts = set()
    for page in pypdf.PdfReader(str(pdf)).pages:
        for ref in page.get("/Resources", {}).get("/Font", {}).values():
            fonts.add(str(ref.get_object().get("/BaseFont")))
    assert not any("Times" in f for f in fonts), f"fell back to a serif face: {fonts}"
