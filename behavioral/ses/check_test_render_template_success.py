"""test-render-template-success."""
from __future__ import annotations

import email

from behavioral_harness import tags


CHECK = "test-render-template-success"
GROUP = 'templates'
SERVICES = ['ses']

# TestRenderTemplate returns "the complete MIME message", so the result is parsed as one rather
# than substring-matched against the template parts.


def _mime(rendered: str):
    """Parse a TestRenderTemplate result as the MIME message it actually is."""
    msg = email.message_from_string(rendered)
    assert msg.defects == [], f"the rendered template is not a well-formed MIME message: {msg.defects!r}"
    return msg


def _part_text(part) -> str:
    raw = part.get_payload(decode=True)
    assert raw is not None, f"part {part.get_content_type()!r} carries no decodable payload"
    return raw.decode(part.get_content_charset() or "utf-8")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestRenderTemplate substitutes TemplateData and returns a MIME message with a rendered Subject,
    MIME-Version, and a multipart/alternative body with text/plain before text/html."""
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-behav-tmpl-render-")
    ses.create_template(
        Template={
            "TemplateName": name,
            "SubjectPart": "Hello {{name}}",
            "HtmlPart": "<p>Welcome, {{name}}!</p>",
            "TextPart": "Welcome, {{name}}!",
        }
    )
    ctx.on_cleanup(lambda _n=name: ses.delete_template(TemplateName=_n))

    resp = ses.test_render_template(TemplateName=name, TemplateData='{"name": "Zaphod"}')
    rendered = resp["RenderedTemplate"]
    msg = _mime(rendered)

    assert msg.get_content_type() == "multipart/alternative", (
        "a template carrying both an HtmlPart and a TextPart must render as a multipart/alternative "
        f"message, got Content-Type {msg.get('Content-Type')!r}"
    )
    parts = msg.get_payload()
    assert [p.get_content_type() for p in parts] == ["text/plain", "text/html"], (
        "multipart/alternative orders parts least-rich first, so the text/plain part must precede the "
        f"text/html part; got {[p.get_content_type() for p in parts]!r}"
    )
    assert msg["Subject"] == "Hello Zaphod", (
        f"the Subject header must carry the rendered subject, got {msg['Subject']!r}"
    )
    assert msg["MIME-Version"] == "1.0", (
        f"an assembled MIME message must declare MIME-Version 1.0, got {msg['MIME-Version']!r}"
    )
    assert _part_text(parts[0]) == "Welcome, Zaphod!", (
        f"the text/plain part must be the rendered TextPart, got {_part_text(parts[0])!r}"
    )
    assert _part_text(parts[1]) == "<p>Welcome, Zaphod!</p>", (
        f"the text/html part must be the rendered HtmlPart, got {_part_text(parts[1])!r}"
    )
    assert "{{name}}" not in rendered, "template placeholder was not substituted"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
