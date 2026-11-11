"""template-render-applies-handlebars-conditional-branches."""
from __future__ import annotations

import email
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-render-applies-handlebars-conditional-branches"
GROUP = "templates"
SERVICES = ["ses"]

_SUBJECT_PART = "Hi {{name}}"
_TEXT_PART = "{{#if vip}}VIP for {{name}}{{else}}standard for {{name}}{{/if}}"
_HTML_PART = "<p>{{name}} is {{#if vip}}a VIP{{else}}standard{{/if}}</p>"

def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "TemplateDoesNotExist":
            raise


def _parts(rendered: str) -> dict[str, str]:
    """Parse TestRenderTemplate's MIME output and return content-type -> body.

    Parsed structurally because the boundary is minted per render.
    """
    msg = email.message_from_string(rendered)
    assert msg.is_multipart(), f"rendered template is not multipart: {msg.get_content_type()!r}"
    return {p.get_content_type(): p.get_payload(decode=False) for p in msg.get_payload()}


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """One stored template renders both branches of a {{#if}} block from the supplied TemplateData,
    with the name substituted into the subject, text and HTML parts, and the template left unchanged.
    """
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-behav-ses-tpl-")

    ses.create_template(Template={
        "TemplateName": name,
        "SubjectPart": _SUBJECT_PART,
        "TextPart": _TEXT_PART,
        "HtmlPart": _HTML_PART,
    })
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ses.delete_template(TemplateName=name)))

    vip = ses.test_render_template(
        TemplateName=name, TemplateData=json.dumps({"name": "Ada", "vip": True})
    )["RenderedTemplate"]
    standard = ses.test_render_template(
        TemplateName=name, TemplateData=json.dumps({"name": "Bob", "vip": False})
    )["RenderedTemplate"]

    vip_msg = email.message_from_string(vip)
    assert vip_msg["Subject"] == "Hi Ada", (
        f"subject rendered as {vip_msg['Subject']!r}, expected 'Hi Ada'"
    )
    assert vip_msg.get_content_type() == "multipart/alternative", (
        f"rendered content type was {vip_msg.get_content_type()!r}, expected multipart/alternative"
    )
    assert vip_msg["Date"] is not None, "rendered template carries no Date header"

    vip_parts = _parts(vip)
    assert set(vip_parts) == {"text/plain", "text/html"}, (
        f"rendered parts were {sorted(vip_parts)!r}, expected text/plain and text/html"
    )
    # .strip() removes only the CRLF the MIME boundary owns, not template output.
    assert vip_parts["text/plain"].strip() == "VIP for Ada", (
        f"text part rendered as {vip_parts['text/plain']!r}, expected 'VIP for Ada'"
    )
    assert vip_parts["text/html"].strip() == "<p>Ada is a VIP</p>", (
        f"html part rendered as {vip_parts['text/html']!r}, expected '<p>Ada is a VIP</p>'"
    )

    standard_msg = email.message_from_string(standard)
    assert standard_msg["Subject"] == "Hi Bob", (
        f"subject rendered as {standard_msg['Subject']!r}, expected 'Hi Bob'"
    )
    standard_parts = _parts(standard)
    assert standard_parts["text/plain"].strip() == "standard for Bob", (
        f"the {{{{else}}}} branch rendered as {standard_parts['text/plain']!r}, expected "
        f"'standard for Bob'"
    )
    assert standard_parts["text/html"].strip() == "<p>Bob is standard</p>", (
        f"html else-branch rendered as {standard_parts['text/html']!r}, expected "
        f"'<p>Bob is standard</p>'"
    )

    stored = ses.get_template(TemplateName=name)["Template"]
    assert stored["TextPart"] == _TEXT_PART, (
        f"stored TextPart came back as {stored['TextPart']!r}, expected the unrendered "
        f"{_TEXT_PART!r} — rendering must not rewrite the template"
    )
    assert stored["SubjectPart"] == _SUBJECT_PART, (
        f"stored SubjectPart came back as {stored['SubjectPart']!r}, expected {_SUBJECT_PART!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
