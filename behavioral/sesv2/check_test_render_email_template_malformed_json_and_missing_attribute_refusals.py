"""test-render-email-template-malformed-json-and-missing-attribute-refusals."""
from __future__ import annotations

import email
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-render-email-template-malformed-json-and-missing-attribute-refusals"
GROUP = "template-render"
SERVICES = ["sesv2"]


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestRenderEmailTemplate refuses syntactically invalid JSON and JSON missing a referenced
    attribute with two distinct BadRequestException messages against the same template; neither
    refusal changes the stored content, and supplying every attribute renders it.
    """
    ses = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-behav-render-refusals-")
    content = {
        "Subject": "Order {{order_id}} confirmed",
        "Text": "Hello {{name}}, order {{order_id}} ships to {{address}}.",
        "Html": "<p>Hello {{name}}, order {{order_id}} ships to {{address}}.</p>",
    }
    ses.create_email_template(TemplateName=name, TemplateContent=content)
    ctx.on_cleanup(lambda: ses.delete_email_template(TemplateName=name))
    stored_initial = ses.get_email_template(TemplateName=name)["TemplateContent"]
    assert stored_initial == content, f"stored content differs from what was created: {stored_initial!r}"

    _MALFORMED_JSON = (
        "BadRequestException",
        "Template rendering data is invalid",
    )
    expect_error(
        lambda: ses.test_render_email_template(TemplateName=name, TemplateData="{not valid json}"),
        *_MALFORMED_JSON,
    )
    stored_after_malformed = ses.get_email_template(TemplateName=name)["TemplateContent"]
    assert stored_after_malformed == content, (
        f"the malformed-JSON refusal changed the stored template: {stored_after_malformed!r}"
    )

    incomplete_data = json.dumps({"name": "Mary Major", "order_id": "A1"})
    _MISSING_ATTRIBUTE = (
        "BadRequestException",
        "Attribute 'address' is not present in the rendering data.",
    )
    expect_error(
        lambda: ses.test_render_email_template(TemplateName=name, TemplateData=incomplete_data),
        *_MISSING_ATTRIBUTE,
    )
    stored_after_missing = ses.get_email_template(TemplateName=name)["TemplateContent"]
    assert stored_after_missing == content, (
        f"the missing-attribute refusal changed the stored template: {stored_after_missing!r}"
    )

    complete_data = json.dumps({"name": "Mary Major", "order_id": "A1", "address": "123 Any Street"})
    rendered = ses.test_render_email_template(TemplateName=name, TemplateData=complete_data)["RenderedTemplate"]
    msg = email.message_from_string(rendered)
    assert msg.defects == [], f"the rendered template is not a well-formed MIME message: {msg.defects!r}"
    assert msg["Subject"] == "Order A1 confirmed", f"unexpected Subject: {msg['Subject']!r}"
    text_part, html_part = msg.get_payload()[0], msg.get_payload()[1]

    def _part_text(part) -> str:
        raw = part.get_payload(decode=True)
        assert raw is not None, f"part {part.get_content_type()!r} carries no decodable payload"
        return raw.decode(part.get_content_charset() or "utf-8")

    assert _part_text(text_part) == "Hello Mary Major, order A1 ships to 123 Any Street.", (
        f"unexpected text/plain part: {_part_text(text_part)!r}"
    )
    assert _part_text(html_part) == "<p>Hello Mary Major, order A1 ships to 123 Any Street.</p>", (
        f"unexpected text/html part: {_part_text(html_part)!r}"
    )

    stored_final = ses.get_email_template(TemplateName=name)["TemplateContent"]
    assert stored_final == content, f"a successful render changed the stored template: {stored_final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
