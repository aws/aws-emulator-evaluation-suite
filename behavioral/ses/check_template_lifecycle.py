"""template-lifecycle."""
from __future__ import annotations

import email
import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-lifecycle"
GROUP = 'templates'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the (Code, HTTP status, Message) of the ClientError it raises.

    An unexpected success raises, so a target that accepts what AWS refuses fails loudly
    instead of reading as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return error.get("Code"), status, error.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _assert_missing(label, fn, expected_message):
    code, status, message = _err(fn)
    assert code == "TemplateDoesNotExist", f"{label}: expected TemplateDoesNotExist, got {code!r} ({message!r})"
    assert isinstance(status, int) and 400 <= status < 500, f"{label}: expected HTTP 4xx, got {status!r}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _template_names(ses):
    """Every template name, following NextToken."""
    names, token = [], None
    while True:
        resp = ses.list_templates(NextToken=token) if token else ses.list_templates()
        names.extend(t["Name"] for t in resp.get("TemplatesMetadata", []))
        token = resp.get("NextToken")
        if not token:
            return names


def _delete_if_present(ses, name):
    try:
        ses.delete_template(TemplateName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "TemplateDoesNotExist":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTemplate -> GetTemplate -> TestRenderTemplate substitutes the data -> DeleteTemplate
    -> gone from GetTemplate and ListTemplates and refused by UpdateTemplate and the renderer."""
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-behav-tmpl-")

    _assert_missing("GetTemplate before create", lambda: ses.get_template(TemplateName=name), expected_message=f"Template {name} does not exist.")

    ses.create_template(
        Template={
            "TemplateName": name,
            "SubjectPart": "Subject {{value}}",
            "HtmlPart": "<p>{{value}}</p>",
            "TextPart": "{{value}}",
        }
    )
    ctx.on_cleanup(lambda _n=name: _delete_if_present(ses, _n))

    got = ses.get_template(TemplateName=name)["Template"]
    assert got["TemplateName"] == name, f"expected TemplateName {name!r}, got {got['TemplateName']!r}"
    assert got["SubjectPart"] == "Subject {{value}}", (
        f"expected SubjectPart 'Subject {{{{value}}}}', got {got['SubjectPart']!r}"
    )

    # The send-path renderer substitutes the data into subject and text.
    marker = uuid.uuid4().hex
    rendered = ses.test_render_template(
        TemplateName=name, TemplateData=json.dumps({"value": marker})
    )["RenderedTemplate"]
    msg = email.message_from_string(rendered)
    subject = str(msg.get("Subject", ""))
    assert subject == f"Subject {marker}", f"expected rendered Subject 'Subject {marker}', got {subject!r}"
    texts = [
        part.get_payload(decode=True).decode("utf-8", "replace")
        for part in msg.walk()
        if part.get_content_type() == "text/plain"
    ]
    assert any(marker in t for t in texts), f"expected the text part to carry {marker!r}, got {texts!r}"
    assert "{{value}}" not in rendered, f"rendered MIME still contains an unsubstituted placeholder: {rendered!r}"

    assert name in _template_names(ses), "template missing from ListTemplates"

    ses.delete_template(TemplateName=name)

    _assert_missing("GetTemplate after delete", lambda: ses.get_template(TemplateName=name), expected_message=f"Template {name} does not exist.")
    assert name not in _template_names(ses), f"deleted template {name!r} is still listed by ListTemplates"

    # A mutation on the dead id must also fail -- UpdateTemplate does not upsert -- and the
    # renderer refuses it too.
    _assert_missing(
        "UpdateTemplate after delete",
        lambda: ses.update_template(Template={"TemplateName": name, "SubjectPart": "S", "TextPart": "B"}),
        expected_message=f"Template {name} does not exist.",
    )
    _assert_missing(
        "TestRenderTemplate after delete",
        lambda: ses.test_render_template(TemplateName=name, TemplateData=json.dumps({"value": marker})),
        expected_message=f"Unable to find <{name}> for <{ctx.account}>",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
