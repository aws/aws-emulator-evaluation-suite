"""template-render-rejects-a-missing-rendering-attribute."""
from __future__ import annotations

import email
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-render-rejects-a-missing-rendering-attribute"
GROUP = "templates"
SERVICES = ["ses"]

_SUBJECT_PART = "Order {{orderId}} for {{name}}"
_TEXT_PART = "{{name}}, order {{orderId}} is confirmed."

def _error(fn, what: str) -> tuple[str, str]:
    """Call fn(); return (Error.Code, Error.Message). An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what} SUCCEEDED; real AWS rejects it")


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "TemplateDoesNotExist":
            raise


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Rendering with TemplateData that omits a referenced variable is refused with
    MissingRenderingAttribute naming it, rather than substituting an empty string; the stored
    template is untouched and complete data still renders.
    """
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-behav-ses-tpl-")

    ses.create_template(Template={
        "TemplateName": name, "SubjectPart": _SUBJECT_PART, "TextPart": _TEXT_PART,
    })
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ses.delete_template(TemplateName=name)))

    complete = ses.test_render_template(
        TemplateName=name, TemplateData=json.dumps({"name": "Ada", "orderId": "A-1"})
    )["RenderedTemplate"]
    rendered = email.message_from_string(complete)
    assert rendered["Subject"] == "Order A-1 for Ada", (
        f"the complete render produced subject {rendered['Subject']!r}, expected "
        f"'Order A-1 for Ada'; the negative below would then prove nothing"
    )

    code, message = _error(
        lambda: ses.test_render_template(
            TemplateName=name, TemplateData=json.dumps({"orderId": "A-1"})
        ),
        "TestRenderTemplate with 'name' omitted",
    )
    assert code == "MissingRenderingAttribute", (
        f"expected MissingRenderingAttribute, got {code!r}: {message!r}"
    )
    assert message == "Attribute 'name' is not present in the rendering data.", (
        f"expected \"Attribute 'name' is not present in the rendering data.\", got {message!r}"
    )

    code, message = _error(
        lambda: ses.test_render_template(TemplateName=name, TemplateData=json.dumps({})),
        "TestRenderTemplate with no rendering data at all",
    )
    assert code == "MissingRenderingAttribute", (
        f"expected MissingRenderingAttribute for empty TemplateData, got {code!r}: {message!r}"
    )

    stored = ses.get_template(TemplateName=name)["Template"]
    assert stored["SubjectPart"] == _SUBJECT_PART, (
        f"stored SubjectPart is now {stored['SubjectPart']!r}, expected {_SUBJECT_PART!r}"
    )
    assert stored["TextPart"] == _TEXT_PART, (
        f"stored TextPart is now {stored['TextPart']!r}, expected {_TEXT_PART!r}"
    )

    again = email.message_from_string(ses.test_render_template(
        TemplateName=name, TemplateData=json.dumps({"name": "Bob", "orderId": "B-2"})
    )["RenderedTemplate"])
    assert again["Subject"] == "Order B-2 for Bob", (
        f"a complete render after the refusals produced {again['Subject']!r}, expected "
        f"'Order B-2 for Bob'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
