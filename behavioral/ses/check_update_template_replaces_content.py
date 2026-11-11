"""update-template-replaces-content."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-template-replaces-content"
GROUP = 'templates'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises.

    An unexpected success raises, so a target that accepts what AWS refuses fails loudly
    instead of reading as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTemplate replaces the template body/subject in place without changing its name."""
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-behav-tmpl-update-")
    ses.create_template(
        Template={
            "TemplateName": name,
            "SubjectPart": "Old Subject",
            "HtmlPart": "<p>Old</p>",
            "TextPart": "Old",
        }
    )
    ctx.on_cleanup(lambda _n=name: ses.delete_template(TemplateName=_n))

    ses.update_template(
        Template={
            "TemplateName": name,
            "SubjectPart": "New Subject",
            "HtmlPart": "<p>New</p>",
            "TextPart": "New",
        }
    )
    got = ses.get_template(TemplateName=name)["Template"]
    assert got["TemplateName"] == name, f"template name changed by update: {got}"
    assert got["SubjectPart"] == "New Subject", f"subject not updated in place: {got}"
    assert got["HtmlPart"] == "<p>New</p>", f"html part not updated in place: {got}"
    assert got["TextPart"] == "New", f"text part not updated in place: {got}"

    missing_name = ctx.unique_name("sim2real-behav-tmpl-nope-")
    err = _err(
        lambda: ses.update_template(
            Template={"TemplateName": missing_name, "SubjectPart": "x", "HtmlPart": "<p>x</p>", "TextPart": "x"}
        )
    )
    assert err == ("TemplateDoesNotExist", f"Template {missing_name} does not exist."), (
        f"expected TemplateDoesNotExist updating a non-existent template, got {err!r}"
    )

    # UpdateTemplate on an absent template must not upsert it as a side effect.
    err2 = _err(lambda: ses.get_template(TemplateName=missing_name))
    assert err2 == ("TemplateDoesNotExist", f"Template {missing_name} does not exist."), (
        f"UpdateTemplate on a missing template must not have created it, got {err2!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
