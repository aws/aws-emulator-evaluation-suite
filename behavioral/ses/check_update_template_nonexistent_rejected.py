"""update-template-nonexistent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-template-nonexistent-rejected"
GROUP = 'overly-permissive'
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTemplate must not upsert a template that does not exist yet (TemplateDoesNotExist)."""
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-behav-tmpl-absent-")
    err = _err(
        lambda: ses.update_template(
            Template={"TemplateName": name, "SubjectPart": "S", "TextPart": "B"}
        )
    )
    assert err == ("TemplateDoesNotExist", f"Template {name} does not exist."), (
        f"expected TemplateDoesNotExist updating an absent template, got {err!r}"
    )

    # It must not have been upserted as a side effect.
    err2 = _err(lambda: ses.get_template(TemplateName=name))
    assert err2 == ("TemplateDoesNotExist", f"Template {name} does not exist."), (
        f"UpdateTemplate must not have created the template, got {err2!r}"
    )

    # DeleteTemplate, by contrast, is a tolerant no-op for absent templates.
    ses.delete_template(TemplateName=name)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
