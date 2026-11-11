"""template-without-subject-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-without-subject-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTemplate rejects a template without SubjectPart with InvalidParameterValue and stores
    nothing, while an otherwise-identical template with a subject is accepted."""
    ses = ctx.client("ses")

    ok_name = ctx.unique_name("sim2real-behav-tmpl-nosubj-ctrl-")
    ses.create_template(
        Template={
            "TemplateName": ok_name,
            "SubjectPart": "Control subject",
            "TextPart": "Body only, no subject",
        }
    )
    ctx.on_cleanup(lambda _n=ok_name: ses.delete_template(TemplateName=_n))
    got = ses.get_template(TemplateName=ok_name)["Template"]
    assert got["TemplateName"] == ok_name, (
        f"positive control template must exist under its own name, got {got.get('TemplateName')!r}"
    )

    name = ctx.unique_name("sim2real-behav-tmpl-nosubj-")
    err = _err(
        lambda: ses.create_template(
            Template={"TemplateName": name, "TextPart": "Body only, no subject"}
        )
    )
    assert err == ("InvalidParameterValue", "The subject must be specified."), (
        f"expected InvalidParameterValue for a subject-less template, got {err!r}"
    )

    err2 = _err(lambda: ses.get_template(TemplateName=name))
    assert err2 == ("TemplateDoesNotExist", f"Template {name} does not exist."), (
        f"rejected template must not exist, got {err2!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
