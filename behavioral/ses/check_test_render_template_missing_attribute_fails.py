"""test-render-template-missing-attribute-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-render-template-missing-attribute-fails"
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


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestRenderTemplate must fail with MissingRenderingAttributeException when TemplateData omits a referenced variable."""
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-behav-tmpl-missing-")
    ses.create_template(
        Template={
            "TemplateName": name,
            "SubjectPart": "Hello {{name}}",
            "HtmlPart": "<p>{{name}} - {{unfilled_var}}</p>",
            "TextPart": "{{name}} - {{unfilled_var}}",
        }
    )
    ctx.on_cleanup(lambda _n=name: ses.delete_template(TemplateName=_n))

    control = ses.test_render_template(
        TemplateName=name, TemplateData='{"name": "Zaphod", "unfilled_var": "42"}'
    )
    rendered = control["RenderedTemplate"]
    assert "Zaphod" in rendered and "42" in rendered, (
        f"positive control: expected both replacement values in rendered template, got {rendered!r}"
    )

    err = _err(
        lambda: ses.test_render_template(TemplateName=name, TemplateData='{"name": "Zaphod"}')
    )
    assert err == (
        "MissingRenderingAttribute",
        "Attribute 'unfilled_var' is not present in the rendering data.",
    ), (
        f"expected MissingRenderingAttribute for unfilled variable, got {err!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
