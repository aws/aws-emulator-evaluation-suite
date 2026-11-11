"""test-render-template-invalid-json-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-render-template-invalid-json-fails"
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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestRenderTemplate rejects malformed TemplateData with InvalidRenderingParameter, while
    well-formed data on the same template renders correctly both before and after."""
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-behav-tmpl-badjson-")
    ses.create_template(
        Template={
            "TemplateName": name,
            "SubjectPart": "Hello {{name}}",
            "HtmlPart": "<p>{{name}}</p>",
            "TextPart": "{{name}}",
        }
    )
    ctx.on_cleanup(lambda _n=name: ses.delete_template(TemplateName=_n))

    control = ses.test_render_template(TemplateName=name, TemplateData='{"name": "Ford"}')[
        "RenderedTemplate"
    ]
    assert "Ford" in control, f"positive control did not substitute the provided value, got {control!r}"

    # An unclosed JSON object.
    err = _err(
        lambda: ses.test_render_template(TemplateName=name, TemplateData='{"name": ')
    )
    assert err == ("InvalidRenderingParameter", "Template rendering data is invalid"), (
        f"expected InvalidRenderingParameter for malformed TemplateData JSON, got {err!r}"
    )

    # Each render carries a live Date header and fresh MIME boundary, so compare substitution,
    # not bytes, against `control`.
    rendered = ses.test_render_template(TemplateName=name, TemplateData='{"name": "Ford"}')[
        "RenderedTemplate"
    ]
    assert "Ford" in rendered, (
        f"well-formed render broke after a rejected malformed call, got {rendered!r}"
    )
    assert "{{name}}" not in rendered, (
        f"template placeholder was not substituted after the rejected call: {rendered!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
