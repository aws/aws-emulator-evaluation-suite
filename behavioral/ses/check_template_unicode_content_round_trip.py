"""template-unicode-content-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-unicode-content-round-trip"
GROUP = "representation"
SERVICES = ["ses"]


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A template created with unicode subject/HTML/text body content is
    returned byte-identical on GetTemplate, and deleting it makes it
    unreachable by both an independent read and a further mutation."""
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-ses-tmpl-")
    subject = "Café ☕ update – {{name}} 确认您的订阅"
    html = "<html><body><p>Bonjour {{name}}, café ☕ &amp; 100% naïve — 你好</p></body></html>"
    text = "Bonjour {{name}}, café ☕ & 100% naïve — 你好"

    ses.create_template(
        Template={"TemplateName": name, "SubjectPart": subject, "HtmlPart": html, "TextPart": text}
    )
    ctx.on_cleanup(lambda: ses.delete_template(TemplateName=name))

    got = ses.get_template(TemplateName=name)["Template"]
    assert got["SubjectPart"] == subject, (repr(got["SubjectPart"]), repr(subject))
    assert got["HtmlPart"] == html, (repr(got["HtmlPart"]), repr(html))
    assert got["TextPart"] == text, (repr(got["TextPart"]), repr(text))

    ses.delete_template(TemplateName=name)

    err = _err(lambda: ses.get_template(TemplateName=name))
    missing = ("TemplateDoesNotExist", f"Template {name} does not exist.")
    assert err == missing, f"expected not-found after delete, got {err!r}"

    err2 = _err(
        lambda: ses.update_template(
            Template={"TemplateName": name, "SubjectPart": subject, "TextPart": text}
        )
    )
    assert err2 == missing, f"expected UpdateTemplate on deleted name to fail, got {err2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
