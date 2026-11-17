"""create-email-template-aws-tag-prefix-rejected-name-freed."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-email-template-aws-tag-prefix-rejected-name-freed"
GROUP = "templates-v2"
SERVICES = ["sesv2"]

_REFUSED = ("BadRequestException", "Invalid tags")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code, message) -> None:
    got_code, got_msg = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r}: {got_msg!r}"
    assert got_msg == message, f"expected message {message!r}, got {got_msg!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEmailTemplate refuses an aws:-prefixed tag key and creates no template, and the
    freed name accepts a later CreateEmailTemplate carrying legal tags.
    """
    ses = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-behav-v2tpl-awstag-")

    expect_error(
        lambda: ses.create_email_template(
            TemplateName=name,
            TemplateContent={"Subject": "refused", "Text": "refused"},
            Tags=[{"Key": "aws:sim2real", "Value": "nope"}],
        ),
        *_REFUSED,
    )

    expected_missing_msg = f"Template {name} does not exist."
    expect_error(lambda: ses.get_email_template(TemplateName=name), "NotFoundException", expected_missing_msg)

    ses.create_email_template(
        TemplateName=name,
        TemplateContent={"Subject": "legal", "Text": "legal"},
        Tags=[{"Key": "sim2real-env", "Value": "dev"}],
    )
    ctx.on_cleanup(lambda _k=name: ses.delete_email_template(TemplateName=_k))

    created = ses.get_email_template(TemplateName=name)
    assert created["TemplateName"] == name, f"expected {name!r}, got {created['TemplateName']!r}"
    assert created["TemplateContent"]["Subject"] == "legal", (
        f"expected the legal-tag create's content, got {created['TemplateContent']!r}"
    )

    arn = f"arn:aws:ses:{ctx.region}:{ctx.account}:template/{name}"
    tag_map = {t["Key"]: t["Value"] for t in ses.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert tag_map == {"sim2real-env": "dev"}, f"expected the legal tag only, got {tag_map!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
