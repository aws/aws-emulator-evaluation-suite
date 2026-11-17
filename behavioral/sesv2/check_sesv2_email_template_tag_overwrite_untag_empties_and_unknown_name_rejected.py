"""sesv2-email-template-tag-overwrite-untag-empties-and-unknown-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sesv2-email-template-tag-overwrite-untag-empties-and-unknown-name-rejected"
GROUP = "templates-v2"
SERVICES = ["sesv2"]


def _error(fn):
    """The (code, message) ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource on an email template overwrites a key in place, UntagResource can empty the
    tag list, GetEmailTemplate's content is unaffected by either, and TagResource/UntagResource on
    a template name never created both fail NotFoundException with the same message.
    """
    ses = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-behav-tpltagov-")
    arn = f"arn:aws:ses:{ctx.region}:{ctx.account}:template/{name}"
    content = {"Subject": "S", "Text": "T"}

    ses.create_email_template(
        TemplateName=name,
        TemplateContent=content,
        Tags=[{"Key": "audit", "Value": "original"}],
    )
    ctx.on_cleanup(lambda: ses.delete_email_template(TemplateName=name))

    after_create = ses.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert after_create == [{"Key": "audit", "Value": "original"}], (
        f"expected exactly [audit=original] right after create, got {after_create!r}"
    )

    ses.tag_resource(ResourceArn=arn, Tags=[{"Key": "audit", "Value": "updated"}])
    after_tag = ses.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert after_tag == [{"Key": "audit", "Value": "updated"}], (
        f"expected TagResource to overwrite the 'audit' value in place, got {after_tag!r}"
    )

    content_after_tag = ses.get_email_template(TemplateName=name)["TemplateContent"]
    assert content_after_tag == content, (
        f"expected GetEmailTemplate content unchanged by tagging, got {content_after_tag!r}"
    )

    ses.untag_resource(ResourceArn=arn, TagKeys=["audit"])
    after_untag = ses.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert after_untag == [], f"expected an empty tag list after removing the only tag, got {after_untag!r}"

    content_after_untag = ses.get_email_template(TemplateName=name)["TemplateContent"]
    assert content_after_untag == content, (
        f"expected GetEmailTemplate content unchanged by untagging, got {content_after_untag!r}"
    )

    ghost_name = ctx.unique_name("sim2real-behav-tpltagov-missing-")
    ghost_arn = f"arn:aws:ses:{ctx.region}:{ctx.account}:template/{ghost_name}"
    expected = ("NotFoundException", f"No Template present with name: {ghost_name}")

    tag_result = _error(lambda: ses.tag_resource(ResourceArn=ghost_arn, Tags=[{"Key": "k", "Value": "v"}]))
    assert tag_result == expected, (
        f"TagResource on a template name never created gave {tag_result!r}, expected {expected!r}"
    )

    untag_result = _error(lambda: ses.untag_resource(ResourceArn=ghost_arn, TagKeys=["k"]))
    assert untag_result == expected, (
        f"UntagResource on a template name never created gave {untag_result!r}, expected {expected!r}"
    )

    after_refusals = ses.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert after_refusals == [], (
        f"the real template's tags changed to {after_refusals!r} after the refused calls on an "
        "unrelated name, expected still empty"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
