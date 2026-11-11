"""tag-resource-rejected-for-launch-configuration-template-arn."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-rejected-for-launch-configuration-template-arn"
GROUP = "overly-permissive"
SERVICES = ["drs"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
    "requires:drs-initialized",
)
def run(ctx) -> None:
    """Tag/List/UntagResource refuse a launch-configuration-template ARN with
    BadRequestException regardless of existence, and the template's tags -- settable only at
    create time -- are left unchanged by the refused attempt.
    """
    drs = ctx.client("drs")

    created = drs.create_launch_configuration_template(tags={"sim2real-key": "sim2real-value"})[
        "launchConfigurationTemplate"
    ]
    lct_id = created["launchConfigurationTemplateID"]
    lct_arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_lct(drs, lct_id))

    code, message = _expect_rejected(
        lambda: drs.tag_resource(resourceArn=lct_arn, tags={"sim2real-other": "x"})
    )
    assert code == "BadRequestException", (
        f"TagResource against a launch-configuration-template ARN got {code!r}"
    )
    assert message == "Invalid input resource arn", (
        f"TagResource against a launch-configuration-template ARN answered {message!r}"
    )

    code, message = _expect_rejected(lambda: drs.list_tags_for_resource(resourceArn=lct_arn))
    assert code == "BadRequestException", (
        f"ListTagsForResource against a launch-configuration-template ARN got {code!r}"
    )
    assert message == "Invalid input resource arn", (
        f"ListTagsForResource against a launch-configuration-template ARN answered {message!r}"
    )

    code, message = _expect_rejected(
        lambda: drs.untag_resource(resourceArn=lct_arn, tagKeys=["sim2real-key"])
    )
    assert code == "BadRequestException", (
        f"UntagResource against a launch-configuration-template ARN got {code!r}"
    )
    assert message == "Invalid input resource arn", (
        f"UntagResource against a launch-configuration-template ARN answered {message!r}"
    )

    # The refused UntagResource attempt must not have removed the tag it named.
    described = drs.describe_launch_configuration_templates(
        launchConfigurationTemplateIDs=[lct_id]
    )["items"][0]
    assert described["tags"] == {"sim2real-key": "sim2real-value"}, (
        f"the template's tags must be unchanged by the refused tag operations, "
        f"got {described['tags']!r}"
    )


def _expect_rejected(fn):
    try:
        result = fn()
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")


def _delete_lct(drs, lct_id: str) -> None:
    try:
        drs.delete_launch_configuration_template(launchConfigurationTemplateID=lct_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
