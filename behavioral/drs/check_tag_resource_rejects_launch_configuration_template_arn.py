"""tag-resource-rejects-launch-configuration-template-arn."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-rejects-launch-configuration-template-arn"
GROUP = "tagging"
SERVICES = ["drs"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags(
    "requires:drs-initialized",
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """TagResource and ListTagsForResource both refuse a Launch Configuration Template ARN
    while the generic tag API accepts the same shape of ARN for a Replication Configuration
    Template, and the rejected call leaves that unrelated resource's own tags untouched."""
    drs = ctx.client("drs")

    control = drs.create_launch_configuration_template(tags={"owner": "sim2real-behav"})
    control_id = control["launchConfigurationTemplate"]["launchConfigurationTemplateID"]
    control_arn = control["launchConfigurationTemplate"]["arn"]
    ctx.on_cleanup(
        lambda: drs.delete_launch_configuration_template(launchConfigurationTemplateID=control_id)
    )
    assert control["launchConfigurationTemplate"]["tags"] == {"owner": "sim2real-behav"}, (
        f"unexpected tags on creation: {control['launchConfigurationTemplate']['tags']!r}"
    )

    code, message = _error(lambda: drs.tag_resource(resourceArn=control_arn, tags={"extra": "v"}))
    assert code == "BadRequestException", (
        f"TagResource on a launch-configuration-template ARN gave {code}: {message!r}"
    )
    assert message == "Invalid input resource arn", f"unexpected message {message!r}"

    code, message = _error(lambda: drs.list_tags_for_resource(resourceArn=control_arn))
    assert code == "BadRequestException", (
        f"ListTagsForResource on a launch-configuration-template ARN gave {code}: {message!r}"
    )
    assert message == "Invalid input resource arn", f"unexpected message {message!r}"

    # The rejected TagResource call must have changed nothing: the control template's own
    # tags, read back the only way this resource type lets a template's tags be read, are
    # exactly what create set.
    unaffected = drs.describe_launch_configuration_templates(
        launchConfigurationTemplateIDs=[control_id]
    )["items"][0]
    assert unaffected["tags"] == {"owner": "sim2real-behav"}, (
        f"template tags changed after a rejected TagResource call: {unaffected['tags']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
