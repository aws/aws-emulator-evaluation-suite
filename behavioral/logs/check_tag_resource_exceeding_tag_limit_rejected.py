"""tag-resource-exceeding-tag-limit-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-exceeding-tag-limit-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with 51 tags (over the 50-tag quota) is rejected with InvalidParameterException
    and persists none of them; tagging the same resource with exactly 50 tags succeeds.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")

    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    group_arn = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0][
        "logGroupArn"
    ]

    over_limit_tags = {f"sim2real-tag-{i}": f"value-{i}" for i in range(51)}
    code, message = _error_code(lambda: logs.tag_resource(resourceArn=group_arn, tags=over_limit_tags))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}: {message!r}"
    assert message == (
        "1 validation error detected: Value at 'tags' failed to satisfy constraint: "
        "Member must have length less than or equal to 50"
    ), f"unexpected over-limit TagResource message: {message!r}"


    # Effect absent: none of the over-limit tags were persisted.
    tags_after_failed_call = logs.list_tags_for_resource(resourceArn=group_arn).get("tags", {})
    assert tags_after_failed_call == {}, (
        f"expected no tags persisted after a rejected over-limit call, got {tags_after_failed_call!r}"
    )

    # Positive control: exactly 50 tags on the same resource succeeds.
    at_limit_tags = {f"sim2real-tag-{i}": f"value-{i}" for i in range(50)}
    logs.tag_resource(resourceArn=group_arn, tags=at_limit_tags)
    ctx.on_cleanup(
        lambda: logs.untag_resource(resourceArn=group_arn, tagKeys=list(at_limit_tags.keys()))
    )
    tags_after_ok_call = logs.list_tags_for_resource(resourceArn=group_arn).get("tags", {})
    assert tags_after_ok_call == at_limit_tags, (
        f"expected exactly the 50 control tags persisted, got {tags_after_ok_call!r}"
    )


def _error_code(fn):
    """Call fn(); return its (error code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects TagResource over the tag-count quota, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
