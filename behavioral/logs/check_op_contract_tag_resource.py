"""op-contract-tagResource."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-tagResource"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource persists tags via resourceArn (ARN-based tagging API); exceeding the 50-tag quota is rejected."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    # describe_log_groups() appends a trailing ":*" wildcard suffix to the ARN
    # for backward-compatibility reasons; ARN-based tagging APIs such as
    # TagResource reject that suffixed form with
    # ValidationException("Invalid resourceArn"), so it must be stripped.
    raw_arn = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0]["arn"]
    log_group_arn = raw_arn[: -len(":*")] if raw_arn.endswith(":*") else raw_arn

    logs.tag_resource(resourceArn=log_group_arn, tags={"team": "sim2real", "stage": "dev"})
    tags_resp = logs.list_tags_for_resource(resourceArn=log_group_arn)["tags"]
    assert tags_resp == {"team": "sim2real", "stage": "dev"}, (
        f"expected {{'team': 'sim2real', 'stage': 'dev'}}, got {tags_resp}"
    )

    # tag_resource and tag_log_group operate on the same underlying tag set
    legacy_tags = logs.list_tags_log_group(logGroupName=group_name)["tags"]
    assert legacy_tags == {"team": "sim2real", "stage": "dev"}, (
        "TagResource and TagLogGroup/ListTagsLogGroup must observe the same tag store"
    )

    # error boundary: exceeding the 50-tags-per-resource quota
    group_name_2 = ctx.unique_name("sim2real-behav-lg2-")
    logs.create_log_group(logGroupName=group_name_2)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name_2))
    log_group_arn_2 = logs.describe_log_groups(logGroupNamePrefix=group_name_2)["logGroups"][0][
        "arn"
    ]
    if log_group_arn_2.endswith(":*"):
        log_group_arn_2 = log_group_arn_2[: -len(":*")]
    too_many_tags = {f"k{i}": f"v{i}" for i in range(51)}
    code, msg = _error(
        lambda: logs.tag_resource(resourceArn=log_group_arn_2, tags=too_many_tags)
    )
    # Real CloudWatch Logs rejects exceeding the 50-tag quota as a request-validation failure
    # (InvalidParameterException) rather than the EC2-style TooManyTagsException.
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert msg == (
        "1 validation error detected: Value at 'tags' failed to satisfy constraint: "
        "Member must have length less than or equal to 50"
    ), f"got {msg!r}"

    # the resource must remain untagged after the rejected bulk-tag call
    tags_after_reject = logs.list_tags_for_resource(resourceArn=log_group_arn_2)["tags"]
    assert tags_after_reject == {}, (
        f"rejected TagResource call must not partially apply tags, got {tags_after_reject}"
    )


def _error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
