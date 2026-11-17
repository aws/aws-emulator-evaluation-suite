"""tag-resources-rejects-the-log-group-arns-trailing-wildcard-suffix."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resources-rejects-the-log-group-arns-trailing-wildcard-suffix"
GROUP = "tagging-discovery"
SERVICES = ["logs", "resourcegroupstaggingapi"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResources rejects a log group ARN carrying DescribeLogGroups' trailing ":*" while the
    same batch call tags the same group's non-wildcard ARN.
    """
    logs = ctx.client("logs")
    rgt = ctx.client("resourcegroupstaggingapi")

    group_name = ctx.unique_name("/sim2real/behav-tag-wildcard-")
    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    starred_arn = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0]["arn"]
    assert starred_arn.endswith(":*"), (
        f"describe_log_groups returned {starred_arn!r}, expected a trailing ':*'"
    )
    bare_arn = starred_arn[:-2]

    key = ctx.unique_name("sim2real-behav-tagkey-")
    value = ctx.unique_name("sim2real-behav-tagval-")

    resp = rgt.tag_resources(ResourceARNList=[starred_arn, bare_arn], Tags={key: value})

    failed = resp["FailedResourcesMap"]
    assert set(failed) == {starred_arn}, (
        f"FailedResourcesMap named {sorted(failed)!r}, expected exactly the wildcard-suffixed "
        f"ARN {starred_arn!r} to fail while the bare ARN {bare_arn!r} in the same batch succeeds"
    )
    detail = failed[starred_arn]
    got = (detail["ErrorCode"], detail["StatusCode"], detail["ErrorMessage"])
    expected = ("ValidationException", 400, "Invalid resourceArn")
    assert got == expected, (
        f"the wildcard-suffixed ARN's (ErrorCode, StatusCode, ErrorMessage) was {got!r}, "
        f"expected {expected!r}"
    )

    native = logs.list_tags_for_resource(resourceArn=bare_arn).get("tags", {})
    assert native == {key: value}, (
        f"ListTagsForResource on the bare ARN reports {native!r}; the wildcard ARN's rejection in "
        f"the same batch must not have blocked the bare ARN from being tagged"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
