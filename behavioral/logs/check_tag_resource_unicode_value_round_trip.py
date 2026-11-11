"""tag-resource-unicode-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value containing unicode letters (CJK, Cyrillic, Greek, accented Latin) is
    stored and returned unchanged via ListTagsForResource.
    """
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-logs-")
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    arn = _log_group_arn(ctx, group)

    # TagValue's allowed character set is letters/numbers/separators plus _.:/=+-@ --
    # unicode *letters* (CJK, Cyrillic, Greek, accented Latin) are permitted, emoji/symbols
    # are not, so we stick to letter scripts here.
    tag_key = "sim2real-unicode-tag"
    tag_value = "café-北京-Москва-θήτα"
    logs.tag_resource(resourceArn=arn, tags={tag_key: tag_value})
    ctx.on_cleanup(lambda: logs.untag_resource(resourceArn=arn, tagKeys=[tag_key]))

    got = logs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tag_key in got, f"tag key missing from ListTagsForResource: {got!r}"
    assert got[tag_key] == tag_value, f"unicode tag value not preserved: {got[tag_key]!r} != {tag_value!r}"


def _log_group_arn(ctx, group_name):
    logs = ctx.client("logs")
    resp = logs.describe_log_groups(logGroupNamePrefix=group_name)
    matches = [g for g in resp.get("logGroups", []) if g["logGroupName"] == group_name]
    assert matches, f"log group {group_name} not found via DescribeLogGroups"
    arn = matches[0]["arn"]
    # DescribeLogGroups appends a trailing ":*" to the ARN; TagResource's ARN pattern
    # does not allow "*", so it must be stripped before use with the tagging APIs.
    if arn.endswith(":*"):
        arn = arn[:-2]
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
