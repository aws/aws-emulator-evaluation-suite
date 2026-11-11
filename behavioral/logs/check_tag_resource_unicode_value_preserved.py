"""tag-resource-unicode-value-preserved."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-unicode-value-preserved"
GROUP = "representation"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value with CJK and accented Latin letters survives TagResource/ListTagsForResource
    unchanged. Emoji is excluded: the tag regex rejects Unicode symbols.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")

    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: logs.delete_log_group(logGroupName=group_name)))
    # Use logGroupArn (no trailing ":*") -- TagResource/ListTagsForResource
    # require this ARN form, not the ":*"-suffixed "arn" field.
    group_arn = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0][
        "logGroupArn"
    ]

    tag_key = "sim2real-unicode-tag"
    tag_value = "\u65e5\u672c\u8a9e-\u4e2d\u6587-\u00e9\u00e8\u00e0-value"

    logs.tag_resource(resourceArn=group_arn, tags={tag_key: tag_value})
    ctx.on_cleanup(
        lambda: _ignore_notfound(lambda: logs.untag_resource(resourceArn=group_arn, tagKeys=[tag_key]))
    )

    tags = logs.list_tags_for_resource(resourceArn=group_arn)["tags"]
    assert tag_key in tags, f"tag key missing from ListTagsForResource: {tags!r}"
    assert tags[tag_key] == tag_value, (
        f"unicode tag value mangled: sent {tag_value!r} got {tags[tag_key]!r}"
    )

    # The cleanups re-delete/re-untag harmlessly (they tolerate not-found) -- doing the
    # delete here lets us prove gone-and-unusable independently.
    logs.delete_log_group(logGroupName=group_name)
    remaining = logs.describe_log_groups(logGroupNamePrefix=group_name).get("logGroups", [])
    assert remaining == [], f"log group still visible after delete: {remaining!r}"

    try:
        logs.tag_resource(resourceArn=group_arn, tags={tag_key: tag_value})
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException tagging a deleted log group, got {code}: {message!r}"
        )
        assert message == "The specified log group does not exist.", (
            f"unexpected deleted-log-group message: {message!r}"
        )
    else:
        raise AssertionError("TagResource succeeded against a deleted log group")


def _ignore_notfound(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
