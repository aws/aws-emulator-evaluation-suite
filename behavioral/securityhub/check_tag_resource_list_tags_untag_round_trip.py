"""tag-resource-list-tags-untag-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-list-tags-untag-round-trip"
GROUP = "data-plane"
SERVICES = ["securityhub"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip a tag on the Security Hub `Hub` resource."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(sh)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    hub_arn = f"arn:aws:securityhub:{ctx.region}:{account_id}:hub/default"

    key = "sim2real-tag-key"
    value = ctx.unique_name("sim2real-tag-value-")
    sh.tag_resource(ResourceArn=hub_arn, Tags={key: value})
    ctx.on_cleanup(lambda: _untag_ignore(sh, hub_arn, key))

    tags = sh.list_tags_for_resource(ResourceArn=hub_arn)["Tags"]
    assert tags.get(key) == value, f"expected tag {key}={value!r} on hub, got {tags.get(key)!r}"

    sh.untag_resource(ResourceArn=hub_arn, TagKeys=[key])
    tags_after = sh.list_tags_for_resource(ResourceArn=hub_arn)["Tags"]
    assert key not in tags_after, f"expected {key} removed after UntagResource, still present: {tags_after!r}"


def _ensure_hub_enabled(sh):
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise


def _untag_ignore(sh, arn, key):
    try:
        sh.untag_resource(ResourceArn=arn, TagKeys=[key])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

