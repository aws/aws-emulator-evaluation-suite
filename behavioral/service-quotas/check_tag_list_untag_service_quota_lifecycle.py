"""tag-list-untag-service-quota-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-list-untag-service-quota-lifecycle"
GROUP = "state"
SERVICES = ["service-quotas"]

_SERVICE_CODE = "vpc"
_QUOTA_CODE = "L-F678F1CE"  # VPCs per Region


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tagging the ARN of an applied quota makes the tag visible via
    ListTagsForResource, and untagging removes it again."""
    sq = ctx.client("service-quotas")

    try:
        quota = sq.get_service_quota(ServiceCode=_SERVICE_CODE, QuotaCode=_QUOTA_CODE)["Quota"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchResourceException":
            raise AssertionError(
                "no applied quota ARN is available for "
                f"{_SERVICE_CODE}/{_QUOTA_CODE} in this account/region -- there is "
                "no taggable resource to exercise"
            )
        raise
    arn = quota.get("QuotaArn")
    if not arn:
        raise AssertionError(
            f"applied quota for {_SERVICE_CODE}/{_QUOTA_CODE} has no QuotaArn -- "
            "cannot be tagged"
        )

    tag_key = ctx.unique_name("sim2real-sq-tag-")
    tag_value = "behavioral-check"

    sq.tag_resource(ResourceARN=arn, Tags=[{"Key": tag_key, "Value": tag_value}])
    ctx.on_cleanup(lambda: sq.untag_resource(ResourceARN=arn, TagKeys=[tag_key]))

    tags_after_add = {t["Key"]: t["Value"] for t in sq.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags_after_add.get(tag_key) == tag_value, (
        f"expected ListTagsForResource to show {tag_key}={tag_value!r} after TagResource, "
        f"got {tags_after_add.get(tag_key)!r}"
    )

    sq.untag_resource(ResourceARN=arn, TagKeys=[tag_key])
    tags_after_remove = {t["Key"]: t["Value"] for t in sq.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tag_key not in tags_after_remove, (
        f"expected {tag_key} to be absent from ListTagsForResource after UntagResource, "
        f"still present with value {tags_after_remove.get(tag_key)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
