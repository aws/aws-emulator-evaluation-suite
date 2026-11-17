"""tag-resources-mixed-live-bucket-and-absent-table-rejected-per-resource."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resources-mixed-live-bucket-and-absent-table-rejected-per-resource"
GROUP = "overly-permissive"
SERVICES = ["resourcegroupstaggingapi", "s3", "sts"]


def _delete_bucket(s3, bucket: str) -> None:
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A TagResources batch naming a live S3 bucket and an absent DynamoDB table ARN tags the
    bucket and lists the absent table in FailedResourcesMap with DynamoDB's own error; the absent
    ARN never enters the tagging index."""
    s3 = ctx.client("s3")
    rgt = ctx.client("resourcegroupstaggingapi")
    sts = ctx.client("sts")

    account = sts.get_caller_identity()["Account"]
    key = ctx.unique_name("sim2real-behav-part-")

    bucket = ctx.unique_name("sim2real-behav-bkt-")
    create_params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    bucket_arn = f"arn:aws:s3:::{bucket}"

    # A syntactically valid ARN for a table this check never creates, in this account and region so
    # only the table's existence is wrong.
    ghost_arn = f"arn:aws:dynamodb:{ctx.region}:{account}:table/{ctx.unique_name('sim2real-behav-ghost-')}"

    result = rgt.tag_resources(ResourceARNList=[bucket_arn, ghost_arn], Tags={key: "partial"})
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=[bucket_arn], TagKeys=[key]))

    failed = result["FailedResourcesMap"]
    assert set(failed) == {ghost_arn}, (
        f"FailedResourcesMap named {sorted(failed)!r}, expected exactly the absent table "
        f"{ghost_arn!r} — the live bucket {bucket_arn!r} must not fail and the absent table must "
        f"not pass"
    )
    detail = failed[ghost_arn]
    assert detail["ErrorCode"] == "ResourceNotFoundException", (
        f"the per-resource ErrorCode for an absent table was {detail['ErrorCode']!r}, expected "
        f"DynamoDB's own ResourceNotFoundException"
    )
    assert detail["StatusCode"] == 400, (
        f"the per-resource StatusCode was {detail['StatusCode']!r}, expected 400"
    )
    expected_message = f"Requested resource not found: ResourceArn: {ghost_arn} not found"
    assert detail["ErrorMessage"] == expected_message, (
        f"the per-resource ErrorMessage for an absent table was {detail['ErrorMessage']!r}, "
        f"expected {expected_message!r}"
    )

    # Positive control, in the same call: the live bucket really was tagged.
    bucket_tags = _poll_until(
        lambda: {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])},
        lambda m: m.get(key) == "partial",
        timeout_s=120.0,
    )
    assert bucket_tags.get(key) == "partial", (
        f"the live bucket's own GetBucketTagging reports {bucket_tags!r}; a partial failure must "
        f"still apply the tags that succeeded"
    )

    # Effect absent: the absent table was never indexed.
    settled = _poll_until(
        lambda: {m["ResourceARN"] for m in _all_resources(rgt, TagFilters=[{"Key": key}])},
        lambda arns: arns == {bucket_arn},
        timeout_s=180.0,
    )
    assert settled == {bucket_arn}, (
        f"tag filter {key!r} matched {sorted(settled)!r}, expected exactly the live bucket "
        f"{bucket_arn!r} — the absent table must not have been indexed"
    )


def _all_resources(rgt, **kwargs):
    """Every ResourceTagMapping for a GetResources query, following PaginationToken to the end."""
    out, token = [], ""
    while True:
        page = rgt.get_resources(**kwargs, **({"PaginationToken": token} if token else {}))
        out.extend(page["ResourceTagMappingList"])
        token = page["PaginationToken"]
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
