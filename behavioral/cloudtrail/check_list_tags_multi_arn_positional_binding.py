"""list-tags-multi-arn-positional-binding."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

# The single-shot bucket cleanup is safe: StartLogging is never called, so the bucket stays empty.

def _error_response(fn):
    """Call fn(); return the full botocore error response dict, or None if it succeeded."""
    try:
        fn()
    except ClientError as exc:
        return exc.response
    return None


def _call(fn, retry_codes=(
    "ThrottlingException",
    "MaximumNumberOfTrailsExceededException",
    "ConflictException",
    "InsufficientS3BucketPolicyException",
), attempts=7):
    """Invoke fn(), retrying transient CloudTrail control-plane errors."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in retry_codes and i < attempts - 1:
                last = exc
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise last


def _create_bucket_only(s3, bucket, region):
    """Create a plain S3 bucket (no CloudTrail policy)."""
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise


def _create_trail_bucket(s3, bucket, region, account_id):
    """Create an S3 bucket with the policy CloudTrail needs to deliver logs."""
    _create_bucket_only(s3, bucket, region)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": [
                    f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                    f"arn:aws:s3:::{bucket}/*/AWSLogs/{account_id}/*",
                ],
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _empty_and_delete_bucket(s3, bucket):
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_trail(ct, name):
    """Best-effort teardown: stop logging (if on) then delete the trail."""
    try:
        ct.stop_logging(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise
    try:
        _call(lambda: ct.delete_trail(Name=name))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


def _trail_arn(ctx, name):
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cloudtrail:{ctx.region}:{account}:trail/{name}"


CHECK = "list-tags-multi-arn-positional-binding"
GROUP = 'tags'
SERVICES = ['cloudtrail']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTags returns one entry per ResourceIdList element, bound to its own trail's tags, past the
    documented 20-ARN limit; a batch with one unknown ARN fails whole with ResourceNotFoundException.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_ListTags.html
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
    _create_trail_bucket(s3, bucket, ctx.region, account)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    def make_trail():
        name = ctx.unique_name("sim2real-behav-ct-trail-")
        resp = _call(lambda: ct.create_trail(Name=name, S3BucketName=bucket))
        ctx.on_cleanup(lambda: _delete_trail(ct, name))
        arn = resp["TrailARN"]
        assert arn.endswith(f":trail/{name}"), arn
        assert arn == _trail_arn(ctx, name), (arn, _trail_arn(ctx, name))
        return name, arn

    name_a, arn_a = make_trail()
    name_b, arn_b = make_trail()
    assert arn_a != arn_b, (arn_a, arn_b)

    # The SAME key with DIFFERENT values on each trail: no flattened representation can
    # answer this correctly.
    tags_a = {"sim2real-which-trail": "a", "sim2real-only-on-a": "yes"}
    tags_b = {"sim2real-which-trail": "b", "sim2real-only-on-b": "yes"}

    for target_arn, target_tags in ((arn_a, tags_a), (arn_b, tags_b)):
        # Re-assert the minted ARN before mutating.
        assert target_arn in (arn_a, arn_b), target_arn
        _call(
            lambda: ct.add_tags(
                ResourceId=target_arn,
                TagsList=[{"Key": k, "Value": v} for k, v in target_tags.items()],
            )
        )

    def tag_map(resource_ids):
        """ListTags over resource_ids, returning {ResourceId: {key: value}}."""
        entries = []
        token = None
        for _ in range(20):
            if token:
                page = _call(lambda: ct.list_tags(ResourceIdList=resource_ids, NextToken=token))
            else:
                page = _call(lambda: ct.list_tags(ResourceIdList=resource_ids))
            entries.extend(page.get("ResourceTagList", []))
            token = page.get("NextToken")
            if not token:
                break
        assert not token, "ListTags did not terminate within 20 pages"
        # ResourceTagList is positional: one entry per ResourceIdList element, duplicates included.
        assert len(entries) == len(resource_ids), (
            f"ListTags returned {len(entries)} entries for {len(resource_ids)} ResourceIds; "
            f"the list is positional, one entry per input element"
        )
        return {e["ResourceId"]: {t["Key"]: t["Value"] for t in e.get("TagsList", [])} for e in entries}

    # One entry per ARN, each carrying only its own tags.
    both = tag_map([arn_a, arn_b])
    assert set(both) == {arn_a, arn_b}, sorted(both)
    assert both[arn_a] == tags_a, both[arn_a]
    assert both[arn_b] == tags_b, both[arn_b]

    # Reversing the input must not change the binding.
    reversed_call = tag_map([arn_b, arn_a])
    assert reversed_call == both, (reversed_call, both)

    # One ARN twice yields two entries, each with arn_a's tags undoubled: AWS does not dedupe.
    duplicated = tag_map([arn_a, arn_a])
    assert set(duplicated) == {arn_a}, sorted(duplicated)
    assert duplicated[arn_a] == tags_a, duplicated[arn_a]

    # Break exactly one thing: one well-formed ARN in the batch names no trail.
    unknown_arn = _trail_arn(ctx, ctx.unique_name("sim2real-behav-ct-nonexistent-"))
    unknown_message = f"Unknown trail: {unknown_arn} for the user: {account}"
    mixed = _error_response(lambda: ct.list_tags(ResourceIdList=[arn_a, unknown_arn]))
    assert mixed is not None, (
        "ListTags returned 200 for a batch containing an unresolvable ARN — partial "
        "success is over-permissive; real ListTags is all-or-nothing"
    )
    assert mixed["Error"]["Code"] == "ResourceNotFoundException", mixed["Error"]
    assert mixed["Error"].get("Message") == unknown_message, mixed["Error"]
    # Effect absent: no partial page of tags for the ARN that WAS valid.
    assert "ResourceTagList" not in mixed, mixed.get("ResourceTagList")

    # Same refusal with the unknown ARN first, so it is not position-dependent.
    flipped = _error_response(lambda: ct.list_tags(ResourceIdList=[unknown_arn, arn_b]))
    assert flipped is not None, "ListTags returned 200 for a batch led by an unresolvable ARN"
    assert flipped["Error"]["Code"] == "ResourceNotFoundException", flipped["Error"]
    assert flipped["Error"].get("Message") == unknown_message, flipped["Error"]

    # The documented 20-ARN limit is not enforced: 25 resolvable ARNs are neither truncated nor
    # collapsed.
    oversized = [arn_a, arn_b] * 12 + [arn_a]
    assert len(oversized) == 25, len(oversized)
    over = _call(lambda: ct.list_tags(ResourceIdList=oversized))
    entries = over["ResourceTagList"]
    assert len(entries) == 25, (
        f"ListTags returned {len(entries)} entries for a 25-element ResourceIdList; real AWS "
        f"does not enforce the documented 20-ARN limit and does not truncate"
    )
    assert not over.get("NextToken"), over.get("NextToken")
    # Every entry is still correctly BOUND, so the oversized list did not shift the pairing.
    by_id = {}
    for entry in entries:
        tags_for = {t["Key"]: t["Value"] for t in entry.get("TagsList", [])}
        assert by_id.setdefault(entry["ResourceId"], tags_for) == tags_for, entry
    assert by_id == both, (by_id, both)

    # The control case is unchanged after the refusals.
    final = tag_map([arn_a, arn_b])
    assert final == both, (final, both)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
