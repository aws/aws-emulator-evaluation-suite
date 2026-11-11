"""create-trail-unknown-kms-key-rejected."""

from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

# The check creates no KMS key: a CMK bills monthly and its deletion waits at least 7 days.


def _error(fn):
    """Call fn() and return the (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected SUCCESS raises, so a target that accepts a call real AWS refuses fails loudly
    rather than reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]})
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


def _create_trail(ctx, ct, s3, name, **kwargs):
    """Create a trail (provisioning a policy-ready bucket unless S3BucketName is
    given) and register best-effort teardown of the trail and any bucket made."""
    bucket = kwargs.pop("S3BucketName", None)
    if not bucket:
        bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
        account = ctx.client("sts").get_caller_identity()["Account"]
        _create_trail_bucket(s3, bucket, ctx.region, account)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    params = {"Name": name, "S3BucketName": bucket, "TagsList": [
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]}
    params.update(kwargs)
    resp = _call(lambda: ct.create_trail(**params))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    return resp


CHECK = "create-trail-unknown-kms-key-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudtrail']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTrail and CreateTrail refuse an absent same-region key (ARN, bare UUID, alias) with
    InsufficientEncryptionPolicyException and a malformed or other-region key with KmsKeyNotFoundException,
    each with AWS's exact message; GetTrail still reports no KmsKeyId and no orphan trail exists.
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: an ordinary trail with default SSE-S3 encryption.
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    created = _create_trail(ctx, ct, s3, name)
    minted_arn = created["TrailARN"]
    assert minted_arn.endswith(f":trail/{name}"), minted_arn
    assert "KmsKeyId" not in created, created.get("KmsKeyId")

    def assert_unencrypted():
        """GetTrail must still report no CMK on the trail this check minted."""
        trail = _call(lambda: ct.get_trail(Name=name))["Trail"]
        assert trail["TrailARN"] == minted_arn, trail["TrailARN"]
        assert "KmsKeyId" not in trail, trail.get("KmsKeyId")
        return trail

    bucket = assert_unencrypted()["S3BucketName"]

    def policy_refusal(key_arn):
        return f"Insufficient permissions to access S3 bucket {bucket} or KMS key {key_arn}."

    def not_found_refusal(key_arn):
        return (
            f"KMS key ID {key_arn} does not exist, or s3 bucket {bucket} and key are not in the "
            "same region."
        )

    # A syntactically valid key ARN, right account, right region, naming nothing. A random
    # UUID is used rather than ctx.unique_name() because the KMS key-id grammar is a UUID:
    # a 12-hex-char name would be malformed and would pin the wrong refusal.
    absent_key = f"arn:aws:kms:{ctx.region}:{account}:key/{uuid.uuid4()}"

    # Break exactly one thing: the key does not exist. CloudTrail cannot read the policy of
    # a key it cannot resolve, and reports that as an ENCRYPTION-POLICY refusal.
    code, msg = _error(lambda: ct.update_trail(Name=name, KmsKeyId=absent_key))
    assert code == "InsufficientEncryptionPolicyException", code
    assert msg == policy_refusal(absent_key), msg
    # Effect absent: the refused update stored no key.
    assert_unencrypted()

    # A malformed identifier is a distinct refusal: CloudTrail expands the bare id into a
    # same-region key ARN and reports KmsKeyNotFoundException on the resulting identifier.
    code, msg = _error(lambda: ct.update_trail(Name=name, KmsKeyId="not-a-key-id"))
    assert code == "KmsKeyNotFoundException", code
    assert msg == not_found_refusal(f"arn:aws:kms:{ctx.region}:{account}:key/not-a-key-id"), msg
    assert_unencrypted()

    # An alias that resolves to nothing is likewise refused, not treated as "no key". Same
    # refusal as the absent key ARN: the alias is well-formed, so it is a lookup failure.
    alias = f"alias/{ctx.unique_name('sim2real-behav-ct-alias-')}"
    code, msg = _error(lambda: ct.update_trail(Name=name, KmsKeyId=alias))
    assert code == "InsufficientEncryptionPolicyException", code
    assert msg == policy_refusal(f"arn:aws:kms:{ctx.region}:{account}:{alias}"), msg
    assert_unencrypted()

    # A bare key UUID (no ARN) resolves in the trail's own region and is refused the same
    # way as the full same-region ARN — the identifier FORM does not change the verdict.
    bare_key = str(uuid.uuid4())
    code, msg = _error(lambda: ct.update_trail(Name=name, KmsKeyId=bare_key))
    assert code == "InsufficientEncryptionPolicyException", code
    assert msg == policy_refusal(f"arn:aws:kms:{ctx.region}:{account}:key/{bare_key}"), msg
    assert_unencrypted()

    # The same-account/other-region case: CloudTrail requires the key to be co-located with
    # the trail's S3 bucket, and that co-location failure is KmsKeyNotFoundException — a
    # DIFFERENT code from the same-region not-found case above, which is the whole point.
    other_region = "eu-west-1" if ctx.region != "eu-west-1" else "us-east-2"
    cross_region_key = f"arn:aws:kms:{other_region}:{account}:key/{uuid.uuid4()}"
    code, msg = _error(lambda: ct.update_trail(Name=name, KmsKeyId=cross_region_key))
    assert code == "KmsKeyNotFoundException", code
    assert msg == not_found_refusal(cross_region_key), msg
    assert_unencrypted()

    # CreateTrail applies the same validation, and must not leave an orphan trail behind.
    bucket = assert_unencrypted()["S3BucketName"]
    orphan = ctx.unique_name("sim2real-behav-ct-trail-")
    code, msg = _error(
        lambda: ct.create_trail(Name=orphan, S3BucketName=bucket, KmsKeyId=absent_key)
    )
    assert code == "InsufficientEncryptionPolicyException", code
    assert msg == policy_refusal(absent_key), msg
    orphan_code, orphan_msg = _error(lambda: ct.get_trail(Name=orphan))
    assert orphan_code == "TrailNotFoundException", orphan_code
    assert orphan_msg == f"Unknown trail: {orphan} for the user: {account}", orphan_msg
    listed = _call(lambda: ct.describe_trails(trailNameList=[orphan]))["trailList"]
    assert listed == [], listed

    # Control case still works: an unrelated field on the minted trail still updates, so
    # the refusals above were about the key and not about the trail being wedged.
    updated = _call(lambda: ct.update_trail(Name=name, S3KeyPrefix="kms-validation"))
    assert updated["TrailARN"] == minted_arn, updated["TrailARN"]
    final_prefix = _call(lambda: ct.get_trail(Name=name))["Trail"]["S3KeyPrefix"]
    assert final_prefix == "kms-validation", final_prefix


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
