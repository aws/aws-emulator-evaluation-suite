"""put-insight-selectors-rejects-insufficient-kms-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-insight-selectors-rejects-insufficient-kms-policy"
GROUP = "server-side"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutInsightSelectors re-validates the trail's KMS key policy: after CloudTrail's grants are
    revoked it fails InsufficientEncryptionPolicyException without changing the selectors, and
    succeeds again once the policy is restored."""
    ct = ctx.client("cloudtrail")
    kms = ctx.client("kms")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    account = sts.get_caller_identity()["Account"]
    region = ctx.region

    bucket = ctx.unique_name("sim2rbeh-ct-").lower().replace("_", "-")
    trail_name = ctx.unique_name("sim2rbeh-trail-")
    trail_arn = f"arn:aws:cloudtrail:{region}:{account}:trail/{trail_name}"

    _create_bucket(ctx, s3, bucket, region)
    bucket_policy = {
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
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account}/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy))

    root_principal_stmt = {
        "Sid": "EnableIAMUserPermissions",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
        "Action": "kms:*",
        "Resource": "*",
    }
    full_key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            root_principal_stmt,
            {
                "Sid": "AllowCloudTrailToEncryptLogs",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "kms:GenerateDataKey*",
                "Resource": "*",
                "Condition": {
                    "StringLike": {"aws:SourceArn": trail_arn},
                    "StringEquals": {"aws:SourceAccount": account},
                },
            },
            {
                "Sid": "AllowCloudTrailToDescribeKey",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "kms:DescribeKey",
                "Resource": "*",
            },
            {
                "Sid": "AllowPrincipalsInAccountToDecrypt",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": ["kms:Decrypt", "kms:ReEncryptFrom"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"kms:CallerAccount": account},
                    "StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": trail_arn},
                },
            },
        ],
    }

    key = kms.create_key(
        Description=f"sim2real-behav CloudTrail key for {trail_name}",
        Policy=json.dumps(full_key_policy),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    create_resp = ct.create_trail(
        Name=trail_name,
        S3BucketName=bucket,
        KmsKeyId=key_id,
        TagsList=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    # CreateTrail's response echoes the KMS key as a fully-specified ARN even though the
    # request was made with a bare key ID.
    assert create_resp["KmsKeyId"] == key_arn, (
        f"expected CreateTrail to echo the fully-specified key ARN {key_arn!r}, "
        f"got {create_resp['KmsKeyId']!r}"
    )
    ctx.on_cleanup(lambda: ct.delete_trail(Name=trail_name))

    got = ct.get_trail(Name=trail_name)["Trail"]
    assert got["KmsKeyId"] == key_arn, (
        f"expected GetTrail to report the fully-specified key ARN {key_arn!r}, "
        f"got {got['KmsKeyId']!r}"
    )

    # CloudTrail adds server-populated fields (e.g. EventCategory), so compare InsightType only.
    ok_resp = ct.put_insight_selectors(
        TrailName=trail_name, InsightSelectors=[{"InsightType": "ApiCallRateInsight"}]
    )
    assert _insight_types(ok_resp["InsightSelectors"]) == ["ApiCallRateInsight"], (
        f"unexpected insight selectors: {ok_resp['InsightSelectors']!r}"
    )
    confirmed = ct.get_insight_selectors(TrailName=trail_name)["InsightSelectors"]
    assert _insight_types(confirmed) == ["ApiCallRateInsight"], (
        f"unexpected insight selectors: {confirmed!r}"
    )

    # Keep account-root access so cleanup can still manage the key.
    minimal_key_policy = {"Version": "2012-10-17", "Statement": [root_principal_stmt]}
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(minimal_key_policy))

    def _put_two_selectors():
        ct.put_insight_selectors(
            TrailName=trail_name,
            InsightSelectors=[
                {"InsightType": "ApiCallRateInsight"},
                {"InsightType": "ApiErrorRateInsight"},
            ],
        )

    # A key policy revocation takes ~20s to reach CloudTrail's check; an immediate attempt is
    # still accepted, so wait past that with margin (re-attempting is idempotent).
    import time

    refusal = None
    for delay in (25, 20):
        time.sleep(delay)
        try:
            _put_two_selectors()
        except ClientError as err:
            # Acceptance is a legitimate intermediate outcome while the revocation propagates.
            refusal = (err.response["Error"].get("Code"), err.response["Error"].get("Message"))
            break
    if refusal is None:
        raise AssertionError(
            "PutInsightSelectors did not re-validate the revoked KMS key policy even 45s "
            "after PutKeyPolicy returned"
        )
    code, message = refusal
    assert code == "InsufficientEncryptionPolicyException", (
        f"expected InsufficientEncryptionPolicyException, got {code!r}"
    )
    assert message == (
        f"Insufficient permissions to access S3 bucket {bucket} or KMS key {key_arn}."
    ), message

    after = ct.get_insight_selectors(TrailName=trail_name)["InsightSelectors"]
    assert _insight_types(after) == ["ApiCallRateInsight"], (
        f"insight selectors were mutated despite the rejected call: {after!r}"
    )

    # The restored key policy is not instantly visible to CloudTrail, so retry on a bounded window.
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(full_key_policy))

    def _retry_identical_call():
        try:
            _put_two_selectors()
        except ClientError:
            return False
        return True

    restored = _poll_until(_retry_identical_call, lambda ok: ok, timeout=120, interval=5)
    assert restored, "PutInsightSelectors still rejected the identical call after the KMS key policy was restored"

    final = ct.get_insight_selectors(TrailName=trail_name)["InsightSelectors"]
    assert _insight_types(final) == ["ApiCallRateInsight", "ApiErrorRateInsight"], (
        f"expected both insight types enabled after restoring the KMS key policy, got {final!r}"
    )


def _poll_until(fetch, predicate, timeout=30, interval=2):
    import time

    deadline = time.monotonic() + timeout
    result = fetch()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval)
        result = fetch()
    return result


def _insight_types(selectors):
    """Sorted InsightType values, ignoring server-populated fields such as EventCategory."""
    return sorted(s["InsightType"] for s in selectors)


def _create_bucket(ctx, s3, bucket, region):
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))


def _delete_bucket(s3, bucket):
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
