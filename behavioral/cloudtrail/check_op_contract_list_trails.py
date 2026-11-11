"""op-contract-list-trails."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-list-trails"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTrails surfaces a created trail; a caller with zero IAM permissions is denied."""
    ct = ctx.client("cloudtrail")
    bucket, _account_id = _create_trail_bucket(ctx)
    name = ctx.unique_name("sim2real-ct-trail-")
    trail_arn = _create_trail_retrying(
        ct, Name=name, S3BucketName=bucket, TagsList=[{"Key": "sim2real", "Value": name}]
    )["TrailARN"]
    ctx.on_cleanup(lambda: _delete_trail(ct, name))

    listed = ct.list_trails()["Trails"]
    matches = [t for t in listed if t["Name"] == name]
    assert len(matches) == 1
    assert matches[0]["TrailARN"] == trail_arn
    assert matches[0]["HomeRegion"] == ctx.region

    # Error boundary: a brand-new IAM identity with no attached policies is denied on
    # ListTrails (default-deny), unlike our own (permitted) caller above.
    iam = ctx.client("iam")
    user_name, denied_client = _make_unprivileged_client(ctx)
    code, message = _wait_for_denied(lambda: denied_client.list_trails())
    assert code == "AccessDeniedException", code
    expected_message = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        "cloudtrail:ListTrails because no identity-based policy allows the "
        "cloudtrail:ListTrails action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Granting ListTrails to the same identity must make the same call succeed.
    policy_name = "sim2real-ct-allow-list-trails"
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "cloudtrail:ListTrails", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    restored = _wait_for_allowed(lambda: denied_client.list_trails())
    restored_matches = [t for t in restored["Trails"] if t["Name"] == name]
    assert len(restored_matches) == 1, (
        f"expected the now-permitted identity's ListTrails to surface {name!r}, got "
        f"{restored['Trails']!r}"
    )


def _error(fn):
    """Call fn() and return its Error (code, message); raise if it succeeds.

    An identity with no attached policy is never allowed ListTrails.
    """
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"ListTrails by an identity with no attached policy succeeded and returned {result!r}"
    )


def _wait_for_denied(fn, timeout_s=90.0, interval_s=3.0):
    # Polls because new IAM access keys propagate eventually.
    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        last = _error(fn)
        if last[0] == "AccessDeniedException":
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"IAM access-key propagation never converged to AccessDenied, last={last}",
    )


def _wait_for_allowed(fn, timeout_s=90.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
        time.sleep(interval_s)
    raise AssertionError(
        f"granted policy never converged to an allowed ListTrails call, last={last_code}",
    )


def _make_unprivileged_client(ctx):
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-ct-nopolicy-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": user_name}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    client = ctx.client(
        "cloudtrail",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )
    return user_name, client


def _bucket_policy(bucket: str, account_id: str) -> dict:
    return {
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
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }


def _create_trail_bucket(ctx):
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-ct-").lower().replace("_", "-")
    # S3 CreateBucket in us-east-1 rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(_bucket_policy(bucket, account_id)))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket, account_id


def _create_trail_retrying(ct, **kwargs):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(6):
        try:
            return ct.create_trail(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InsufficientS3BucketPolicyException":
                raise
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _delete_trail(ct, name):
    from botocore.exceptions import ClientError

    try:
        ct.stop_logging(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise
    try:
        ct.delete_trail(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
