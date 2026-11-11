"""create-stream-conflicting-destinations-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "create-stream-conflicting-destinations-rejected"
GROUP = "server-side"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """S3DestinationConfiguration plus ExtendedS3DestinationConfiguration in one
    CreateDeliveryStream is rejected with InvalidArgumentException and creates no stream;
    either one alone succeeds."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    bad_name = ctx.unique_name("sim2real-behav-frh-bad-")
    firehose = ctx.client("firehose")
    code, message = _error_code(lambda: firehose.create_delivery_stream(
        DeliveryStreamName=bad_name,
        S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
        ExtendedS3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
    ))
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code!r}"
    expected = "Exactly one of S3DestinationConfiguration or ExtendedS3DestinationConfiguration must be specified."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, not_found_message = _error_code(lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"conflicting-destination request must not have created a stream, describe gave {not_found_code!r}"
    )
    expected = f"Firehose under account {ctx.account} not found."
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"
    listed = firehose.list_delivery_streams(Limit=10000)["DeliveryStreamNames"]
    assert bad_name not in listed, "rejected stream name unexpectedly appears in ListDeliveryStreams"

    # Positive control: exactly one destination configuration is accepted.
    good_name = ctx.unique_name("sim2real-behav-frh-good-")
    _create_s3_stream_with_retry(ctx, good_name, bucket, role_arn)
    desc = _wait_stream_active(ctx, good_name)
    assert desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"single-destination stream must become ACTIVE, got {desc['DeliveryStreamStatus']!r}"
    )


# ===== helpers =====

def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of its ClientError. An unexpected
    success raises, so a target accepting what AWS refuses cannot read as a mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn, *missing: str) -> None:
    """Run a teardown call; return quietly only on the given not-found codes, raise the rest."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in missing:
            raise


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-frh-")
    if ctx.region == "us-east-1":
        # us-east-1 is CreateBucket's implicit default region; passing a matching
        # LocationConstraint there is itself rejected, so it is only ever set for
        # every OTHER region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "firehose-behav"}]}
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(lambda: _safe(_cleanup, "NoSuchBucket"))
    return bucket


def _create_firehose_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-frh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "firehose-behav"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    policy_name = f"{role_name}-policy"
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject",
            ],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"))
    return role_arn


def _create_s3_stream_with_retry(
    ctx, name: str, bucket: str, role_arn: str, timeout_s: float = 90.0,
) -> None:
    from botocore.exceptions import ClientError

    firehose = ctx.client("firehose")
    s3_config: dict[str, Any] = {"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket}"}
    ctx.on_cleanup(lambda: _safe(
        lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True),
        "ResourceNotFoundException",
    ))
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                S3DestinationConfiguration=s3_config,
                Tags=[{"Key": "sim2real", "Value": "firehose-behav"}],
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = str(exc).lower()
            role_not_ready = "not authorized" in msg or "unable to assume role" in msg
            if code == "InvalidArgumentException" and role_not_ready and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _wait_stream_active(ctx, name: str, timeout_s: float = 120.0) -> dict[str, Any]:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status in ("CREATING_FAILED", "DELETING_FAILED"):
            raise AssertionError(f"delivery stream {name} entered {status}")
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
