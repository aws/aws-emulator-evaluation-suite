"""splunk-retry-duration-out-of-range-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.config import Config

from behavioral_harness import tags

CHECK = "splunk-retry-duration-out-of-range-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream rejects a Splunk RetryOptions.DurationInSeconds of -1 (outside [0,
    7200]) and creates no stream, while the boundary maximum 7200 is accepted."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    firehose = ctx.client("firehose")
    bad_name = ctx.unique_name("sim2real-behav-frh-bad-")
    bad_config = _splunk_config(role_arn, bucket_arn, retry_duration=-1)  # below the documented minimum of 0

    # RetryOptions.DurationInSeconds carries a [0, 7200] min/max on the Firehose model, so a
    # regular client rejects -1 with ParamValidationError before any request reaches the
    # network -- that would test botocore, not the service. Use a client with parameter
    # validation disabled so the out-of-range value actually reaches Firehose.
    raw = _unvalidated_client(ctx, "firehose")
    code, message = _error_code(lambda: raw.create_delivery_stream(
        DeliveryStreamName=bad_name, SplunkDestinationConfiguration=bad_config,
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value at "
        "'splunkDestinationConfiguration.retryOptions.durationInSeconds' failed to satisfy "
        "constraint: Member must have value greater than or equal to 0"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, not_found_message = _error_code(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"out-of-range request must not have created a stream, describe gave {not_found_code!r}"
    )
    expected_nf = f"Firehose under account {ctx.account} not found."
    assert not_found_message == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found_message!r}"
    )

    # Positive control: the boundary value 7200 (the documented maximum) is accepted.
    good_name = ctx.unique_name("sim2real-behav-frh-good-")
    good_config = _splunk_config(role_arn, bucket_arn, retry_duration=7200)
    ctx.on_cleanup(lambda: _safe(
        lambda: firehose.delete_delivery_stream(DeliveryStreamName=good_name, AllowForceDelete=True),
        "ResourceNotFoundException",
    ))
    _create_stream_with_role_retry(
        firehose, good_name, SplunkDestinationConfiguration=good_config,
    )
    desc = _wait_stream_active(ctx, good_name)
    splunk_desc = desc["Destinations"][0]["SplunkDestinationDescription"]
    actual_duration = splunk_desc["RetryOptions"]["DurationInSeconds"]
    assert actual_duration == 7200, f"expected boundary DurationInSeconds 7200, got {actual_duration!r}"


def _unvalidated_client(ctx, service: str):
    return ctx.client(
        service,
        config=Config(parameter_validation=False, retries={"max_attempts": 8, "mode": "standard"}),
    )



def _splunk_config(role_arn: str, bucket_arn: str, retry_duration: int) -> dict[str, Any]:
    return {
        "HECEndpoint": "https://203.0.113.11:8088/services/collector/event",
        "HECEndpointType": "Event",
        "HECToken": "00000000-0000-0000-0000-000000000000",
        "RetryOptions": {"DurationInSeconds": retry_duration},
        "S3BackupMode": "FailedEventsOnly",
        "S3Configuration": {"RoleARN": role_arn, "BucketARN": bucket_arn},
    }


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_stream_with_role_retry(firehose, name: str, timeout_s: float = 90.0, **kwargs) -> None:
    """Freshly created IAM roles can take a few seconds to become assumable by Firehose;
    retry CreateDeliveryStream until that propagation delay clears."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(DeliveryStreamName=name, **kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = str(exc).lower()
            role_not_ready = "not authorized" in msg or "unable to assume role" in msg
            if code == "InvalidArgumentException" and role_not_ready and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


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
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
