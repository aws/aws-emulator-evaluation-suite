"""create-stream-http-endpoint-url-not-https-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Optional

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-stream-http-endpoint-url-not-https-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream rejects an HttpEndpointDestinationConfiguration whose endpoint
    URL does not start with "https://", and never creates the stream; an identical
    configuration with an https:// URL succeeds."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    bucket_name, bucket_arn = _create_bucket(ctx, s3)
    role_arn = _create_role(ctx, iam, bucket_arn)

    def _http_endpoint_config(url: str) -> dict:
        return {
            "EndpointConfiguration": {"Url": url, "Name": "sim2real-http-endpoint"},
            "S3Configuration": {"RoleARN": role_arn, "BucketARN": bucket_arn},
            "RoleARN": role_arn,
        }

    # Positive control FIRST: the warmed-up role and an https:// URL succeed.
    good_stream_name = ctx.unique_name("sim2real-behav-fhhttp-good-")
    _create_delivery_stream_with_retry(
        firehose,
        DeliveryStreamName=good_stream_name,
        DeliveryStreamType="DirectPut",
        HttpEndpointDestinationConfiguration=_http_endpoint_config("https://example.com/firehose"),
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stream_and_confirm_gone(firehose, good_stream_name))
    status = _wait_for_stream_status(ctx, firehose, good_stream_name, {"ACTIVE", "CREATING_FAILED"})
    assert status == "ACTIVE", f"expected positive control to reach ACTIVE, got {status}"

    # Negative: same warmed-up role and S3 backup config, a non-https URL.
    bad_stream_name = ctx.unique_name("sim2real-behav-fhhttp-bad-")
    code, message = _error_code_and_message(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=bad_stream_name,
            DeliveryStreamType="DirectPut",
            HttpEndpointDestinationConfiguration=_http_endpoint_config("http://example.com/firehose"),
            Tags=[{"Key": "simparity-check", "Value": CHECK}],
        )
    )
    # The URL's `^https://` pattern trait is enforced as a request-shape constraint, reported
    # as ValidationException, not the business-logic InvalidArgumentException.
    assert code == "ValidationException", f"CODE={code}"
    expected = (
        "1 validation error detected: Value at "
        "'httpEndpointDestinationConfiguration.endpointConfiguration.url' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: https://.*"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, not_found_message = _error_code_and_message(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_stream_name)
    )
    assert not_found_code == "ResourceNotFoundException", f"expected stream absent, got {not_found_code}"
    expected_nf = f"Firehose under account {ctx.account} not found."
    assert not_found_message == expected_nf, f"expected message {expected_nf!r}, got {not_found_message!r}"


def _error_code_and_message(fn: Callable[[], Any]) -> tuple[Optional[str], str]:
    """Call fn(); return (Error.Code, Error.Message) on ClientError. An unexpected SUCCESS
    raises -- an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message") or ""
    raise AssertionError(f"expected a ClientError, call succeeded and returned {result!r}")


def _create_bucket(ctx, s3) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-behav-fhhttpbkt-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name, f"arn:aws:s3:::{name}"


def _create_role(ctx, iam, bucket_arn: str) -> str:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_name = ctx.unique_name("sim2real-behav-fhhttprole-")
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_name = f"{role_name}-policy"
    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:PutObjectAcl", "s3:GetBucketLocation", "s3:ListBucket"],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(access_policy))

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _delete_stream_and_confirm_gone(firehose, name: str, *, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    """Delete the stream and poll until DescribeDeliveryStream reports it gone."""
    firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} was not gone within {timeout_s}s of delete")


def _create_delivery_stream_with_retry(firehose, *, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs) -> dict:
    """Retries while a brand-new role's trust policy is still propagating."""
    deadline = time.monotonic() + timeout_s
    last_err: Optional[Exception] = None
    while time.monotonic() < deadline:
        try:
            return firehose.create_delivery_stream(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"create_delivery_stream kept failing with InvalidArgumentException: {last_err}")


def _wait_for_stream_status(ctx, firehose, name: str, terminal_statuses, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} did not reach a terminal status in {timeout_s}s, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
