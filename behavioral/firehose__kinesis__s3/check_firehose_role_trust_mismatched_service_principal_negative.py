"""firehose-role-trust-mismatched-service-principal-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "firehose-role-trust-mismatched-service-principal-negative"
GROUP = "overly-permissive"
SERVICES = ["firehose", "kinesis", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """CreateDeliveryStream with a role trusting lambda.amazonaws.com fails with InvalidArgumentException and its exact
    message and leaves no stream or delivery; Lambda accepts that role, and a Firehose-trusting role delivers."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")
    lambda_client = ctx.client("lambda")

    bucket = _create_bucket(ctx, s3, "sim2real-fhwrongsvc-dst")
    write_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }

    # --- break exactly one thing: trust lambda.amazonaws.com instead of firehose ---
    role_name = ctx.unique_name("sim2real-fhwrongsvc-role-")
    role_arn = _create_role(ctx, iam, role_name, "lambda.amazonaws.com", write_policy)

    bad_stream_name = ctx.unique_name("sim2real-fhwrongsvc-stream-")
    code, message = _error(lambda: firehose.create_delivery_stream(
        DeliveryStreamName=bad_stream_name,
        DeliveryStreamType="DirectPut",
        S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket}"},
    ))
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException for a role trusting the wrong service, got {code!r}"
    want = f"Firehose is unable to assume role {role_arn}. Please check the role provided."
    assert message == want, f"expected {want!r}, got {message!r}"
    describe_code, describe_message = _error(lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_stream_name))
    assert describe_code == "ResourceNotFoundException", f"expected the rejected stream to never exist, describe returned {describe_code!r}"
    want_describe = f"Firehose under account {ctx.account} not found."
    assert describe_message == want_describe, f"expected {want_describe!r}, got {describe_message!r}"
    contents_after_reject = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    assert contents_after_reject == [], f"expected no delivery after a rejected CreateDeliveryStream, bucket has {contents_after_reject!r}"

    # --- proof the role itself is fine: its ACTUALLY-trusted service accepts it ---
    fn_name = ctx.unique_name("sim2real-fhwrongsvc-fn-")
    _create_function_with_retry(ctx, lambda_client, fn_name, role_arn)

    # --- positive control: a role that correctly trusts firehose.amazonaws.com works ---
    good_role_name = ctx.unique_name("sim2real-fhwrongsvc-good-role-")
    good_role_arn = _create_role(ctx, iam, good_role_name, "firehose.amazonaws.com", write_policy)
    good_stream_name = ctx.unique_name("sim2real-fhwrongsvc-good-stream-")
    _create_delivery_stream_with_retry(
        firehose, good_stream_name, good_role_arn, f"arn:aws:s3:::{bucket}",
        buffering={"IntervalInSeconds": 60, "SizeInMBs": 1},
    )
    ctx.on_cleanup(lambda: _delete_stream(firehose, good_stream_name))
    _wait_stream_active(firehose, good_stream_name)

    marker = ctx.unique_name("payload-")
    firehose.put_record(DeliveryStreamName=good_stream_name, Record={"Data": f"hello-{marker}\n".encode()})
    # A new stream's first flush can take 150-185 s despite the 60 s buffering hint, so the
    # poll allows 220 s, which keeps the whole body under the 300 s check budget.
    contents = _poll_for_object(s3, bucket, timeout_s=220)
    assert contents, "positive control: correctly-trusted role never delivered to S3 within 220s"


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_bucket(ctx: Any, s3, prefix: str) -> str:
    name = ctx.unique_name(f"{prefix}-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                    for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_role(ctx: Any, iam, name: str, principal: str, policy_doc: dict) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": principal},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    if policy_doc:
        iam.put_role_policy(RoleName=name, PolicyName=f"{name}-policy", PolicyDocument=json.dumps(policy_doc))
    return arn


def _delete_role(iam, name: str) -> None:
    try:
        for p in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=p)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _simple_lambda_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return 'ok'\n")
    return buf.getvalue()


def _create_function_with_retry(ctx: Any, lambda_client, name: str, role_arn: str, timeout_s: float = 90.0) -> None:
    """CreateFunction can transiently fail right after CreateRole because the role's
    trust policy has not finished propagating to Lambda yet; retry on that specific
    error rather than treating it as a real assumability failure."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            lambda_client.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _simple_lambda_zip()},
                Timeout=10,
            )
            ctx.on_cleanup(lambda: _delete_function(lambda_client, name))
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "").lower()
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                last_err = e
                time.sleep(5)
                continue
            raise
    assert last_err is not None, "loop exited without ever recording a retryable ClientError"
    raise AssertionError(
        "expected Lambda to accept the role as an execution role (it trusts "
        f"lambda.amazonaws.com); CreateFunction kept failing: {last_err}"
    )


def _delete_function(lambda_client, name: str) -> None:
    try:
        lambda_client.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_delivery_stream_with_retry(
    firehose, name: str, role_arn: str, bucket_arn: str,
    buffering: dict | None = None, timeout_s: float = 90.0,
) -> None:
    s3_config: dict[str, Any] = {"RoleARN": role_arn, "BucketARN": bucket_arn}
    if buffering:
        s3_config["BufferingHints"] = buffering
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration=s3_config,
            )
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "").lower()
            if code == "InvalidArgumentException" and "assume role" in msg:
                last_err = e
                time.sleep(5)
                continue
            raise
    assert last_err is not None, "loop exited without ever recording a retryable ClientError"
    raise last_err


def _wait_stream_active(firehose, name: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)
        status = desc["DeliveryStreamDescription"]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        if status == "CREATING_FAILED":
            raise AssertionError("delivery stream entered CREATING_FAILED")
        time.sleep(interval_s)
    raise AssertionError("delivery stream never became ACTIVE")


def _delete_stream(firehose, name: str) -> None:
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_for_object(s3, bucket: str, prefix: str = "", timeout_s: float = 180.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        contents = resp.get("Contents", [])
        if contents:
            return contents
        time.sleep(interval_s)
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
