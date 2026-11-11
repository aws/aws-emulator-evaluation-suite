"""lambda-sdk-s3-bucket-policy-deny-negative."""
from __future__ import annotations

import io
import json
import time
from typing import Any
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-s3-bucket-policy-deny-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "opensearch", "s3"]

_TAG_KEY = "sim2real:managed"
_TAG_VALUE = "lambda-sdk-s3-bucket-policy-deny-negative"

_HANDLER_CODE = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    s3 = boto3.client("s3")
    try:
        body = s3.get_object(Bucket=event["bucket"], Key=event["key"])["Body"].read()
        return {"ok": True, "body": body.decode("utf-8")}
    except ClientError as e:
        return {"ok": False, "code": e.response["Error"]["Code"], "message": e.response["Error"]["Message"]}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An explicit bucket-policy Deny for one key refuses a Lambda's IAM-permitted GetObject on that key
    with AccessDenied and the exact explicit-deny message, while the same role still reads another key."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    denied_key = "denied.txt"
    allowed_key = "allowed.txt"
    denied_body = b"should-never-be-readable"
    allowed_body = b"should-be-readable"
    s3.put_object(Bucket=bucket, Key=denied_key, Body=denied_body)
    s3.put_object(Bucket=bucket, Key=allowed_key, Body=allowed_body)

    # IAM allows GetObject on the whole bucket.
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
        }],
    }
    role_arn = _create_lambda_role(ctx, policy)

    # But a resource-based bucket policy explicitly denies that same role on the specific key.
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenySpecificKey",
            "Effect": "Deny",
            "Principal": {"AWS": role_arn},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/{denied_key}",
        }],
    }
    _put_bucket_policy_with_retry(s3, bucket, bucket_policy)
    ctx.on_cleanup(lambda: s3.delete_bucket_policy(Bucket=bucket))

    func_name = _create_lambda_function(ctx, role_arn, _HANDLER_CODE)

    # A bucket policy naming a just-created role's ARN as principal starts matching only once IAM
    # has propagated the new principal, which can take minutes, so poll until the Deny applies.
    denied = _poll_until(
        lambda: _invoke_lambda(ctx, func_name, {"bucket": bucket, "key": denied_key}),
        lambda r: r["ok"] is False,
        timeout_s=600.0,
        interval_s=5.0,
        description="the bucket-policy Deny to take effect for the Lambda role principal (S3/IAM propagation)",
    )
    assert denied["ok"] is False, denied
    account, role_name = role_arn.split(":")[4], role_arn.rsplit("/", 1)[1]
    expected = (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{func_name} is not authorized to "
        f'perform: s3:GetObject on resource: "arn:aws:s3:::{bucket}/{denied_key}" with an explicit '
        "deny in a resource-based policy"
    )
    assert (denied["code"], denied.get("message")) == ("AccessDenied", expected), denied
    assert "body" not in denied, denied  # effect absent: content was never retrieved

    # Positive control: same role, same function, same bucket -- a key the bucket policy does not deny.
    allowed = _invoke_lambda(ctx, func_name, {"bucket": bucket, "key": allowed_key})
    assert allowed["ok"] is True, allowed
    assert allowed["body"] == allowed_body.decode("utf-8"), allowed


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _put_bucket_policy_with_retry(s3, bucket: str, policy_doc: dict, timeout_s: float = 30.0) -> None:
    # A freshly-created IAM role's ARN can take a few seconds to become resolvable
    # as a bucket-policy principal (IAM read-after-write propagation delay), which
    # surfaces as MalformedPolicy: Invalid principal in policy. Retry through it.
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy_doc))
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "MalformedPolicy":
                last_err = e
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"put_bucket_policy failed (principal propagation?): {last_err}")

def _zip_from_source(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    return buf.getvalue()


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-lam-s3-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": _TAG_KEY, "Value": _TAG_VALUE}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _create_lambda_role(ctx, inline_policy_doc: dict | None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": _TAG_KEY, "Value": _TAG_VALUE}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    if inline_policy_doc is not None:
        policy_name = ctx.unique_name("sim2real-lam-pol-")
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, role_arn: str, handler_code: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    func_name = ctx.unique_name("sim2real-lam-fn-")
    zip_bytes = _zip_from_source(handler_code)
    last_err: Exception | None = None
    deadline = time.monotonic() + 90
    while True:
        try:
            ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags={_TAG_KEY: _TAG_VALUE},
            )
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidParameterValueException" and time.monotonic() < deadline:
                last_err = e
                time.sleep(3)
                continue
            raise AssertionError(f"lambda create_function failed (role propagation?): {last_err or e}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    _wait_for_active(ctx, func_name)
    return func_name


def _wait_for_active(ctx, func_name: str, timeout_s: float = 60.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        conf = lam.get_function_configuration(FunctionName=func_name)
        if conf["State"] == "Active":
            return
        if conf["State"] == "Failed":
            raise AssertionError(f"lambda function failed to become active: {conf}")
        time.sleep(2)
    raise AssertionError("lambda function never became active within timeout")


def _invoke_lambda(ctx, func_name: str, payload: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=func_name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation errored: {body}")
    return body


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
