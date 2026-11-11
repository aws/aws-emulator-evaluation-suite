"""lambda-sdk-s3-presigned-url-generation-positive."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
from typing import Any
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-s3-presigned-url-generation-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "opensearch", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Lambda generates a real S3 presigned GET URL, signed with its execution role, that an external HTTP GET can fetch."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    key = "presign.txt"
    payload = b"presigned-content-abc123"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/{key}",
        }],
    }
    role_arn = _create_lambda_role(ctx, policy)

    handler_code = """
import boto3

def handler(event, context):
    s3 = boto3.client("s3")
    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": event["bucket"], "Key": event["key"]},
        ExpiresIn=300,
    )
    return {"url": url}
"""
    func_name = _create_lambda_function(ctx, role_arn, handler_code)
    result = _invoke_lambda(ctx, func_name, {"bucket": bucket, "key": key})
    url = result["url"]
    assert not (p := ctx.published_url_mismatch(url)), p

    try:
        target, route = ctx.endpoint_route(url)
        with urllib.request.urlopen(urllib.request.Request(target, headers=route), timeout=30) as resp:
            fetched = resp.read()
    except urllib.error.HTTPError as e:
        raise AssertionError(f"presigned URL GET failed: HTTP {e.code} {e.read()!r}") from e

    assert fetched == payload, f"expected {payload!r}, got {fetched!r}"


_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}]


def _zip_from_source(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    return buf.getvalue()


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-lam-s3-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # S3 CreateBucket rejects LocationConstraint == us-east-1
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _resource_tags_kv()})
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_resource_tags_kv())
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
                Tags={_MANAGED_TAG_KEY: "true"},
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
