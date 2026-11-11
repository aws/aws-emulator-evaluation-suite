"""iam-role-policy-update-reflected-lambda-s3-access-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-role-policy-update-reflected-lambda-s3-access-positive"
GROUP = "permission-propagation"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function whose role lacks S3 permissions gets AccessDenied with the exact implicit-deny
    message on GetObject; after PutRolePolicy grants s3:GetObject, the same function reads the
    object content."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    key = "propagated.txt"
    content = "propagate-" + ctx.unique_name("")
    s3.put_object(Bucket=bucket, Key=key, Body=content.encode("utf-8"))

    role = _create_role(ctx, _LAMBDA_TRUST_POLICY)
    fn = _create_function_with_retry(
        ctx, ctx.unique_name("sim2real-fn-"), role["arn"], _zip_bytes(_LAMBDA_HANDLER_S3)
    )

    baseline = _invoke_until(
        ctx, fn, {"action": "get", "bucket": bucket, "key": key}, lambda r: r.get("ok") is not None
    )
    assert baseline["ok"] is False, baseline
    assert baseline["error"] == "AccessDenied"
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role['name']}/{fn} is not authorized to "
        f'perform: s3:GetObject on resource: "arn:aws:s3:::{bucket}/{key}" because no identity-based '
        f"policy allows the s3:GetObject action"
    )
    assert baseline.get("message") == expected, f"expected {expected!r}, got {baseline.get('message')!r}"

    ctx.client("iam").put_role_policy(
        RoleName=role["name"],
        PolicyName="s3-read",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}
                ],
            }
        ),
    )

    result = _invoke_until(
        ctx,
        fn,
        {"action": "get", "bucket": bucket, "key": key},
        lambda r: r.get("ok") is True,
        timeout_s=90,
    )
    assert result["ok"] is True, result
    assert result["body"] == content


_LAMBDA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

_LAMBDA_HANDLER_S3 = """
import boto3


def handler(event, context):
    action = event.get("action")
    bucket = event.get("bucket")
    key = event.get("key")
    s3 = boto3.client("s3")
    try:
        if action == "get":
            resp = s3.get_object(Bucket=bucket, Key=key)
            body = resp["Body"].read().decode("utf-8")
            return {"ok": True, "body": body}
        if action == "put":
            content = event.get("content", "")
            s3.put_object(Bucket=bucket, Key=key, Body=content.encode("utf-8"))
            return {"ok": True}
        return {"ok": False, "error": "bad-action"}
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None) or {}
        code = resp.get("Error", {}).get("Code", type(exc).__name__)
        return {"ok": False, "error": code, "message": resp.get("Error", {}).get("Message", str(exc))}
"""


def _zip_bytes(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_src)
    return buf.getvalue()


def _create_role(ctx, trust_policy: dict) -> dict[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    return {"name": name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role_permissions_boundary(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bkt-")
    # us-east-1 rejects an explicit LocationConstraint for its own region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _wait_active(ctx, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        resp = lam.get_function(FunctionName=name)
        state = resp["Configuration"]["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function {name} entered Failed state")
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active within {timeout_s}s")


def _create_function_with_retry(
    ctx, name: str, role_arn: str, zip_bytes: bytes, *, timeout_s: float = 120.0
) -> str:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "assum" in msg.lower():
                last_exc = exc
                time.sleep(4)
                continue
            raise
    else:
        assert last_exc is not None
        raise last_exc
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(ctx, name)
    return name


def _invoke(ctx, name: str, payload: dict) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode("utf-8"))
    return json.loads(resp["Payload"].read())


def _invoke_until(ctx, name, payload, predicate, timeout_s: float = 90.0, interval_s: float = 4.0):
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = _invoke(ctx, name, payload)
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
