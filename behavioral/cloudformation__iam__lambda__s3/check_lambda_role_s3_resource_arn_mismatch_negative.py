"""lambda-role-s3-resource-arn-mismatch-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-role-s3-resource-arn-mismatch-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]

_MANAGED_TAG_KEY = "sim2real:managed"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role policy scoped to a different bucket ARN makes GetObject on the real bucket fail
    with AccessDenied and the exact implicit-deny message; fixing the ARN in the same policy makes
    the identical call return the object content."""
    bucket = _create_bucket(ctx)
    decoy_bucket_name = ctx.unique_name("sim2real-decoy-bkt-")  # never created; distinct ARN only
    s3 = ctx.client("s3")
    key = "mismatch.txt"
    content = "mismatch-test-" + ctx.unique_name("")
    s3.put_object(Bucket=bucket, Key=key, Body=content.encode("utf-8"))

    role = _create_role(ctx, _LAMBDA_TRUST_POLICY)
    _put_inline_policy(
        ctx,
        role["name"],
        "s3-scoped",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{decoy_bucket_name}/*"}
            ],
        },
    )
    fn = _create_function_with_retry(
        ctx, ctx.unique_name("sim2real-fn-"), role["arn"], _zip_bytes(_LAMBDA_HANDLER_S3)
    )

    denied = _invoke_until(
        ctx, fn, {"action": "get", "bucket": bucket, "key": key}, lambda r: r.get("ok") is False
    )
    assert denied["ok"] is False, denied
    assert denied["error"] == "AccessDenied", (
        f"expected AccessDenied for a role policy scoped to a different bucket ARN, got "
        f"{denied['error']!r}"
    )
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role['name']}/{fn} is not authorized to "
        f'perform: s3:GetObject on resource: "arn:aws:s3:::{bucket}/{key}" because no identity-based '
        f"policy allows the s3:GetObject action"
    )
    assert denied.get("message") == expected, f"expected {expected!r}, got {denied.get('message')!r}"
    # effect absent: the object's content is unchanged and unread via the function
    direct = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
    assert direct == content, f"expected the untouched object body {content!r}, got {direct!r}"

    # positive control: same role, same function, resource ARN fixed to the real bucket
    _put_inline_policy(
        ctx,
        role["name"],
        "s3-scoped",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}
            ],
        },
    )
    allowed = _invoke_until(
        ctx,
        fn,
        {"action": "get", "bucket": bucket, "key": key},
        lambda r: r.get("ok") is True,
        timeout_s=90,
    )
    assert allowed["ok"] is True, allowed
    assert allowed["body"] == content, (
        f"expected the real bucket's content {content!r} once the policy Resource ARN is fixed, "
        f"got {allowed['body']!r}"
    )


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
        Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"}],
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


def _put_inline_policy(ctx, role_name: str, policy_name: str, policy_doc: dict) -> None:
    ctx.client("iam").put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bkt-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": _MANAGED_TAG_KEY, "Value": "true"}]})
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
                Tags={_MANAGED_TAG_KEY: "true"},
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
