"""lambda-role-permission-boundary-restricts-s3-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-role-permission-boundary-restricts-s3-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A permissions boundary excluding S3 makes the function's PutObject fail with AccessDenied and
    the exact "no permissions boundary allows" message despite an s3:* identity policy, leaving no
    object; removing the boundary lets the same write land."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    role = _create_role(ctx, _LAMBDA_TRUST_POLICY)
    _put_inline_policy(
        ctx,
        role["name"],
        "s3-full",
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
    )
    boundary_arn = _create_managed_policy(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "*",
                }
            ],
        },
    )
    iam.put_role_permissions_boundary(RoleName=role["name"], PermissionsBoundary=boundary_arn)

    fn = _create_function_with_retry(
        ctx, ctx.unique_name("sim2real-fn-"), role["arn"], _zip_bytes(_LAMBDA_HANDLER_S3)
    )

    key = "boundary.txt"
    denied = _invoke_until(
        ctx,
        fn,
        {"action": "put", "bucket": bucket, "key": key, "content": "should-not-land"},
        lambda r: r.get("ok") is False,
        timeout_s=60,
    )
    assert denied["ok"] is False, denied
    assert denied["error"] == "AccessDenied", (
        f"a boundary that excludes s3 must refuse s3:PutObject with AccessDenied despite the "
        f"broader s3:* identity policy; got {denied!r}"
    )
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role['name']}/{fn} is not authorized to "
        f'perform: s3:PutObject on resource: "arn:aws:s3:::{bucket}/{key}" because no permissions '
        f"boundary allows the s3:PutObject action"
    )
    assert denied.get("message") == expected, f"expected {expected!r}, got {denied.get('message')!r}"
    # effect absent: the object was never written
    head_code = _error_code(lambda: s3.head_object(Bucket=bucket, Key=key))
    assert head_code == "404", (
        f"the boundary-denied PutObject must leave no object behind; HeadObject returned "
        f"{head_code!r} instead of 404"
    )

    # positive control: drop the boundary, the broad identity policy now applies unrestricted
    iam.delete_role_permissions_boundary(RoleName=role["name"])
    allowed = _invoke_until(
        ctx,
        fn,
        {"action": "put", "bucket": bucket, "key": key, "content": "now-allowed"},
        lambda r: r.get("ok") is True,
        timeout_s=90,
    )
    assert allowed["ok"] is True, allowed
    landed = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
    assert landed == "now-allowed", (
        f"with the boundary detached the identical write must succeed and round-trip its bytes; "
        f"read back {landed!r} instead of 'now-allowed'"
    )


_MANAGED_TAG_KEY = "sim2real:managed"


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real"}]


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
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_tags_kv()
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


def _create_managed_policy(ctx, policy_doc: dict) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-policy-")
    resp = iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(policy_doc), Tags=_tags_kv())
    arn = resp["Policy"]["Arn"]
    ctx.on_cleanup(lambda: _delete_managed_policy(ctx, arn))
    return arn


def _delete_managed_policy(ctx, arn: str) -> None:
    try:
        ctx.client("iam").delete_policy(PolicyArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bkt-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _tags_kv()})
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


def _error_code(fn) -> str:
    """Return the code of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError("expected the call to be refused, but it succeeded")


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
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real"},
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
    raise AssertionError(
        f"invoking {name} with {payload!r} never satisfied the expected condition within "
        f"{timeout_s}s; last observed response was {last!r}"
    )


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
