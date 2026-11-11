"""lambda-without-s3-permission-denied."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-without-s3-permission-denied"

GROUP = "overly-permissive"

SERVICES = ["dynamodb", "lambda", "s3"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function whose role has no S3 permission gets AccessDenied from PutObject and leaves no object, while a
    granted twin's object lands; once the same role is granted, the same call's object is readable at S3. A
    revoke can take minutes to apply, so the role starts ungranted and is only ever granted.
    """
    bucket = _create_bucket(ctx)
    key = "denied.txt"
    code = f'''
import boto3
from botocore.exceptions import ClientError
s3 = boto3.client("s3")

def lambda_handler(event, context):
    try:
        s3.put_object(Bucket="{bucket["name"]}", Key="{key}", Body=b"x")
        return {{"ok": True}}
    except ClientError as e:
        return {{"ok": False, "error": e.response["Error"]["Code"]}}
'''
    iam = ctx.client("iam")
    s3_client = ctx.client("s3")
    grant_name = "s3-put"
    grant_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"{bucket['arn']}/*"}
        ],
    })
    logs_statement = {
        "Effect": "Allow",
        "Action": [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
        ],
        "Resource": "arn:aws:logs:*:*:*",
    }

    def make_role_and_function(*, granted: bool) -> tuple[dict[str, str], dict[str, str]]:
        statements = [logs_statement]
        if granted:
            statements.append(json.loads(grant_doc)["Statement"][0])
        role = _create_role(
            ctx,
            "lambda.amazonaws.com",
            inline_policy={"Version": "2012-10-17", "Statement": statements},
        )
        fn = _create_function_with_retry(ctx, code, role["arn"], {})
        return role, fn

    def object_exists() -> bool:
        try:
            s3_client.head_object(Bucket=bucket["name"], Key=key)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] in ("404", "NoSuchKey", "NotFound"):
                return False
            raise

    def invoke_ok(fn: dict[str, str]) -> bool:
        r = _invoke_lambda(ctx, fn["name"], {})
        return r["payload"]["ok"]

    # --- Positive control: an independently-provisioned, already-granted Lambda succeeds, and the
    #     object is independently observable at S3 -- the bucket, role and function wiring here are
    #     healthy before anything is concluded from the target's denial below.
    _control_role, control_fn = make_role_and_function(granted=True)
    control_ok = _poll_until(
        lambda: invoke_ok(control_fn),
        lambda v: v is True,
        timeout_s=60,
        interval_s=3,
        description="positive control: an already-granted role allows PutObject",
    )
    assert control_ok is True, f"expected PutObject to succeed with a granted role, got ok={control_ok!r}"
    assert object_exists(), "positive control: PutObject succeeded but the object is not visible at S3"
    s3_client.delete_object(Bucket=bucket["name"], Key=key)

    # --- Break exactly one thing: the target's role is provisioned with NO S3 permission at all.
    target_role, target_fn = make_role_and_function(granted=False)
    result = _invoke_lambda(ctx, target_fn["name"], {})
    assert result["payload"]["ok"] is False, (
        f"expected PutObject to be denied for a role with no S3 permission, got {result['payload']!r}"
    )
    assert result["payload"]["error"] == "AccessDenied", (
        f"expected an access-denied error code, got {result['payload'].get('error')!r}"
    )
    assert not object_exists(), "the denied PutObject must leave no object at the destination"

    # --- Restore: grant the target's role, and demand the IDENTICAL call then succeeds.
    iam.put_role_policy(RoleName=target_role["name"], PolicyName=grant_name, PolicyDocument=grant_doc)
    restored = _poll_until(
        lambda: invoke_ok(target_fn),
        lambda v: v is True,
        timeout_s=60,
        interval_s=3,
        description="restore: granting the target's role allows PutObject",
    )
    assert restored is True, f"expected PutObject to succeed once the target's role is granted, got ok={restored!r}"
    assert object_exists(), "after restoring the grant, the object must be independently observable at S3"


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    # No unconditional wait here: IAM trust/permission propagation is covered by the bounded
    # retry in _create_function_with_retry ("cannot be assumed") and by the check's own
    # _poll_until on each grant/revoke, both with a stated deadline.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
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
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """S3 buckets must be emptied before deletion — a raw delete_bucket on a non-empty bucket fails
    with BucketNotEmpty and leaks the bucket. Purge objects AND all
    versions/delete-markers (versioning may be on), then delete."""
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError:
        try:
            p2 = s3.get_paginator("list_objects_v2")
            for page in p2.paginate(Bucket=bucket):
                keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if keys:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
    s3.delete_bucket(Bucket=bucket)


def _wait_function_active(ctx, name: str, timeout_s: float = 60) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
) -> dict[str, str]:
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.
    Registers the function's teardown (LIFO-before its role, as the role was registered first)."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    # Dedent the inline handler and alias `handler` to the fixed "lambda_function.lambda_handler"
    # entrypoint; without that symbol the function fails with Runtime.HandlerNotFound.
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs: dict[str, Any] = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The function creates /aws/lambda/<name> on its first invoke and that log group
            # outlives the function, so it is deleted too.
            ctx.on_cleanup(
                lambda: ctx.client("logs").delete_log_group(
                    logGroupName=f"/aws/lambda/{name}"
                )
            )
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _invoke_lambda(ctx, name: str, payload: dict | None = None) -> dict[str, Any]:
    """Invoke a Lambda synchronously; return {status_code[, error], payload|payload_raw}."""
    resp = ctx.client("lambda").invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode(),
    )
    body = resp["Payload"].read()
    result: dict[str, Any] = {"status_code": resp["StatusCode"]}
    if resp.get("FunctionError"):
        result["error"] = resp["FunctionError"]
    try:
        result["payload"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        result["payload_raw"] = body.decode("utf-8", errors="replace")
    return result


def _create_bucket(ctx) -> dict[str, str]:
    """Create an S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":  # us-east-1 is the one region CreateBucket rejects a
        # LocationConstraint for -- an AWS API constant, not a hardcoded target region.
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    except ClientError:
        pass
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
