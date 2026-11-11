"""s3-notification-missing-invoke-permission-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-notification-missing-invoke-permission-negative"

GROUP = "overly-permissive"

SERVICES = ["lambda", "s3", "stepfunctions"]


@tags("axis:rejection", "cap:c1", "concern:eventing", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketNotificationConfiguration must be rejected while the target Lambda has no
    resource policy granting s3.amazonaws.com invoke rights; granting that permission must make
    the IDENTICAL call succeed and the wiring actually deliver."""
    bucket = _create_bucket(ctx)
    bucket_name = bucket["name"]
    bucket_arn = bucket["arn"]

    handler_code = """
import boto3, json, os
def lambda_handler(event, context):
    s3 = boto3.client('s3')
    s3.put_object(Bucket=os.environ['BUCKET_NAME'], Key='triggered/marker.txt', Body='triggered')
    return {'triggered': True}
"""
    fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        permissions=[
            {"Action": ["s3:PutObject"], "Resource": f"{bucket_arn}/*"},
        ],
        env={"BUCKET_NAME": bucket_name},
    )
    # Intentionally NOT calling add_permission yet — the config below must be rejected
    # before any Lambda invoke permission exists.

    s3 = ctx.client("s3")
    notification_config = {
        "LambdaFunctionConfigurations": [
            {"LambdaFunctionArn": fn["arn"], "Events": ["s3:ObjectCreated:*"]}
        ]
    }

    def configure():
        return s3.put_bucket_notification_configuration(
            Bucket=bucket_name, NotificationConfiguration=notification_config
        )

    err, message = _error_code(configure)
    assert err == "InvalidArgument", (
        f"Unexpected error code for missing invoke permission: {err!r}: {message!r}"
    )
    assert message == "Unable to validate the following destination configurations", (
        f"Unexpected InvalidArgument message for missing invoke permission: {message!r}"
    )

    # Independent read (a different operation than the rejected mutation): the rejected
    # call must not have persisted any configuration.
    persisted = s3.get_bucket_notification_configuration(Bucket=bucket_name)
    assert not persisted.get("LambdaFunctionConfigurations"), (
        f"Rejected notification config was persisted anyway: {persisted}"
    )

    # Restore: grant the missing invoke permission, then retry the IDENTICAL call.
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId="s3-invoke",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn=bucket_arn,
    )
    # S3 validates the destination against the function policy, which propagates
    # eventually: retry the identical call on InvalidArgument for a bounded window.
    deadline = time.monotonic() + 120
    while True:
        try:
            configure()
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidArgument" or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    persisted = s3.get_bucket_notification_configuration(Bucket=bucket_name)
    assert persisted.get("LambdaFunctionConfigurations"), (
        "Identical call must succeed once invoke permission is granted"
    )

    # Positive control / delivery proof: the now-permitted wiring must actually deliver —
    # this is what separates "correctly blocked" from "no delivery path at all".
    s3.put_object(Bucket=bucket_name, Key="trigger.txt", Body="test")

    def list_triggered():
        resp = s3.list_objects_v2(Bucket=bucket_name, Prefix="triggered/")
        return resp.get("Contents", [])

    objects = _poll_until(
        list_triggered,
        lambda objs: len(objs) > 0,
        timeout_s=90,
        interval_s=5,
        description="Lambda invocation marker after granting invoke permission",
    )
    keys = [o["Key"] for o in objects]
    assert "triggered/marker.txt" in keys, (
        f"Lambda was never invoked even after granting invoke permission; found {keys}"
    )


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


def _error_code(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises — real AWS
    refuses this call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"put_bucket_notification_configuration should be rejected without invoke permission, "
        f"but it SUCCEEDED and returned {result!r}"
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
    with BucketNotEmpty and (since teardown swallows errors) leaks the bucket. Purge objects AND all
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
    Registers the function's teardown (LIFO-before its role, since the role was registered first)."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    # Normalize inline handler source: dedent (checks often embed indented triple-quoted code) and
    # bind to the fixed entrypoint — the Handler is "lambda_function.lambda_handler", but inline code
    # is conventionally written as `def handler(event, context)`. Without a lambda_handler symbol the
    # function fails at runtime with Runtime.HandlerNotFound before any behavior is exercised. Both are
    # no-ops for code that's already column-0 and defines lambda_handler.
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
    # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
    # function deletion, and an in-flight invocation can write it after an early delete. Registered
    # before create, so it runs after delete_function and reaps over a bounded reappearance window.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _reap_log_group(ctx, log_group: str) -> None:
    """Delete the log group, then keep deleting it until it stays absent for a 60s window."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + 60
    while True:
        try:
            logs.delete_log_group(logGroupName=log_group)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        if time.monotonic() >= deadline:
            found = logs.describe_log_groups(logGroupNamePrefix=log_group).get("logGroups", [])
            if any(g["logGroupName"] == log_group for g in found):
                raise AssertionError(f"log group {log_group} still present after the reap window")
            return
        time.sleep(10)


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
) -> dict[str, str]:
    """Create a Lambda with an execution role scoped to `permissions` (a list of IAM statement
    fragments like [{"Action": ["sqs:SendMessage"], "Resource": queue_arn}]); logs are always
    allowed. Role + function each register their own teardown (function torn down first, LIFO).
    Returns {name,arn}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    return _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )


def _create_bucket(ctx) -> dict[str, str]:
    """Create an S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":  # S3 rejects an explicit LocationConstraint for us-east-1
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
