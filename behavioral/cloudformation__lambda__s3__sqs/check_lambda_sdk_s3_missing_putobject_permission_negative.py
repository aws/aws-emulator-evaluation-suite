"""lambda-sdk-s3-missing-putobject-permission-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError
from botocore.exceptions import ClientError as BotoClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-s3-missing-putobject-permission-negative"

GROUP = "overly-permissive"

SERVICES = ["cloudformation", "lambda", "s3", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With a role granting s3:GetObject but not s3:PutObject, the Lambda's GetObject succeeds and
    its PutObject fails with AccessDenied and AWS's exact message without creating the object;
    once s3:PutObject is granted, the same PutObject succeeds."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")

    control_key = "control/preexisting.txt"
    s3.put_object(Bucket=bucket["name"], Key=control_key, Body=b"control-value")

    handler_code = """
import boto3, os
from botocore.exceptions import ClientError
def lambda_handler(event, context):
    s3 = boto3.client('s3')
    result = {}
    try:
        obj = s3.get_object(Bucket=os.environ['BUCKET_NAME'], Key=event['control_key'])
        result['get'] = {'ok': True, 'body': obj['Body'].read().decode()}
    except ClientError as e:
        result['get'] = {'ok': False, 'error': e.response['Error']['Code']}
    try:
        s3.put_object(
            Bucket=os.environ['BUCKET_NAME'],
            Key=event['key'],
            Body=event['body'].encode()
        )
        result['put'] = {'ok': True}
    except ClientError as e:
        result['put'] = {'ok': False, 'error': e.response['Error']['Code'],
                         'message': e.response['Error'].get('Message')}
    return result
"""
    fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        permissions=[
            {"Action": ["s3:GetObject"], "Resource": bucket["arn"] + "/*"},
            # s3:PutObject intentionally absent for the first invocation
        ],
        env={"BUCKET_NAME": bucket["name"]},
    )

    invoke_payload = {"control_key": control_key, "key": "denied/test.txt", "body": "x"}
    result = _invoke_lambda(ctx, fn["name"], invoke_payload)
    payload = result["payload"]
    assert isinstance(payload, dict) and "get" in payload and "put" in payload, (
        f"Expected a {{'get': ..., 'put': ...}} payload, got: {payload!r}"
    )

    # Positive control: GetObject, which the role IS granted, must succeed. Without this leg, a
    # target that denies every S3 call regardless of policy would score identically to one that
    # correctly enforces the missing PutObject permission.
    get_result = payload["get"]
    assert get_result.get("ok") is True, (
        f"Positive control failed: GetObject with a granted permission should succeed, got: {get_result!r}"
    )
    assert get_result.get("body") == "control-value", (
        f"Positive control returned the wrong body: {get_result!r}"
    )

    # Negative: PutObject, which the role is NOT granted, must be denied with the specific code.
    put_result = payload["put"]
    assert put_result.get("ok") is False, (
        f"Expected PutObject to be denied without s3:PutObject permission, got: {put_result!r}"
    )
    account = fn["arn"].split(":")[4]
    denied_message = (
        f"User: arn:aws:sts::{account}:assumed-role/{fn['role_name']}/{fn['name']} is not authorized "
        f"to perform: s3:PutObject on resource: \"{bucket['arn']}/denied/test.txt\" because no "
        f"identity-based policy allows the s3:PutObject action"
    )
    assert (put_result.get("error"), put_result.get("message")) == ("AccessDenied", denied_message), (
        f"Expected AccessDenied {denied_message!r}, got {put_result!r}"
    )

    # Effect absent: the denied write must not have created the object.
    try:
        stray = s3.get_object(Bucket=bucket["name"], Key="denied/test.txt")
    except BotoClientError as e:
        absent = (e.response["Error"]["Code"], e.response["Error"].get("Message"))
    else:
        raise AssertionError(f"Object exists in bucket after a denied PutObject: {stray!r}")
    assert absent == ("NoSuchKey", "The specified key does not exist."), (
        f"Expected NoSuchKey reading the never-written object, got: {absent!r}"
    )

    # Restore: grant s3:PutObject on the same role, then retry the IDENTICAL call.
    _grant_role_permission(
        ctx,
        fn["role_name"],
        policy_name="restore-putobject",
        actions=["s3:PutObject"],
        resource=bucket["arn"] + "/*",
    )

    def _retry_put() -> dict:
        r = _invoke_lambda(ctx, fn["name"], invoke_payload)
        return r["payload"].get("put", {})

    restored = _poll_until(
        _retry_put,
        lambda p: p.get("ok") is True,
        timeout_s=30.0,
        interval_s=3.0,
        description="identical PutObject call succeeding after granting s3:PutObject",
    )
    assert restored.get("ok") is True, (
        f"Expected the identical PutObject call to succeed once granted, got: {restored!r}"
    )

    written = s3.get_object(Bucket=bucket["name"], Key="denied/test.txt")
    body = written["Body"].read().decode()
    assert body == "x", f"Expected the restored PutObject to have written 'x', got: {body!r}"


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
    # No unconditional sleep here for IAM propagation: _create_function_with_retry already
    # bounds-and-retries CreateFunction through the "cannot be assumed" window.
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
    """Delete every object version and delete marker (versioning may be on), then the bucket:
    DeleteBucket on a non-empty bucket fails with BucketNotEmpty."""
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


def _delete_log_group_if_present(ctx, group: str) -> None:
    """Delete a log group; one that was never created is already clean."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The function creates /aws/lambda/<name> on its first invoke and the group outlives the
            # function, so delete it too; Lambda creates it asynchronously, so one that never
            # appeared is not a failure.
            ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{name}"))
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


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
    fn = _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )
    fn["role_name"] = role["name"]
    return fn


def _grant_role_permission(
    ctx, role_name: str, policy_name: str, actions: list[str], resource: str
) -> None:
    """Add a further inline policy to an existing role (cleaned up by `_delete_role`, which removes
    every inline policy on the role, not just the original one). Propagation is bounded by the
    caller retrying the actual call, not here."""
    ctx.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}],
            }
        ),
    )


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
    if ctx.region != "us-east-1":
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
