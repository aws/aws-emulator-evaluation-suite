"""lambda-s3-putobject-missing-permission-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-s3-putobject-missing-permission-negative"

GROUP = "overly-permissive"

SERVICES = ["lambda", "s3", "stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda role loses s3:PutObject and gets AccessDeniedException, not a silent success; it
    recovers once the permission is restored (broken-then-restored negative: positive control ->
    break one thing -> deny -> absent -> restore -> succeed)."""
    bucket = _create_bucket(ctx)
    bucket_name = bucket["name"]
    bucket_arn = bucket["arn"]

    handler_code = """
import boto3, os
def lambda_handler(event, context):
    s3 = boto3.client('s3')
    try:
        s3.put_object(Bucket=os.environ['BUCKET_NAME'], Key=event['key'], Body=event['body'])
        return {'status': 'ok'}
    except Exception as e:
        return {
            'error': type(e).__name__,
            'message': str(e),
            'code': getattr(e, 'response', {}).get('Error', {}).get('Code', '') if hasattr(e, 'response') else ''
        }
"""
    policy_name = "s3-write-policy"

    def _policy_doc(allow_put: bool) -> str:
        actions = ["s3:GetObject"] + (["s3:PutObject"] if allow_put else [])
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": actions,
                        "Resource": f"{bucket_arn}/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "arn:aws:logs:*:*:*",
                    },
                ],
            }
        )

    role = _create_role(ctx, "lambda.amazonaws.com")
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role["name"], PolicyName=policy_name, PolicyDocument=_policy_doc(allow_put=True)
    )
    fn = _create_function_with_retry(
        ctx, handler_code, role["arn"], {"BUCKET_NAME": bucket_name}
    )
    s3 = ctx.client("s3")

    # 1. Positive control: with s3:PutObject granted, the write succeeds. Polling rides out
    # the same IAM trust/permission propagation window a blind sleep used to paper over.
    control = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {"key": "control.txt", "body": "control ok"}),
        lambda r: r["payload"].get("status") == "ok",
        timeout_s=30.0,
        interval_s=2.0,
        description="positive-control PutObject to succeed with s3:PutObject granted",
    )
    assert control["payload"].get("status") == "ok", (
        f"Expected positive control to succeed but got: {control['payload']}"
    )
    # The positive-control object exists: HeadObject raises if it does not.
    s3.head_object(Bucket=bucket_name, Key="control.txt")

    # 2. Break exactly one thing: revoke s3:PutObject; s3:GetObject and logs stay granted.
    iam.put_role_policy(
        RoleName=role["name"], PolicyName=policy_name, PolicyDocument=_policy_doc(allow_put=False)
    )

    # 3. The specific error, once the policy change has propagated. Revoking permission on an
    # already-in-use role is itself eventually consistent (confirmed on real AWS: the first retry
    # after revoking can still land before the change propagates), so each attempt writes to a
    # FRESH key — reusing one key would let an early, still-permitted write plant the very object
    # the absence check below expects to be missing.
    _denial_attempts = {"n": 0}

    def _denial_probe():
        _denial_attempts["n"] += 1
        candidate_key = f"blocked-{_denial_attempts['n']}.txt"
        return candidate_key, _invoke_lambda(
            ctx, fn["name"], {"key": candidate_key, "body": "should fail"}
        )

    denied_key, denied_resp = _poll_until(
        _denial_probe,
        lambda kv: "accessdenied" in json.dumps(kv[1]["payload"]).lower()
        or "access denied" in json.dumps(kv[1]["payload"]).lower(),
        timeout_s=30.0,
        interval_s=2.0,
        description="PutObject to be denied after revoking s3:PutObject",
    )

    # 4. Effect absent: the write for the specific denied attempt never landed.
    payload_str = json.dumps(denied_resp["payload"]).lower()
    assert "accessdenied" in payload_str or "access denied" in payload_str, (
        f"Expected AccessDeniedException but got: {denied_resp['payload']}"
    )
    err, err_message = _error_code(lambda: s3.head_object(Bucket=bucket_name, Key=denied_key))
    assert (err, err_message) == ("404", "Not Found"), (
        f"Object {denied_key} should not exist (head_object should 404), got {err!r}: {err_message!r}"
    )

    # 5. Restore the permission.
    iam.put_role_policy(
        RoleName=role["name"], PolicyName=policy_name, PolicyDocument=_policy_doc(allow_put=True)
    )

    # 6. The identical call (same key, same body as the denied attempt) now succeeds.
    restored = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {"key": denied_key, "body": "should fail"}),
        lambda r: r["payload"].get("status") == "ok",
        timeout_s=30.0,
        interval_s=2.0,
        description="identical PutObject to succeed once s3:PutObject is restored",
    )
    assert restored["payload"].get("status") == "ok", (
        f"Expected identical call to succeed after restoring s3:PutObject, got: {restored['payload']}"
    )
    # The restored write landed: HeadObject raises if the object does not exist.
    s3.head_object(Bucket=bucket_name, Key=denied_key)


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
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    # No sleep here: the only caller (_create_lambda -> _create_function_with_retry)
    # already retries create_function against "cannot be assumed" for up to 30s, which
    # is the bounded wait for IAM role trust/permission propagation.
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
    # no-ops for code that's already column-0 and defines lambda_handler. (Folds in the dedent+alias
    # that ~8 per-suite harness overrides used to do, so no suite needs its own create_lambda shim.)
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
            # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
            # function deletion and sweep_account doesn't scan log groups, so it would leak. Delete it
            # too (best-effort — on_cleanup swallows if it was never created).
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
