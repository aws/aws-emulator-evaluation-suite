"""sfn-catch-lambda-error-and-write-s3."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-catch-lambda-error-and-write-s3"

GROUP = "error-propagation"

SERVICES = ["lambda", "s3", "stepfunctions"]


def _cleanup_state_machine(ctx, arn: str) -> None:
    """Delete a state machine, then block until it is truly gone.

    StepFunctions DeleteStateMachine is asynchronous — the machine lingers in DELETING for up to
    ~a minute after the call returns. The account residual audit runs shortly after teardown, so a
    machine created by one of the last checks is still mid-deletion and gets misreported as a LEAK
    even though its delete was correctly issued. Wait out that window so teardown is deterministic.
    """
    sfn = ctx.client("stepfunctions")
    sfn.delete_state_machine(stateMachineArn=arn)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            if (
                sfn.describe_state_machine(stateMachineArn=arn).get("status")
                != "DELETING"
            ):
                return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                raise
            return
        time.sleep(5)


def _is_trust_lag(result: dict) -> bool:
    """True when an execution FAILED only because role trust had not propagated."""
    blob = result.get("cause", "") + result.get("error", "")
    return result.get("status") == "FAILED" and (
        "not authorized to assume" in blob or "AccessDenied" in blob
    )


def _bust_cached_trust(ctx, sm_arn):
    """Force Step Functions to re-resolve the state machine's role.

    A CreateStateMachine issued before the role's states.amazonaws.com trust has
    propagated leaves SFN holding a NEGATIVE trust resolution: executions keep
    failing with "not authorized to assume" even after IAM has settled, because
    the state machine still caches the stale result. Re-applying the same roleArn
    via UpdateStateMachine makes SFN re-resolve the (now-propagated) trust, so the
    next execution can succeed. Best-effort: a failure here just costs one retry.
    """
    sfn = ctx.client("stepfunctions")
    try:
        role_arn = sfn.describe_state_machine(stateMachineArn=sm_arn)["roleArn"]
        sfn.update_state_machine(stateMachineArn=sm_arn, roleArn=role_arn)
    except Exception:
        pass


def _run_execution_past_trust_lag(
    ctx, sm_arn, exec_input, *, attempts=8, backoff_s=15, timeout_s=120
):
    """Start a STANDARD execution, retrying past role-trust propagation lag.

    Returns the settled describe_execution result. A non-trust failure (e.g. an
    intentional Lambda error caught by a Catch state) is returned immediately so
    negative/catch assertions still see the real terminal state. Between trust-lag
    retries it re-resolves the SM role (see _bust_cached_trust) — a plain re-run is
    not enough when SFN has cached the pre-propagation negative validation.
    """
    sfn = ctx.client("stepfunctions")
    result = None
    for _ in range(attempts):
        ex = sfn.start_execution(stateMachineArn=sm_arn, input=exec_input)
        exec_arn = ex["executionArn"]
        result = _poll_until(
            lambda: sfn.describe_execution(executionArn=exec_arn),
            lambda r: r["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=timeout_s,
            interval_s=3,
        )
        if not _is_trust_lag(result):
            return result
        time.sleep(backoff_s)
        _bust_cached_trust(ctx, sm_arn)
    return result


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """SFN Catch catches Lambda error, routes to fallback that writes error details to S3."""
    bucket = _create_bucket(ctx)
    bucket_name = bucket["name"]
    bucket_arn = bucket["arn"]

    handler_code_1 = """
class ProcessingError(Exception):
    pass

def lambda_handler(event, context):
    raise ProcessingError('intentional failure')
"""
    fn1 = _create_lambda(
        ctx,
        handler_code=handler_code_1,
        permissions=[
            {
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            },
        ],
    )

    handler_code_2 = """
import boto3, json, os, time
def lambda_handler(event, context):
    s3 = boto3.client('s3')
    bucket = os.environ['BUCKET_NAME']
    ts = int(time.time() * 1000)
    key = f'errors/{ts}.json'
    s3.put_object(Bucket=bucket, Key=key, Body=json.dumps({'cause': str(event), 'timestamp': ts}))
    return {'errorKey': key}
"""
    fn2 = _create_lambda(
        ctx,
        handler_code=handler_code_2,
        permissions=[
            {"Action": ["s3:PutObject"], "Resource": f"{bucket_arn}/*"},
            {
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            },
        ],
        env={"BUCKET_NAME": bucket_name},
    )

    iam = ctx.client("iam")
    sfn_role_name = ctx.unique_name("sfn-catch-role")
    sfn_role_resp = iam.create_role(
        RoleName=sfn_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "states.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    sfn_role_arn = sfn_role_resp["Role"]["Arn"]
    # Use the harness's policy-aware role deletion: these roles get an inline
    # put_role_policy, and a plain iam.delete_role fails with DeleteConflict while
    # any policy is still attached, leaking the role. _delete_role detaches/deletes
    # policies first.
    ctx.on_cleanup(lambda name=sfn_role_name: _delete_role(ctx, name))
    _poll_until(
        lambda: iam.get_role(RoleName=sfn_role_name),
        lambda r: r.get("Role", {}).get("Arn") == sfn_role_arn,
        timeout_s=30,
        interval_s=3,
    )

    iam = ctx.client("iam")
    catch_policy_name = ctx.unique_name("sfn-catch-policy")
    iam.put_role_policy(
        RoleName=sfn_role_name,
        PolicyName=catch_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["lambda:InvokeFunction"],
                        "Resource": [fn1["arn"], fn2["arn"]],
                    }
                ],
            }
        ),
    )
    _poll_until(
        lambda: iam.get_role_policy(
            RoleName=sfn_role_name, PolicyName=catch_policy_name
        ),
        lambda r: "PolicyDocument" in r,
        timeout_s=30,
        interval_s=3,
    )

    definition = json.dumps(
        {
            "StartAt": "Processor",
            "States": {
                "Processor": {
                    "Type": "Task",
                    "Resource": fn1["arn"],
                    "Catch": [
                        {
                            "ErrorEquals": ["States.ALL"],
                            "Next": "ErrorHandler",
                            "ResultPath": "$.errorInfo",
                        }
                    ],
                    "End": True,
                },
                "ErrorHandler": {
                    "Type": "Task",
                    "Resource": fn2["arn"],
                    "InputPath": "$.errorInfo",
                    "ResultPath": "$.errorResult",
                    "End": True,
                },
            },
        }
    )

    sfn = ctx.client("stepfunctions")
    sm_name = ctx.unique_name("sfn-catch-sm")
    sm_resp = sfn.create_state_machine(
        name=sm_name,
        definition=definition,
        roleArn=sfn_role_arn,
        type="STANDARD",
    )
    sm_arn = sm_resp["stateMachineArn"]
    ctx.on_cleanup(lambda arn=sm_arn: _cleanup_state_machine(ctx, arn))

    # The intentional Lambda error (ProcessingError) is caught by the Catch state,
    # so a healthy run ends SUCCEEDED. Only a role-trust propagation failure
    # (AccessDenied / not-authorized-to-assume) is retried; the caught error is not.
    result = _run_execution_past_trust_lag(
        ctx, sm_arn, json.dumps({"test": "error-propagation"})
    )

    assert result["status"] == "SUCCEEDED", (
        f"Expected SUCCEEDED via catch path, got: {result['status']} cause={result.get('cause', '')}"
    )

    s3 = ctx.client("s3")

    def list_errors():
        resp = s3.list_objects_v2(Bucket=bucket_name, Prefix="errors/")
        return resp.get("Contents", [])

    error_objects = _poll_until(
        list_errors, lambda objs: len(objs) > 0, timeout_s=30, interval_s=3
    )
    assert len(error_objects) > 0, "No error object written to S3"
    obj = s3.get_object(Bucket=bucket_name, Key=error_objects[0]["Key"])
    body_str = obj["Body"].read().decode()
    assert "intentional failure" in body_str or "ProcessingError" in body_str, (
        f"Error details not in S3 body: {body_str}"
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
    # No blind sleep here: IAM role trust/permission propagation is absorbed by
    # _create_function_with_retry's bounded retry-on-"cannot be assumed" loop below.
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
