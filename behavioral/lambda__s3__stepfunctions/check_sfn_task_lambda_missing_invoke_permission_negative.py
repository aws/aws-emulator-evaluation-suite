"""sfn-task-lambda-missing-invoke-permission-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-task-lambda-missing-invoke-permission-negative"

GROUP = "overly-permissive"

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
    via UpdateStateMachine makes SFN re-resolve the (now-propagated) trust.
    """
    sfn = ctx.client("stepfunctions")
    try:
        role_arn = sfn.describe_state_machine(stateMachineArn=sm_arn)["roleArn"]
        sfn.update_state_machine(stateMachineArn=sm_arn, roleArn=role_arn)
    except Exception:
        pass


def _run_execution_past_trust_lag(
    ctx, sm_arn, token_prefix, *, attempts=8, backoff_s=15, timeout_s=120
):
    """Start STANDARD executions, retrying past role-trust propagation lag (see
    _bust_cached_trust), until the terminal status is not trust-lag-shaped. Only
    needed for the very first execution against a freshly created role — later
    executions on the same, already-proven role never hit this. Each attempt mints
    its own token so a discarded (trust-lag) attempt cannot leave a side effect that
    contaminates the independent read on the attempt that is actually kept. Returns
    (result, token) for the attempt that was kept."""
    sfn = ctx.client("stepfunctions")
    result = None
    token = None
    for i in range(attempts):
        token = f"{token_prefix}-{i}"
        ex = sfn.start_execution(
            stateMachineArn=sm_arn, input=json.dumps({"token": token})
        )
        result = _poll_until(
            lambda arn=ex["executionArn"]: sfn.describe_execution(executionArn=arn),
            lambda r: r["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=timeout_s,
            interval_s=3,
        )
        if not _is_trust_lag(result):
            return result, token
        time.sleep(backoff_s)
        _bust_cached_trust(ctx, sm_arn)
    return result, token


def _run_execution_expecting(
    ctx, sm_arn, token_prefix, *, want_status, attempts=5, backoff_s=10, timeout_s=60
):
    """Start executions until the terminal status matches want_status or attempts run
    out. An IAM inline-policy change on an already-trusted role is eventually
    consistent, so the execution immediately after a grant/revoke may still observe
    the old permission set for a few seconds — retry rather than sleep-then-hope.
    Each attempt mints its own token so a discarded attempt cannot leave a side
    effect that contaminates the independent read on the attempt that is actually
    kept. Returns (result, token) for the attempt that was kept — the last one
    tried either way; the caller asserts on it."""
    sfn = ctx.client("stepfunctions")
    result = None
    token = None
    for i in range(attempts):
        token = f"{token_prefix}-{i}"
        ex = sfn.start_execution(
            stateMachineArn=sm_arn, input=json.dumps({"token": token})
        )
        result = _poll_until(
            lambda arn=ex["executionArn"]: sfn.describe_execution(executionArn=arn),
            lambda r: r["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=timeout_s,
            interval_s=3,
        )
        if result["status"] == want_status:
            return result, token
        time.sleep(backoff_s)
    return result, token


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SFN execution role gains, then loses, then regains lambda:InvokeFunction. Only the
    middle (denied) leg may fail, and only then is the Lambda side effect absent."""
    bucket = _create_bucket(ctx)
    bucket_name = bucket["name"]

    handler_code = """
import boto3, os
def lambda_handler(event, context):
    s3 = boto3.client('s3')
    token = event.get('token', 'unknown')
    s3.put_object(Bucket=os.environ['BUCKET_NAME'], Key=f'triggered/{token}.txt', Body='triggered')
    return {'ok': True, 'token': token}
"""
    fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        permissions=[
            {"Action": ["s3:PutObject"], "Resource": f"{bucket['arn']}/*"},
        ],
        env={"BUCKET_NAME": bucket_name},
    )

    iam = ctx.client("iam")
    sfn_role_name = ctx.unique_name("sfn-noperm-role")
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
    # Use the harness's policy-aware role deletion: this role gets an inline
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

    invoke_policy_name = ctx.unique_name("sfn-invoke-policy")
    invoke_policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["lambda:InvokeFunction"],
                    "Resource": fn["arn"],
                }
            ],
        }
    )

    def _grant_invoke():
        iam.put_role_policy(
            RoleName=sfn_role_name,
            PolicyName=invoke_policy_name,
            PolicyDocument=invoke_policy_doc,
        )

    def _revoke_invoke():
        try:
            iam.delete_role_policy(RoleName=sfn_role_name, PolicyName=invoke_policy_name)
        except ClientError:
            pass

    def _marker_exists(token: str) -> bool:
        resp = ctx.client("s3").list_objects_v2(
            Bucket=bucket_name, Prefix=f"triggered/{token}.txt"
        )
        return len(resp.get("Contents", [])) > 0

    definition = json.dumps(
        {
            "StartAt": "InvokeLambda",
            "States": {
                "InvokeLambda": {
                    "Type": "Task",
                    "Resource": fn["arn"],
                    "End": True,
                }
            },
        }
    )

    sfn = ctx.client("stepfunctions")
    sm_name = ctx.unique_name("sfn-noperm-sm")
    sm_resp = sfn.create_state_machine(
        name=sm_name,
        definition=definition,
        roleArn=sfn_role_arn,
        type="STANDARD",
    )
    sm_arn = sm_resp["stateMachineArn"]
    ctx.on_cleanup(lambda arn=sm_arn: _cleanup_state_machine(ctx, arn))

    # Beat 1: positive control — grant the permission first and prove the wiring
    # actually works (and the Lambda genuinely runs) before withholding anything.
    _grant_invoke()
    positive, positive_token = _run_execution_past_trust_lag(
        ctx, sm_arn, "positive-control"
    )
    assert positive["status"] == "SUCCEEDED", (
        f"Positive control expected SUCCEEDED, got: {positive}"
    )
    assert _marker_exists(positive_token), (
        "Positive control execution SUCCEEDED but the Lambda side effect "
        "(S3 marker) is missing"
    )

    # Beats 2-3: break exactly one thing — revoke lambda:InvokeFunction — and
    # demand the specific denial.
    _revoke_invoke()
    denied, denied_token = _run_execution_expecting(
        ctx, sm_arn, "denied", want_status="FAILED"
    )
    assert denied["status"] == "FAILED", (
        f"Expected FAILED once lambda:InvokeFunction is revoked, got: {denied}"
    )
    cause_or_error = (denied.get("cause", "") + denied.get("error", "")).lower()
    assert (
        "accessdenied" in cause_or_error
        or "not authorized" in cause_or_error
        or "states.taskfailed" in cause_or_error
    ), f"Expected an access-denied Task failure, got: {denied}"

    # Beat 4: the effect is absent, on an independent read at the destination —
    # the Lambda was never actually invoked.
    assert not _marker_exists(denied_token), (
        "Lambda ran (S3 marker present) despite the revoked invoke permission"
    )

    # Beats 5-6: restore the identical permission and demand the identical call
    # now succeeds again.
    _grant_invoke()
    restored, restored_token = _run_execution_expecting(
        ctx, sm_arn, "restored", want_status="SUCCEEDED"
    )
    assert restored["status"] == "SUCCEEDED", (
        f"Expected SUCCEEDED after restoring lambda:InvokeFunction, got: {restored}"
    )
    assert _marker_exists(restored_token), (
        "Restored permission but the Lambda side effect (S3 marker) is missing"
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
    # No fixed propagation sleep here: _create_function_with_retry already retries
    # "cannot be assumed" for up to 30s, which is this role's only real consumer.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
