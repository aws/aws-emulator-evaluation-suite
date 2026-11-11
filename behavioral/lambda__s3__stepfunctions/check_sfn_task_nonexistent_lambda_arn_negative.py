"""sfn-task-nonexistent-lambda-arn-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sfn-task-nonexistent-lambda-arn-negative"

GROUP = "overly-permissive"

SERVICES = ["lambda", "s3", "stepfunctions"]

# Tag every created resource so a tag search finds any remainder even if this
# check's own cleanup is killed mid-run.
_MANAGED_TAG = {"sim2real:managed": "true"}


def _cleanup_state_machine(ctx, arn: str) -> None:
    """Delete a state machine, then wait briefly for it to leave DELETING.

    DeleteStateMachine is asynchronous and the machine can stay DELETING for about a minute. All
    of this check's teardowns share one cleanup budget, so each machine's wait is capped at 20 s to
    leave room for the function and role deletes registered before it; this is a bound, not a check.
    """
    sfn = ctx.client("stepfunctions")
    sfn.delete_state_machine(stateMachineArn=arn)
    deadline = time.monotonic() + 20
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
    ctx, sm_arn, exec_input, *, attempts=6, backoff_s=10, timeout_s=60
):
    """Start a STANDARD execution, retrying past role-trust propagation lag.

    Returns the settled describe_execution result. A non-trust failure (e.g. the
    resource genuinely not existing) is returned immediately so the caller sees the
    real terminal state. Between trust-lag retries it re-resolves the SM role (see
    _bust_cached_trust) — a plain re-run is not enough when SFN has cached the
    pre-propagation negative validation.
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
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """SFN Task state references a nonexistent Lambda function; execution must fail with the
    function's own not-found error, not hang, not succeed, and not merely fail for some unrelated
    reason (proven by a positive control that invokes a REAL function through identical wiring)."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    fn = _create_lambda(
        ctx,
        handler_code="""
        def lambda_handler(event, context):
            return {"ok": True}
        """,
    )

    iam = ctx.client("iam")
    sfn_role_name = ctx.unique_name("sfn-notfound-role")
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
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAG.items()],
    )
    sfn_role_arn = sfn_role_resp["Role"]["Arn"]
    # Use the harness's policy-aware role deletion: these roles get an inline
    # put_role_policy, and a plain iam.delete_role fails with DeleteConflict while
    # any policy is still attached, leaking the role. _delete_role detaches/deletes
    # policies first.
    ctx.on_cleanup(lambda name=sfn_role_name: _delete_role(ctx, name))

    iam.put_role_policy(
        RoleName=sfn_role_name,
        PolicyName=ctx.unique_name("sfn-notfound-policy"),
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["lambda:InvokeFunction"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )

    sfn = ctx.client("stepfunctions")

    def _make_state_machine(name_prefix: str, resource_arn: str) -> str:
        sm_resp = sfn.create_state_machine(
            name=ctx.unique_name(name_prefix),
            definition=json.dumps(
                {
                    "StartAt": "CallLambda",
                    "States": {
                        "CallLambda": {
                            "Type": "Task",
                            "Resource": resource_arn,
                            "End": True,
                        }
                    },
                }
            ),
            roleArn=sfn_role_arn,
            type="STANDARD",
            tags=[{"key": k, "value": v} for k, v in _MANAGED_TAG.items()],
        )
        arn = sm_resp["stateMachineArn"]
        ctx.on_cleanup(lambda arn=arn: _cleanup_state_machine(ctx, arn))
        return arn

    # ---- positive control: the SAME role invoking a REAL function succeeds ----
    positive_sm_arn = _make_state_machine("sfn-notfound-positive-sm", fn["arn"])
    positive_result = _run_execution_past_trust_lag(ctx, positive_sm_arn, "{}")
    assert positive_result["status"] == "SUCCEEDED", (
        f"Positive control (real function, same role/wiring) must succeed but got: "
        f"{positive_result['status']} cause={positive_result.get('cause', '')}"
    )
    output = json.loads(positive_result["output"])
    assert output == {"ok": True}, (
        f"Positive control's Lambda did not actually run: {output}"
    )

    # ---- break exactly one thing: point the Task at a function that does not exist ----
    fake_lambda_arn = (
        f"arn:aws:lambda:{ctx.region}:{account_id}:function:nonexistent-function-xyz"
    )
    negative_sm_arn = _make_state_machine("sfn-notfound-negative-sm", fake_lambda_arn)
    negative_result = _run_execution_past_trust_lag(ctx, negative_sm_arn, "{}")
    assert negative_result["status"] == "FAILED", (
        f"Expected FAILED for nonexistent Lambda but got: {negative_result['status']}"
    )
    error = negative_result.get("error", "") or ""
    cause = negative_result.get("cause", "") or ""
    assert error == "Lambda.ResourceNotFoundException", (
        f"Expected Lambda.ResourceNotFoundException for a nonexistent function, got "
        f"error={error!r} cause={cause!r}"
    )
    assert "nonexistent-function-xyz" in cause, (
        f"The not-found cause did not name the missing function: {cause!r}"
    )


# ===== helpers =====
def _delete_role(ctx, role_name: str) -> None:
    """Delete an IAM role after detaching/removing its policies. These roles get an inline
    put_role_policy, and a plain iam.delete_role fails with DeleteConflict while any policy is
    still attached, leaking the role — so detach/delete policies first."""
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
    ctx, handler_code, role_arn, timeout=30, memory=128, runtime="python3.12"
) -> dict[str, str]:
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.
    Registers the function's teardown."""
    name = ctx.unique_name("sfn-notfound-fn")
    lam = ctx.client("lambda")
    handler_code = textwrap.dedent(handler_code)
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
        "Tags": dict(_MANAGED_TAG),
    }
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The function auto-creates /aws/lambda/<name> on first invoke; that log group
            # survives function deletion and the account residual scan doesn't watch log
            # groups, so it would leak. Delete it too (best-effort: no-op if never created).
            ctx.on_cleanup(
                lambda: ctx.client("logs").delete_log_group(
                    logGroupName=f"/aws/lambda/{name}"
                )
            )
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except Exception as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _create_lambda(ctx, handler_code) -> dict[str, str]:
    """Create a Lambda with a minimal execution role (logs only). Returns {name, arn}."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sfn-notfound-fn-role")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAG.items()],
    )
    ctx.on_cleanup(lambda name=role_name: _delete_role(ctx, name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=ctx.unique_name("sfn-notfound-fn-logs"),
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ],
            }
        ),
    )
    return _create_function_with_retry(ctx, handler_code, role["Role"]["Arn"])


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
