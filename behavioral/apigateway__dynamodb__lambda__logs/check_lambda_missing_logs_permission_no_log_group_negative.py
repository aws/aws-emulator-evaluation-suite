"""lambda-missing-logs-permission-no-log-group-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-missing-logs-permission-no-log-group-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function whose role has no CloudWatch Logs permissions invokes successfully but gets no log
    group, while a role with basic-execution permissions gets its log group for the same code."""
    code = "def handler(event, context):\n    return {'ok': True}\n"
    lam = ctx.client("lambda")

    # --- positive control FIRST: identical handler, role WITH standard logging permissions ---
    good_fn = ctx.unique_name("sim2real-withlogperm-")
    good_role_arn, _ = _create_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
        "withlogperm",
    )
    _create_function_with_role_retry(ctx, good_fn, good_role_arn, _make_zip(code))
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=good_fn))
    good_log_group = f"/aws/lambda/{good_fn}"
    ctx.on_cleanup(lambda: _delete_log_group_ignore(ctx, good_log_group))

    positive_invoke_started = time.monotonic()
    resp2 = lam.invoke(FunctionName=good_fn, Payload=json.dumps({}).encode())
    assert resp2["StatusCode"] == 200, f"expected StatusCode 200 for positive control, got {resp2['StatusCode']}"
    assert "FunctionError" not in resp2, f"positive control invocation reported a FunctionError: {resp2.get('FunctionError')}"

    exists = _poll_until(
        lambda: _log_group_exists(ctx, good_log_group),
        lambda found: found,
        timeout_s=90,
        interval_s=3,
    )
    assert exists is True, "positive control: log group was never created even though the role had logs permissions"
    positive_latency_s = time.monotonic() - positive_invoke_started

    # --- negative: role has NO logs permissions at all (only the lambda trust policy) ---
    bad_fn = ctx.unique_name("sim2real-nologperm-")
    bad_role_arn, _ = _create_role(ctx, [], "nologperm")
    _create_function_with_role_retry(ctx, bad_fn, bad_role_arn, _make_zip(code))
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=bad_fn))
    bad_log_group = f"/aws/lambda/{bad_fn}"
    ctx.on_cleanup(lambda: _delete_log_group_ignore(ctx, bad_log_group))

    resp = lam.invoke(FunctionName=bad_fn, Payload=json.dumps({}).encode())
    assert resp["StatusCode"] == 200, f"expected StatusCode 200 for the no-logs-permission invoke, got {resp['StatusCode']}"
    assert "FunctionError" not in resp, "invocation itself must succeed even without logging permissions"
    payload = json.loads(resp["Payload"].read())
    assert payload == {"ok": True}, f"expected handler payload {{'ok': True}}, got {payload}"

    # The absence window is at least 3x the positive control's measured latency, so a target
    # that is slower but correct is not scored as having blocked log group creation.
    absence_window_s = max(15.0, 3.0 * positive_latency_s)
    appeared = _poll_until(
        lambda: _log_group_exists(ctx, bad_log_group),
        lambda found: found,
        timeout_s=absence_window_s,
        interval_s=3,
    )
    assert appeared is False, (
        f"log group {bad_log_group} was created despite the role having no logs permissions "
        f"(held absence for {absence_window_s:.0f}s, >= 3x the positive control's measured "
        f"{positive_latency_s:.0f}s)"
    )


def _make_zip(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_role(ctx, statements: list[dict[str, Any]], suffix: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-{suffix}-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if statements:
        policy_doc = {"Version": "2012-10-17", "Statement": statements}
        iam.put_role_policy(RoleName=role_name, PolicyName="inline-policy", PolicyDocument=json.dumps(policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-policy"))
    return role_arn, role_name


def _wait_function_active(ctx, name: str, timeout_s: float = 120.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg.get("State")
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function {name} failed to activate: {cfg.get('StateReasonCode')}")
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active within {timeout_s}s")


def _create_function_with_role_retry(
    ctx, name: str, role_arn: str, zip_bytes: bytes, handler: str = "index.handler",
    env: dict[str, str] | None = None, timeout_s: float = 90.0,
) -> dict[str, Any]:
    lam = ctx.client("lambda")
    kwargs: dict[str, Any] = dict(
        FunctionName=name, Runtime="python3.12", Role=role_arn, Handler=handler,
        Code={"ZipFile": zip_bytes}, Timeout=30, MemorySize=128,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            _wait_function_active(ctx, name)
            return resp
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"create_function never succeeded (IAM role propagation?): {last_exc}")


def _delete_log_group_ignore(ctx, log_group_name: str) -> None:
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except logs.exceptions.ResourceNotFoundException:
        pass


def _log_group_exists(ctx, log_group_name: str) -> bool:
    logs = ctx.client("logs")
    resp = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
    return any(g["logGroupName"] == log_group_name for g in resp.get("logGroups", []))


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
