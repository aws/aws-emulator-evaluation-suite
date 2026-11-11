"""lambda-log-retention-set-via-put-retention-policy."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-log-retention-set-via-put-retention-policy"
GROUP = "log-delivery"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Lambda's auto-created log group starts with no retention policy (never expire);
    after PutRetentionPolicy, DescribeLogGroups reflects the new retentionInDays value."""
    fn_name = ctx.unique_name("sim2real-retention-")
    role_arn, _ = _create_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
        "retention",
    )
    code = "def handler(event, context):\n    return {'ok': True}\n"
    _create_function_with_role_retry(ctx, fn_name, role_arn, _make_zip(code))
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=fn_name))
    log_group_name = f"/aws/lambda/{fn_name}"
    ctx.on_cleanup(lambda: _delete_log_group_ignore(ctx, log_group_name))

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps({}).encode())
    assert resp["StatusCode"] == 200, f"expected invoke to return 200, got {resp['StatusCode']}"

    logs = ctx.client("logs")
    before = _poll_until(
        lambda: _describe_log_group(ctx, log_group_name),
        lambda g: g is not None,
        timeout_s=90,
        interval_s=3,
    )
    assert before is not None, f"log group {log_group_name} was never created"
    assert "retentionInDays" not in before, "freshly auto-created log group should have no retention policy set"
    logs.tag_log_group(logGroupName=log_group_name, tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-retention"})

    logs.put_retention_policy(logGroupName=log_group_name, retentionInDays=7)

    after = _poll_until(
        lambda: _describe_log_group(ctx, log_group_name),
        lambda g: g is not None and g.get("retentionInDays") == 7,
        timeout_s=30,
        interval_s=2,
    )
    assert after is not None and after.get("retentionInDays") == 7, (
        f"expected retentionInDays=7 after PutRetentionPolicy, got {after}"
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-retention"}],
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
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-retention"},
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


def _describe_log_group(ctx, log_group_name: str) -> dict[str, Any] | None:
    logs = ctx.client("logs")
    resp = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
    for g in resp.get("logGroups", []):
        if g["logGroupName"] == log_group_name:
            return g
    return None


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
