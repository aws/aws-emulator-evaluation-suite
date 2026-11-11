"""iam-role-trusts-lambda-service-assumed."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-trusts-lambda-service-assumed"
GROUP = "trust-policy"
SERVICES = ["events", "lambda", "sns"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda assumes a role trusting lambda.amazonaws.com: a synchronous Invoke returns 200
    with the expected payload and no FunctionError, and the function's CloudWatch Logs carry its
    REPORT line."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    role_name = ctx.unique_name("sim2real-behav-tp-lrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    log_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="logs", PolicyDocument=json.dumps(log_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="logs"))

    fn_name = ctx.unique_name("sim2real-behav-tp-fn-")
    code = (
        "def handler(event, context):\n"
        "    return {'ok': True, 'marker': event.get('marker')}\n"
    )
    zip_bytes = _lambda_zip(code)

    _create_function_with_retry(lam, fn_name, role_arn, zip_bytes, timeout_s=90.0)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_for_active(lam, fn_name, timeout_s=90.0)

    marker = ctx.unique_name("marker-")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps({"marker": marker}).encode())
    assert resp["StatusCode"] == 200, f"expected StatusCode 200, got {resp['StatusCode']}"
    assert "FunctionError" not in resp, f"expected no FunctionError, got {resp.get('FunctionError')!r}"
    payload = json.loads(resp["Payload"].read())
    assert payload == {"ok": True, "marker": marker}, f"expected {{'ok': True, 'marker': {marker!r}}}, got {payload!r}"

    log_group = f"/aws/lambda/{fn_name}"
    ctx.on_cleanup(lambda: _delete_log_group_if_exists(logs, log_group))
    report_seen = _poll_for_report_line(logs, log_group, timeout_s=90.0)
    assert report_seen, (
        "no REPORT line ever appeared in the function's own log group -- "
        "the lambda.amazonaws.com-trusted execution role was never usable to write logs"
    )


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_function_with_retry(lam: Any, fn_name: str, role_arn: str, zip_bytes: bytes, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=15,
            )["FunctionArn"]
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"CreateFunction never succeeded (role propagation?): {last_exc}")


def _wait_for_active(lam: Any, fn_name: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=fn_name)["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError("function entered Failed state")
        time.sleep(3)
    raise AssertionError("function never reached Active state")


def _delete_log_group_if_exists(logs: Any, log_group: str) -> None:
    try:
        logs.delete_log_group(logGroupName=log_group)
    except logs.exceptions.ResourceNotFoundException:
        pass


def _poll_for_report_line(logs: Any, log_group: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group, filterPattern="REPORT")
        except logs.exceptions.ResourceNotFoundException:
            time.sleep(4)
            continue
        if resp.get("events"):
            return True
        time.sleep(4)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
