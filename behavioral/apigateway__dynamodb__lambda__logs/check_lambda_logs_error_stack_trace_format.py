"""lambda-logs-error-stack-trace-format."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-logs-error-stack-trace-format"
GROUP = "data-format"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An unhandled exception is reported via FunctionError and a REPORT line + traceback in logs."""
    fn_name = ctx.unique_name("sim2real-errfmt-")
    role_arn, _ = _create_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
        "errfmt",
    )
    marker = uuid.uuid4().hex
    code = (
        "def handler(event, context):\n"
        f"    raise ValueError('boom-{marker}')\n"
    )
    _create_function_with_role_retry(ctx, fn_name, role_arn, _make_zip(code))
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=fn_name))
    log_group_name = f"/aws/lambda/{fn_name}"
    ctx.on_cleanup(lambda: _delete_log_group_ignore(ctx, log_group_name))

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps({}).encode())
    assert resp["StatusCode"] == 200, f"expected StatusCode 200, got {resp['StatusCode']}"
    assert resp.get("FunctionError") == "Unhandled", f"expected FunctionError=Unhandled, got {resp.get('FunctionError')!r}"
    payload = json.loads(resp["Payload"].read())
    assert payload.get("errorType") == "ValueError", f"expected errorType=ValueError, got {payload.get('errorType')!r}"
    assert f"boom-{marker}" in payload.get("errorMessage", ""), (
        f"expected 'boom-{marker}' in errorMessage, got {payload.get('errorMessage')!r}"
    )

    messages = _poll_until(
        lambda: _all_log_messages(ctx, log_group_name),
        lambda msgs: any("REPORT RequestId" in m for m in msgs) and any(f"boom-{marker}" in m for m in msgs),
        timeout_s=90,
        interval_s=4,
    )
    report_lines = [m for m in messages if m.startswith("REPORT RequestId")]
    assert report_lines, f"no REPORT line found among {len(messages)} log events"
    assert "Duration:" in report_lines[0] and "Billed Duration:" in report_lines[0], (
        f"REPORT line missing Duration/Billed Duration fields: {report_lines[0]!r}"
    )

    traceback_lines = [m for m in messages if "Traceback (most recent call last)" in m]
    assert traceback_lines, "no stack trace was written to the log stream"
    error_lines = [m for m in messages if f"boom-{marker}" in m]
    assert error_lines, "exception message was never written to the log stream"


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        Tags={"sim2real": CHECK},
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


def _all_log_messages(ctx, log_group_name: str) -> list[str]:
    logs = ctx.client("logs")
    try:
        streams = logs.describe_log_streams(logGroupName=log_group_name)["logStreams"]
    except logs.exceptions.ResourceNotFoundException:
        return []
    out: list[str] = []
    for stream in streams:
        events = logs.get_log_events(
            logGroupName=log_group_name, logStreamName=stream["logStreamName"], startFromHead=True
        )["events"]
        out.extend(e["message"] for e in events)
    return out


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last result={result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
