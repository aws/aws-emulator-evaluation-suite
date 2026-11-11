"""lambda-put-log-events-via-sdk-positive."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-put-log-events-via-sdk-positive"
GROUP = "sdk-call"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A handler that explicitly calls logs.create_log_group/create_log_stream/put_log_events
    via boto3 successfully writes a custom entry into a log group distinct from the
    function's own /aws/lambda/<name> group."""
    fn_name = ctx.unique_name("sim2real-sdkputlog-")
    custom_log_group = ctx.unique_name("/sim2real/custom-sdk-log-")
    role_arn, _ = _create_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
        "sdkputlog",
    )
    code = (
        "import time\n"
        "import boto3\n"
        "logs = boto3.client('logs')\n"
        "def handler(event, context):\n"
        "    lg = event['log_group']\n"
        "    ls = event['stream']\n"
        "    try:\n"
        "        logs.create_log_group(logGroupName=lg)\n"
        "    except logs.exceptions.ResourceAlreadyExistsException:\n"
        "        pass\n"
        "    logs.create_log_stream(logGroupName=lg, logStreamName=ls)\n"
        "    logs.put_log_events(logGroupName=lg, logStreamName=ls, logEvents=[\n"
        "        {'timestamp': int(time.time() * 1000), 'message': 'custom-sdk-message:' + event['marker']}\n"
        "    ])\n"
        "    return {'ok': True}\n"
    )
    _create_function_with_role_retry(ctx, fn_name, role_arn, _make_zip(code))
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=fn_name))
    auto_log_group = f"/aws/lambda/{fn_name}"
    ctx.on_cleanup(lambda: _delete_log_group_ignore(ctx, auto_log_group))
    ctx.on_cleanup(lambda: _delete_log_group_ignore(ctx, custom_log_group))

    stream_name = ctx.unique_name("stream-")
    marker = uuid.uuid4().hex
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=fn_name,
        Payload=json.dumps({"log_group": custom_log_group, "stream": stream_name, "marker": marker}).encode(),
    )
    assert resp["StatusCode"] == 200, f"expected StatusCode 200, got {resp['StatusCode']}"
    assert "FunctionError" not in resp, f"unexpected FunctionError on invoke: {resp.get('FunctionError')}"
    payload = json.loads(resp["Payload"].read())
    assert payload == {"ok": True}, f"expected handler to report {{'ok': True}}, got {payload}"

    logs = ctx.client("logs")
    events = _poll_until(
        lambda: logs.get_log_events(logGroupName=custom_log_group, logStreamName=stream_name, startFromHead=True)[
            "events"
        ],
        lambda evts: len(evts) >= 1,
        timeout_s=60,
        interval_s=3,
        timeout_msg=f"no log events observed in {custom_log_group}/{stream_name} within 60s",
    )
    assert len(events) == 1, f"expected exactly 1 event in {custom_log_group}/{stream_name}, got {len(events)}"
    assert events[0]["message"] == f"custom-sdk-message:{marker}", (
        f"expected message 'custom-sdk-message:{marker}', got {events[0]['message']!r}"
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


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0, timeout_msg: str | None = None):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(timeout_msg or f"condition not met within {timeout_s}s (last result: {result!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
