"""lambda-logs-missing-putlogevents-permission-negative."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-logs-missing-putlogevents-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role without logs:PutLogEvents gets AccessDeniedException from put_log_events in the handler
    and no event is written; with the permission the call succeeds and the message is in the stream."""
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
        "    try:\n"
        "        logs.create_log_stream(logGroupName=lg, logStreamName=ls)\n"
        "    except logs.exceptions.ResourceAlreadyExistsException:\n"
        "        pass\n"
        "    try:\n"
        "        logs.put_log_events(logGroupName=lg, logStreamName=ls, logEvents=[\n"
        "            {'timestamp': int(time.time() * 1000), 'message': 'should-not-land:' + event['marker']}\n"
        "        ])\n"
        "        return {'ok': True}\n"
        "    except Exception as e:\n"
        "        err = e.response['Error']\n"
        "        return {'ok': False, 'error_code': err['Code'], 'message': err.get('Message')}\n"
    )

    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    # --- positive control first: measure how long a permitted put_log_events call takes
    #     to become visible, so the negative's absence window below can be calibrated to
    #     that measured latency instead of an arbitrary guess ---
    good_fn = ctx.unique_name("sim2real-withputperm-")
    good_log_group = ctx.unique_name("/sim2real/withputperm-log-")
    good_role_arn, _ = _create_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
        "withputperm",
    )
    _create_function_with_role_retry(ctx, good_fn, good_role_arn, _make_zip(code))
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=good_fn))
    ctx.on_cleanup(lambda: _delete_log_group_ignore(ctx, f"/aws/lambda/{good_fn}"))
    ctx.on_cleanup(lambda: _delete_log_group_ignore(ctx, good_log_group))

    good_stream = ctx.unique_name("stream-")
    good_marker = uuid.uuid4().hex
    good_invoke_started = time.monotonic()
    resp2 = lam.invoke(
        FunctionName=good_fn,
        Payload=json.dumps({"log_group": good_log_group, "stream": good_stream, "marker": good_marker}).encode(),
    )
    assert resp2["StatusCode"] == 200, f"expected StatusCode 200 for positive control, got {resp2['StatusCode']}"
    payload2 = json.loads(resp2["Payload"].read())
    assert payload2 == {"ok": True}, f"expected positive control to report ok=True, got {payload2}"

    good_events = _poll_until(
        lambda: logs.get_log_events(logGroupName=good_log_group, logStreamName=good_stream, startFromHead=True)[
            "events"
        ],
        lambda evts: len(evts) >= 1,
        timeout_s=60,
        interval_s=3,
    )
    positive_latency_s = time.monotonic() - good_invoke_started
    assert len(good_events) == 1, f"expected exactly 1 event in positive control stream, got {len(good_events)}"
    assert good_events[0]["message"] == f"should-not-land:{good_marker}", (
        f"expected message 'should-not-land:{good_marker}', got {good_events[0]['message']!r}"
    )

    # --- negative: role can create the group/stream but cannot put events into them ---
    bad_fn = ctx.unique_name("sim2real-noputperm-")
    bad_log_group = ctx.unique_name("/sim2real/noputperm-log-")
    bad_role_arn, bad_role_name = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream"], "Resource": "*"}],
        "noputperm",
    )
    _create_function_with_role_retry(ctx, bad_fn, bad_role_arn, _make_zip(code))
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=bad_fn))
    ctx.on_cleanup(lambda: _delete_log_group_ignore(ctx, f"/aws/lambda/{bad_fn}"))
    ctx.on_cleanup(lambda: _delete_log_group_ignore(ctx, bad_log_group))

    bad_stream = ctx.unique_name("stream-")
    bad_marker = uuid.uuid4().hex
    resp = lam.invoke(
        FunctionName=bad_fn,
        Payload=json.dumps({"log_group": bad_log_group, "stream": bad_stream, "marker": bad_marker}).encode(),
    )
    assert resp["StatusCode"] == 200, f"expected StatusCode 200 for negative invoke, got {resp['StatusCode']}"
    assert "FunctionError" not in resp, f"unexpected FunctionError on negative invoke: {resp.get('FunctionError')}"
    payload = json.loads(resp["Payload"].read())
    assert payload["ok"] is False, f"expected handler to report ok=False, got {payload}"
    assert payload["error_code"] == "AccessDeniedException", (
        f"expected error_code 'AccessDeniedException', got {payload.get('error_code')!r}"
    )
    want_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{bad_role_name}/{bad_fn} is not "
        f"authorized to perform: logs:PutLogEvents on resource: arn:aws:logs:{ctx.region}:"
        f"{ctx.account}:log-group:{bad_log_group}:log-stream:{bad_stream} because no "
        f"identity-based policy allows the logs:PutLogEvents action"
    )
    assert payload.get("message") == want_message, (
        f"expected the denial message {want_message!r}, got {payload.get('message')!r}"
    )

    # Hold absence for >= 3x the positive control's own measured delivery latency: a flat
    # sleep would score a correct-but-slower target as blocked, and a single read right
    # after invoke would miss a target that denies synchronously but still writes the
    # event asynchronously underneath. Freeze-detect instead: every poll in the window
    # must show zero events.
    absence_window_s = max(3 * positive_latency_s, 15.0)
    deadline = time.monotonic() + absence_window_s
    while time.monotonic() < deadline:
        try:
            events = logs.get_log_events(
                logGroupName=bad_log_group, logStreamName=bad_stream, startFromHead=True
            )["events"]
        except logs.exceptions.ResourceNotFoundException:
            events = []
        assert events == [], f"put_log_events was denied but {len(events)} event(s) landed in the stream: {events}"
        time.sleep(3)


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
        Tags=[{"Key": "sim2real", "Value": "lambda-logs-missing-putlogevents-permission-negative"}],
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
        Tags={"sim2real": "lambda-logs-missing-putlogevents-permission-negative"},
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
