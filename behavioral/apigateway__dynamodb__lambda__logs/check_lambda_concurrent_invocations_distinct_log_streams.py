"""lambda-concurrent-invocations-distinct-log-streams."""
from __future__ import annotations

import io
import json
import re
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-concurrent-invocations-distinct-log-streams"
GROUP = "shared-state"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_MARKER_RE = re.compile(r"MARKER::([0-9a-f]{32})")


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent invocations each get their own uncorrupted response, and every invocation's
    log marker lands intact in exactly the log stream its execution environment reports, so the
    streams used are exactly the environments that served the invocations."""
    fn_name = ctx.unique_name("sim2real-concstreams-")
    role_arn, _ = _create_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
        "concstreams",
        CHECK,
    )
    code = (
        "import time\n"
        "def handler(event, context):\n"
        "    marker = event['marker']\n"
        "    print('MARKER::' + marker)\n"
        "    time.sleep(0.5)\n"
        "    return {'echo': marker, 'stream': context.log_stream_name}\n"
    )
    _create_function_with_role_retry(ctx, fn_name, role_arn, _make_zip(code), tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=fn_name))
    log_group_name = f"/aws/lambda/{fn_name}"
    ctx.on_cleanup(lambda: _delete_log_group_ignore(ctx, log_group_name))

    # prime: one invocation so the log group/first stream exist and role-assumption is warm
    lam = ctx.client("lambda")
    warm_marker = uuid.uuid4().hex
    lam.invoke(FunctionName=fn_name, Payload=json.dumps({"marker": warm_marker}).encode())
    _poll_until(
        lambda: _log_group_exists(ctx, log_group_name),
        lambda found: found,
        timeout_s=_cap(ctx, 90.0),
        interval_s=3,
    )

    n = 6
    markers = [uuid.uuid4().hex for _ in range(n)]

    def _invoke_one(marker: str) -> dict[str, Any]:
        r = lam.invoke(FunctionName=fn_name, Payload=json.dumps({"marker": marker}).encode())
        return {"marker": marker, "status": r["StatusCode"], "error": r.get("FunctionError"),
                 "payload": json.loads(r["Payload"].read())}

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_invoke_one, m) for m in markers]
        for fut in as_completed(futures):
            results.append(fut.result())

    # each concurrent invocation's synchronous response is intact and not cross-contaminated
    assert len(results) == n, f"expected {n} synchronous responses, got {len(results)}"
    for r in results:
        assert r["status"] == 200 and r["error"] is None, (
            f"invocation for marker {r['marker']} did not complete cleanly: "
            f"status={r['status']} error={r['error']}"
        )
        payload = r["payload"]
        assert isinstance(payload, dict) and payload.get("echo") == r["marker"], (
            f"response payload {payload!r} does not match the request's own marker {r['marker']}"
        )
        assert isinstance(payload.get("stream"), str) and payload["stream"], (
            f"invocation for marker {r['marker']} reported no log stream name: {payload!r}"
        )

    expected = set(markers)
    marker_streams = _poll_until(
        lambda: _found_marker_streams(ctx, log_group_name),
        lambda seen: expected.issubset(seen.keys()),
        timeout_s=_cap(ctx, 90.0),
        interval_s=4,
    )
    found = set(marker_streams.keys())
    missing = expected - found
    assert not missing, f"markers never observed in any log stream: {missing}"
    # every captured marker string must be a value we actually sent (regex+set-equality rules out
    # concatenation/truncation corruption across concurrently-written streams)
    unexpected = {m for m in found if m not in expected and m != warm_marker}
    assert not unexpected, f"log streams contained marker strings that were never sent: {unexpected}"

    # each environment writes one stream: a marker lands only in the stream its invocation
    # reported, so the set of streams used is exactly the set of environments reported
    reported = {r["marker"]: r["payload"]["stream"] for r in results}
    for marker in markers:
        assert marker_streams[marker] == {reported[marker]}, (
            f"marker {marker} landed in streams {sorted(marker_streams[marker])}, expected only the "
            f"stream its invocation reported ({reported[marker]!r})"
        )
    streams_used = {s for marker in markers for s in marker_streams[marker]}
    assert streams_used == set(reported.values()), (
        f"log streams used {sorted(streams_used)} differ from the streams the invocations "
        f"reported {sorted(set(reported.values()))}"
    )


def _cap(ctx, own_s: float, margin_s: float = 15.0) -> float:
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _make_zip(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_role(ctx, statements: list[dict[str, Any]], suffix: str, check_id: str | None = None) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-{suffix}-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    kwargs: dict[str, Any] = dict(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    if check_id:
        kwargs["Tags"] = [{"Key": "sim2real", "Value": check_id}]
    resp = iam.create_role(**kwargs)
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
    env: dict[str, str] | None = None, timeout_s: float = 90.0, tags: dict[str, str] | None = None,
) -> dict[str, Any]:
    lam = ctx.client("lambda")
    kwargs: dict[str, Any] = dict(
        FunctionName=name, Runtime="python3.12", Role=role_arn, Handler=handler,
        Code={"ZipFile": zip_bytes}, Timeout=30, MemorySize=128,
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    if tags:
        kwargs["Tags"] = tags
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


def _found_marker_streams(ctx, log_group_name: str) -> dict[str, set[str]]:
    """marker -> set of log stream names it was observed in."""
    logs = ctx.client("logs")
    try:
        streams = logs.describe_log_streams(logGroupName=log_group_name)["logStreams"]
    except logs.exceptions.ResourceNotFoundException:
        return {}
    found: dict[str, set[str]] = {}
    for stream in streams:
        events = logs.get_log_events(
            logGroupName=log_group_name, logStreamName=stream["logStreamName"], startFromHead=True
        )["events"]
        for e in events:
            for marker in _MARKER_RE.findall(e["message"]):
                found.setdefault(marker, set()).add(stream["logStreamName"])
    return found


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
