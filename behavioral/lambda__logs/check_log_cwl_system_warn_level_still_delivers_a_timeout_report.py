"""log-cwl-system-warn-level-still-delivers-a-timeout-report."""

from __future__ import annotations

import base64
import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-cwl-system-warn-level-still-delivers-a-timeout-report"
GROUP = "logs"
SERVICES = ["lambda", "logs"]

HANDLER = """\
import time


def handler(event, context):
    time.sleep(event.get("sleep", 0))
    return {"ok": True}
"""


# timing:real-time — workflow: 1 s https://docs.aws.amazon.com/lambda/latest/dg/configuration-timeout.html
@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """At SystemLogLevel=WARN a successful invocation's platform records never reach CloudWatch Logs,
    but a timed-out invocation's platform.runtimeDone and platform.report, both status `timeout`,
    are delivered.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-log-level.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _make_role(ctx, ctx.client("iam"))
    fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-l4-"),
        Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip("index.py", HANDLER)}, MemorySize=128, Timeout=1,
        LoggingConfig={"LogFormat": "JSON", "ApplicationLogLevel": "INFO", "SystemLogLevel": "WARN"},
        Tags={"sim2real": CHECK},
    )
    group = f"/aws/lambda/{fn}"

    ok_rid, body, _ = _invoke_tail(lam, fn, {})
    assert body == {"ok": True}, f"the control invocation must succeed: {body!r}"
    to_rid, err, _ = _invoke_tail(lam, fn, {"sleep": 5}, expect_error=True)
    assert err.get("errorType") == "Sandbox.Timedout", f"the second invocation must time out: {err!r}"

    def _plat(evs, rid):
        out = {}
        for e in evs:
            r = _json_obj(e["message"])
            if r and "type" in r and (r.get("record") or {}).get("requestId") == rid:
                out.setdefault(r["type"], []).append(r["record"])
        return out

    latency, events = _await_events(
        logs, group, lambda evs: "platform.report" in _plat(evs, to_rid),
        f"the timeout platform.report for {to_rid} in {group}",
    )
    plat = _plat(events, to_rid)
    assert set(plat) == {"platform.runtimeDone", "platform.report"}, (
        f"at WARN only the timeout's runtimeDone and report may be delivered; got {sorted(plat)!r}"
    )
    (rd,) = plat["platform.runtimeDone"]
    (rep,) = plat["platform.report"]
    assert rd.get("status") == "timeout" and rep.get("status") == "timeout", f"{rd!r} {rep!r}"
    assert (rep.get("metrics") or {}).get("durationMs", 0) >= 1000, (
        f"a 1 s timeout reports at least 1000 ms: {rep!r}"
    )
    leaked = _held_absent(
        logs, group, lambda msg: ok_rid in msg or '"type":"platform.start"' in msg, latency,
    )
    assert leaked == [], f"successful-invocation platform records crossed at WARN: {leaked!r}"


# ===== helpers =====

_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"
_RID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _zip(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry on an observable condition. RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _make_role(ctx, iam, *, basic_exec: bool = True) -> str:
    """This check's own tagged execution role; AWSLambdaBasicExecutionRole if asked."""
    name = ctx.unique_name("sim2real-behav-l4-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    if basic_exec:
        iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
        ctx.on_cleanup(_teardown(
            lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC), "NoSuchEntity",
        ))
    # IAM propagation exposes no pollable condition; the bounded role-propagation retry in
    # _create_function is what makes first use correct, so no fixed sleep is added here.
    return role["Role"]["Arn"]


def _group_exists(logs, group: str) -> bool:
    kw: dict = {"logGroupNamePrefix": group}
    while True:
        page = logs.describe_log_groups(**kw)
        if any(g["logGroupName"] == group for g in page.get("logGroups", [])):
            return True
        if not page.get("nextToken"):
            return False
        kw["nextToken"] = page["nextToken"]


def _reap_log_group(logs, group: str) -> None:
    """delete_function does not remove the function's log group, and a buffered flush can RECREATE
    it after the delete — so reap in a loop until it has stayed absent for three consecutive reads."""
    quiet = 0
    for _ in range(12):
        if _group_exists(logs, group):
            quiet = 0
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            quiet += 1
            if quiet >= 3:
                return
        time.sleep(3)
    if _group_exists(logs, group):
        raise RuntimeError(f"log group {group} kept reappearing after delete")


def _create_function(ctx, lam, logs, **kwargs) -> str:
    """CreateFunction retrying ONLY the documented role-propagation refusal; waits for Active."""
    name = kwargs["FunctionName"]
    # Registered BEFORE the function exists, so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + 90.0
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            code = exc.response["Error"]["Code"]
            if code != "InvalidParameterValueException" or _ROLE_PROPAGATION not in msg:
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"CreateFunction({name}) kept failing on role propagation: {msg}")
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    _wait_ready(lam, name)
    return name


def _wait_ready(lam, name: str) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed" or cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{name} failed: {cfg.get('StateReason')} {cfg.get('LastUpdateStatusReason')}"
            )
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("State") == "Active"
        and cfg.get("LastUpdateStatus") in (None, "Successful"),
        timeout_s=180.0, interval_s=2.0, description=f"{name} Active + LastUpdateStatus=Successful",
    )


def _invoke_tail(lam, fn: str, payload: dict, *, expect_error: bool = False):
    """Synchronous invoke with LogType=Tail. Returns (request_id, parsed body, decoded tail)."""
    resp = lam.invoke(FunctionName=fn, Payload=json.dumps(payload).encode(), LogType="Tail")
    raw = resp["Payload"].read().decode()
    assert resp["StatusCode"] == 200, f"Invoke StatusCode {resp['StatusCode']!r}: {raw[:300]!r}"
    if expect_error:
        assert resp.get("FunctionError") == "Unhandled", (
            f"expected FunctionError='Unhandled', got {resp.get('FunctionError')!r}: {raw[:300]!r}"
        )
    else:
        assert "FunctionError" not in resp, (
            f"{fn} raised unexpectedly: {resp.get('FunctionError')!r} {raw[:400]!r}"
        )
    rid = resp["ResponseMetadata"]["RequestId"]
    assert _RID.fullmatch(rid or ""), f"Invoke returned no usable RequestId: {rid!r}"
    assert resp.get("LogResult"), "Invoke with LogType=Tail returned no LogResult"
    tail = base64.b64decode(resp["LogResult"]).decode("utf-8")
    return rid, (json.loads(raw) if raw else None), tail


def _json_lines(text: str) -> list:
    """Each line of a log text parsed as a JSON object, or None where the line is not one."""
    out: list = []
    for line in text.splitlines():
        try:
            val = json.loads(line)
        except ValueError:
            out.append(None)
            continue
        out.append(val if isinstance(val, dict) else None)
    return out


def _events(logs, group: str) -> list[dict]:
    """Every event in ``group`` as {stream, message}; [] while the group does not exist yet."""
    out: list[dict] = []
    kw: dict = {"logGroupName": group}
    try:
        while True:
            page = logs.filter_log_events(**kw)
            out += [{"stream": e["logStreamName"], "message": e["message"]} for e in page.get("events", [])]
            if not page.get("nextToken"):
                break
            kw["nextToken"] = page["nextToken"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise
    return out


def _await_events(logs, group: str, predicate, description: str):
    """(latency_s, events) once predicate(events) holds. Asserts content, never latency."""
    start = time.monotonic()
    events = _poll_until(
        lambda: _events(logs, group), predicate,
        timeout_s=150.0, interval_s=2.0, description=description,
    )
    return time.monotonic() - start, events


def _held_absent(logs, group: str, forbidden, latency_s: float) -> list[dict]:
    """Every event matching ``forbidden`` seen over max(10 s, 3 x the control's latency)."""
    deadline = time.monotonic() + max(10.0, 3.0 * latency_s)
    seen: list[dict] = []
    while True:
        seen = [e for e in _events(logs, group) if forbidden(e["message"])]
        if seen or time.monotonic() >= deadline:
            return seen
        time.sleep(2.0)


def _json_obj(message: str):
    """The event parsed as a JSON object, else None."""
    try:
        val = json.loads(message)
    except ValueError:
        return None
    return val if isinstance(val, dict) else None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
