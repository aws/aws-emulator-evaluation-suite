"""log-cwl-system-debug-level-delivers-runtime-done-and-init-records."""

from __future__ import annotations

import base64
import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-cwl-system-debug-level-delivers-runtime-done-and-init-records"
GROUP = "logs"
SERVICES = ["lambda", "logs"]

HANDLER = """\
def handler(event, context):
    return {"ok": True}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SystemLogLevel=DEBUG delivers to one stream, in order, platform.initStart, initRuntimeDone
    (success), initReport (on-demand, durationMs), start, runtimeDone (success, the requestId,
    durationMs) and report.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-log-level.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _make_role(ctx, ctx.client("iam"))
    fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-l4-"),
        Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip("index.py", HANDLER)}, MemorySize=128, Timeout=30,
        LoggingConfig={"LogFormat": "JSON", "ApplicationLogLevel": "INFO", "SystemLogLevel": "DEBUG"},
        Tags={"sim2real": CHECK},
    )
    group = f"/aws/lambda/{fn}"

    rid, _, _ = _invoke_tail(lam, fn, {})

    def _recs(evs):
        return [(e["stream"], r) for e in evs if (r := _json_obj(e["message"])) and "type" in r]

    def _reported(evs):
        return any(r["type"] == "platform.report" and r["record"].get("requestId") == rid
                   for _, r in _recs(evs))

    _, events = _await_events(logs, group, _reported, f"platform.report for {rid} in {group}")
    recs = _recs(events)
    streams = {s for s, r in recs if r["record"].get("requestId") == rid}
    assert len(streams) == 1, f"the request's records must sit in one stream, got {streams!r}"
    (stream,) = streams
    order = [r["type"] for s, r in recs if s == stream]
    want = ["platform.initStart", "platform.initRuntimeDone", "platform.initReport",
            "platform.start", "platform.runtimeDone", "platform.report"]
    assert order == want, f"platform record sequence in {stream} must be {want!r}; got {order!r}"
    by_type = {r["type"]: r["record"] for s, r in recs if s == stream}
    ird = by_type["platform.initRuntimeDone"]
    assert (ird.get("initializationType"), ird.get("phase"), ird.get("status")) == (
        "on-demand", "init", "success"), f"initRuntimeDone {ird!r}"
    irep = by_type["platform.initReport"]
    assert irep.get("initializationType") == "on-demand" and irep.get("status") == "success", f"{irep!r}"
    assert isinstance((irep.get("metrics") or {}).get("durationMs"), (int, float)), f"initReport {irep!r}"
    rd = by_type["platform.runtimeDone"]
    assert rd.get("requestId") == rid and rd.get("status") == "success", f"runtimeDone {rd!r}"
    assert isinstance((rd.get("metrics") or {}).get("durationMs"), (int, float)), f"runtimeDone {rd!r}"


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
