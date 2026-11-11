"""log-lambda-report-json-format-platform-and-application-records-field-by-field."""

from __future__ import annotations

import base64
import io
import json
import re
import sys
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-lambda-report-json-format-platform-and-application-records-field-by-field"
GROUP = "logs"
SERVICES = ["lambda"]

MEMORY_MB = 320

HANDLER = """\
import logging

logging.getLogger().setLevel(logging.INFO)


def handler(event, context):
    print("plain-" + event["marker"])
    logging.getLogger().info("app-info-%s", event["marker"])
    return {"ok": True}
"""

_ISO_S = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


def _records(msgs: list[str]) -> list[dict | None]:
    """Parse each event as JSON; None for an event that is not a JSON object."""
    out: list[dict | None] = []
    for raw in msgs:
        try:
            val = json.loads(raw)
        except ValueError:
            out.append(None)
            continue
        out.append(val if isinstance(val, dict) else None)
    return out


def _platform(recs, kind: str, rid: str | None = None) -> list[dict]:
    return [
        r for r in recs
        if r and r.get("type") == kind
        and (rid is None or (r.get("record") or {}).get("requestId") == rid)
    ]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With LogFormat=JSON, platform.initStart/start/report and application records carry this
    function's ARN, memory, request ids and stream name field by field; initDurationMs is on the
    cold report only, and print() stays plain text.
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _make_role(ctx, ctx.client("iam"))

    fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-logrep-"),
        Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip(HANDLER)}, MemorySize=MEMORY_MB, Timeout=30,
        LoggingConfig={"LogFormat": "JSON", "ApplicationLogLevel": "INFO", "SystemLogLevel": "INFO"},
        Tags={"sim2real": CHECK},
    )
    fn_arn = lam.get_function(FunctionName=fn)["Configuration"]["FunctionArn"]
    group = f"/aws/lambda/{fn}"

    m = ctx.unique_name("m-")
    cold_rid, _, _, _ = _invoke(lam, fn, {"marker": m})
    warm_rid, _, _, _ = _invoke(lam, fn, {"marker": m})

    def _both_reported(streams):
        recs = _records([x for ms in streams.values() for x in ms])
        return all(_platform(recs, "platform.report", r) for r in (cold_rid, warm_rid))

    streams = _await_group(logs, group, _both_reported, f"platform.report for both requests in {group}")

    start_stream = None
    for name, msgs in streams.items():
        if _platform(_records(msgs), "platform.start", cold_rid):
            start_stream = name
    assert start_stream, f"no platform.start record for {cold_rid} in {group}: {streams!r}"
    msgs = streams[start_stream]
    recs = _records(msgs)

    # platform.initStart — once, at the head of the environment's stream.
    inits = _platform(recs, "platform.initStart")
    assert len(inits) == 1 and recs.index(inits[0]) == 0, (
        f"one platform.initStart must open the stream, got {inits!r} (first event {msgs[0]!r})"
    )
    ir = inits[0]["record"]
    assert ir.get("functionName") == fn, f"initStart functionName {ir.get('functionName')!r} != {fn!r}"
    assert ir.get("functionVersion") == "$LATEST", f"initStart functionVersion {ir!r}"
    assert ir.get("initializationType") == "on-demand", f"initStart initializationType {ir!r}"
    assert ir.get("phase") == "init", f"initStart phase {ir!r}"
    assert ir.get("instanceId") == start_stream, (
        f"initStart instanceId {ir.get('instanceId')!r} must equal the stream it is in {start_stream!r}"
    )
    assert ir.get("instanceMaxMemory") == MEMORY_MB * 1024 * 1024, (
        f"instanceMaxMemory {ir.get('instanceMaxMemory')!r} != {MEMORY_MB} MiB in bytes"
    )
    assert _ISO_S.match(inits[0].get("time", "")), f"initStart time {inits[0].get('time')!r}"

    for rid in (cold_rid, warm_rid):
        (start,) = _platform(recs, "platform.start", rid)
        sr = start["record"]
        assert sr == {"requestId": rid, "functionArn": fn_arn, "version": "$LATEST"}, (
            f"platform.start record for {rid} was {sr!r}; expected requestId/functionArn/version"
        )
        (report,) = _platform(recs, "platform.report", rid)
        rr = report["record"]
        met = rr.get("metrics") or {}
        assert rr.get("status") == "success", f"platform.report status {rr!r}"
        assert met.get("memorySizeMB") == MEMORY_MB, (
            f"platform.report memorySizeMB {met.get('memorySizeMB')!r} != configured {MEMORY_MB}"
        )
        assert isinstance(met.get("durationMs"), (int, float)) and met["durationMs"] > 0, (
            f"durationMs {met.get('durationMs')!r}"
        )
        assert isinstance(met.get("billedDurationMs"), int) and met["billedDurationMs"] >= met["durationMs"], (
            f"billedDurationMs {met.get('billedDurationMs')!r} vs durationMs {met.get('durationMs')!r}"
        )
        assert isinstance(met.get("maxMemoryUsedMB"), int) and 0 < met["maxMemoryUsedMB"] <= MEMORY_MB, (
            f"maxMemoryUsedMB {met.get('maxMemoryUsedMB')!r}"
        )
        assert recs.index(start) < recs.index(report), f"platform.start must precede platform.report"

        # The application record for this request, field by field.
        app = [r for r in recs if r and r.get("requestId") == rid and "type" not in r]
        assert len(app) == 1, f"expected one application record for {rid}, got {app!r}"
        a = app[0]
        assert a.get("level") == "INFO" and a.get("message") == f"app-info-{m}", (
            f"application record level/message wrong: {a!r}"
        )
        assert a.get("logger") == "root", f"application record logger {a.get('logger')!r}"
        assert _ISO_S.match(a.get("timestamp", "")), f"application timestamp {a.get('timestamp')!r}"
        assert recs.index(start) < recs.index(a) < recs.index(report), (
            "the application record must sit between platform.start and platform.report"
        )

    cold_met = _platform(recs, "platform.report", cold_rid)[0]["record"]["metrics"]
    warm_met = _platform(recs, "platform.report", warm_rid)[0]["record"]["metrics"]
    assert isinstance(cold_met.get("initDurationMs"), (int, float)) and cold_met["initDurationMs"] > 0, (
        f"the cold platform.report must carry initDurationMs: {cold_met!r}"
    )
    assert "initDurationMs" not in warm_met, (
        f"the warm platform.report (same stream {start_stream}) must NOT carry initDurationMs: {warm_met!r}"
    )

    # print() is not structured: it stays a plain text event even under LogFormat=JSON.
    assert msgs.count(f"plain-{m}\n") == 2, (
        f"each invocation's print must arrive as the raw line {'plain-' + m!r}; events {msgs!r}"
    )
    # And no text-format platform line leaked through.
    text_platform = [x for x in msgs if re.match(r"^(START|END|REPORT|INIT_START) ", x)]
    assert text_platform == [], f"LogFormat=JSON must not emit text platform lines: {text_platform!r}"


_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"

# The text-format platform lines, exactly as the execution environment writes them.
_START_RE = re.compile(r"^START RequestId: (?P<rid>[0-9a-f-]{36}) Version: (?P<ver>\S+)\n$")
_END_RE = re.compile(r"^END RequestId: (?P<rid>[0-9a-f-]{36})\n$")
_REPORT_RE = re.compile(
    r"^REPORT RequestId: (?P<rid>[0-9a-f-]{36})\t"
    r"Duration: (?P<dur>\d+\.\d{2}) ms\t"
    r"Billed Duration: (?P<billed>\d+) ms\t"
    r"Memory Size: (?P<mem>\d+) MB\t"
    r"Max Memory Used: (?P<maxmem>\d+) MB\t"
    r"(?:Init Duration: (?P<init>\d+\.\d{2}) ms\t)?\n$"
)
# YYYY/MM/DD/[<qualifier>]<32 lowercase hex>
_STREAM_RE = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2})/\[(?P<qual>[^\]]+)\](?P<env>[0-9a-f]{32})$"
)


def _zip(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _error_code(fn) -> str:
    """The error code of a call that MUST fail. Raises if it succeeds — never a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"the call was expected to be refused but succeeded: {result!r}")


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


def _make_role(ctx, iam) -> str:
    """This check's own execution role (AWSLambdaBasicExecutionRole), tagged with the check id."""
    name = ctx.unique_name("sim2real-behav-logrep-")
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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    # IAM propagation exposes no pollable condition; the bounded role-propagation retry in
    # _create_function is what makes first use correct, so no fixed sleep is added here.
    return role["Role"]["Arn"]


def _group_exists(logs, group: str) -> bool:
    page = logs.describe_log_groups(logGroupNamePrefix=group)
    return any(g["logGroupName"] == group for g in page.get("logGroups", []))


def _reap_log_group(logs, group: str) -> None:
    """delete_function does not remove /aws/lambda/<fn>, and a buffered flush can RECREATE it after
    the delete — so reap in a loop until it has stayed absent for three consecutive reads."""
    quiet = 0
    for _ in range(14):
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
        time.sleep(4)
    if _group_exists(logs, group):
        raise RuntimeError(f"log group {group} kept reappearing after delete")


def _create_function(ctx, lam, logs, **kwargs) -> str:
    """CreateFunction retrying ONLY the documented role-propagation refusal; waits for Active."""
    name = kwargs["FunctionName"]
    group = f"/aws/lambda/{name}"
    # Registered BEFORE the function exists, so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(logs, group))
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
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
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


def _invoke(lam, fn: str, payload: dict, *, qualifier: str | None = None, expect_error: bool = False):
    """Synchronous invoke with LogType=Tail. Returns (request_id, response, parsed body, tail)."""
    kwargs = {"FunctionName": fn, "Payload": json.dumps(payload).encode(), "LogType": "Tail"}
    if qualifier:
        kwargs["Qualifier"] = qualifier
    resp = lam.invoke(**kwargs)
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
    assert re.fullmatch(r"[0-9a-f-]{36}", rid or ""), f"Invoke returned no usable RequestId: {rid!r}"
    assert resp.get("LogResult"), "Invoke with LogType=Tail returned no LogResult"
    tail = base64.b64decode(resp["LogResult"]).decode("utf-8")
    return rid, resp, json.loads(raw) if raw else None, tail


def _read_group(logs, group: str) -> dict[str, list[str]]:
    """{stream name: [message, ...] in stream order}. {} while the group does not exist yet."""
    streams: dict[str, list[str]] = {}
    try:
        names: list[str] = []
        kw: dict = {"logGroupName": group}
        while True:
            page = logs.describe_log_streams(**kw)
            names += [s["logStreamName"] for s in page.get("logStreams", [])]
            if not page.get("nextToken"):
                break
            kw["nextToken"] = page["nextToken"]
        for name in names:
            msgs: list[str] = []
            kw = {"logGroupName": group, "logStreamName": name, "startFromHead": True}
            while True:
                page = logs.get_log_events(**kw)
                msgs += [e["message"] for e in page.get("events", [])]
                tok = page.get("nextForwardToken")
                if tok is None or tok == kw.get("nextToken"):
                    break
                kw["nextToken"] = tok
            streams[name] = msgs
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return {}
        raise
    return streams


def _await_group(logs, group: str, predicate, description: str, timeout_s: float = 180.0):
    """Poll the whole group until predicate(streams) holds. Asserts content, never latency."""
    return _poll_until(
        lambda: _read_group(logs, group), predicate,
        timeout_s=timeout_s, interval_s=4.0, description=description,
    )


def _stream_of(streams: dict[str, list[str]], line: str) -> str:
    """The single stream holding exactly `line`; fails if it is in none or in several."""
    holders = [s for s, msgs in streams.items() if line in msgs]
    assert len(holders) == 1, f"{line!r} must be in exactly one stream, found in {holders!r}"
    return holders[0]


def _has_report(rid: str):
    prefix = f"REPORT RequestId: {rid}\t"
    return lambda streams: any(m.startswith(prefix) for msgs in streams.values() for m in msgs)


def _report_of(streams: dict[str, list[str]], rid: str) -> dict:
    prefix = f"REPORT RequestId: {rid}\t"
    lines = [m for msgs in streams.values() for m in msgs if m.startswith(prefix)]
    assert len(lines) == 1, f"expected exactly one REPORT line for {rid}, got {lines!r}"
    m = _REPORT_RE.match(lines[0])
    assert m, f"REPORT line does not have the documented field layout: {lines[0]!r}"
    return m.groupdict()


def _invocation_lines(msgs: list[str], rid: str) -> list[str]:
    """The slice of one stream from this request's START line through its REPORT line."""
    starts = [i for i, m in enumerate(msgs) if m.startswith(f"START RequestId: {rid} ")]
    reports = [i for i, m in enumerate(msgs) if m.startswith(f"REPORT RequestId: {rid}\t")]
    assert len(starts) == 1 and len(reports) == 1, (
        f"expected one START and one REPORT for {rid}, got START@{starts} REPORT@{reports}"
    )
    assert starts[0] < reports[0], f"REPORT precedes START for {rid}: {starts} {reports}"
    return msgs[starts[0]:reports[0] + 1]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
