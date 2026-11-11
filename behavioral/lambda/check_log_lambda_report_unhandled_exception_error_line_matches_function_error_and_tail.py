"""log-lambda-report-unhandled-exception-error-line-matches-function-error-and-tail."""

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

CHECK = "log-lambda-report-unhandled-exception-error-line-matches-function-error-and-tail"
GROUP = "logs"
SERVICES = ["lambda"]

HANDLER = """\
def inner(m):
    raise ValueError("BOOM-" + m)


def handler(event, context):
    print("before-" + event["marker"])
    if event.get("boom"):
        inner(event["marker"])
    return {"ok": event["marker"]}
"""


def _nbsp_indent(frame_line: str) -> str:
    """The Python runtime renders a traceback frame's leading spaces as U+00A0 in the text log."""
    stripped = frame_line.lstrip(" ")
    return "\u00a0" * (len(frame_line) - len(stripped)) + stripped


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An unhandled exception's Invoke error payload, its single `[ERROR]` CloudWatch event and the
    LogType=Tail tail must agree; a successful control invocation logs no [ERROR].
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _make_role(ctx, ctx.client("iam"))

    fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-logrep-"),
        Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip(HANDLER)}, MemorySize=128, Timeout=30,
        Tags={"sim2real": CHECK},
    )
    group = f"/aws/lambda/{fn}"

    m = ctx.unique_name("m-")
    rid, _, err, tail = _invoke(lam, fn, {"marker": m, "boom": True}, expect_error=True)
    assert err.get("errorType") == "ValueError", f"errorType {err.get('errorType')!r}: {err!r}"
    assert err.get("errorMessage") == f"BOOM-{m}", f"errorMessage {err.get('errorMessage')!r}"
    assert err.get("requestId") == rid, (
        f"the error payload names request {err.get('requestId')!r}, the Invoke returned {rid!r}"
    )
    trace = err.get("stackTrace")
    assert isinstance(trace, list) and len(trace) == 2, (
        f"stackTrace must list the two user frames (handler, inner), got {trace!r}"
    )
    assert ", in handler\n" in trace[0] and ", in inner\n" in trace[1], (
        f"stackTrace frames must be outermost-first: {trace!r}"
    )

    control_rid, _, control_body, _ = _invoke(lam, fn, {"marker": m})
    assert control_body == {"ok": m}, f"control invocation returned {control_body!r}"

    streams = _await_group(
        logs, group, lambda s: _has_report(rid)(s) and _has_report(control_rid)(s),
        f"REPORT lines for {rid} and {control_rid} in {group}",
    )
    stream = _stream_of(streams, f"START RequestId: {rid} Version: $LATEST\n")
    inv = _invocation_lines(streams[stream], rid)

    # Rebuilt from the response's own stackTrace, so the channels are compared to each other.
    expected_error = (
        f"[ERROR] ValueError: BOOM-{m}\nTraceback (most recent call last):\n"
        + "".join(_nbsp_indent(line) + "\n" for frame in trace for line in frame.splitlines())
    )
    errors = [e for e in inv if e.startswith("[ERROR]")]
    assert len(errors) == 1, f"expected one [ERROR] event for {rid}, got {errors!r}"
    # CloudWatch stores the multi-line error as ONE event without a trailing newline.
    assert errors[0] == expected_error.rstrip("\n"), (
        f"the [ERROR] event does not match the traceback framing rebuilt from the response's "
        f"stackTrace.\n expected {expected_error.rstrip(chr(10))!r}\n got      {errors[0]!r}"
    )
    assert inv.index(f"before-{m}\n") < inv.index(errors[0]) < inv.index(f"END RequestId: {rid}\n"), (
        f"the handler's print, then [ERROR], then END; slice was {inv!r}"
    )

    # The tail is the same log: each CloudWatch event, newline-terminated, concatenated.
    rebuilt = "".join(e if e.endswith("\n") else e + "\n" for e in inv)
    assert len(rebuilt.encode()) < 4096, f"test premise: the log must fit the 4KB tail ({len(rebuilt)})"
    assert tail == rebuilt, (
        f"the LogType=Tail tail must equal the invocation's CloudWatch log.\n tail {tail!r}\n "
        f"cw   {rebuilt!r}"
    )
    assert expected_error in tail and err["errorType"] in tail and err["errorMessage"] in tail, (
        f"the tail must carry the same errorType/errorMessage/traceback as the response: {tail!r}"
    )

    # Control: the successful invocation in the same function logged no [ERROR] at all.
    control_stream = _stream_of(streams, f"START RequestId: {control_rid} Version: $LATEST\n")
    control_inv = _invocation_lines(streams[control_stream], control_rid)
    assert not any(e.startswith("[ERROR]") for e in control_inv), (
        f"the successful control invocation logged an [ERROR]: {control_inv!r}"
    )
    assert f"before-{m}\n" in control_inv, f"control invocation's print missing: {control_inv!r}"



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
    """This check's own execution role (AWSLambdaBasicExecutionRole), tagged so a leftover can be found."""
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
