"""log-lambda-report-init-duration-only-on-cold-report-line."""

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

CHECK = "log-lambda-report-init-duration-only-on-cold-report-line"
GROUP = "logs"
SERVICES = ["lambda"]

MEMORY_MB = 160

# ENV_ID is minted once per execution environment (module scope runs during INIT only), so the
# handler's own answer tells us which environment served each invocation, independently of logs.
HANDLER = """\
import uuid
ENV_ID = uuid.uuid4().hex


def handler(event, context):
    return {"env": ENV_ID, "stream": context.log_stream_name}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Init Duration appears on the REPORT line of a cold invocation and is ABSENT from a warm one
    in the same environment (proven by a module-scope id); a configuration change forces a new
    environment whose REPORT carries it again, and INIT_START precedes only the cold START."""
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _make_role(ctx, ctx.client("iam"))

    fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-logrep-"),
        Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip(HANDLER)}, MemorySize=MEMORY_MB, Timeout=30,
        Tags={"sim2real": CHECK},
    )
    group = f"/aws/lambda/{fn}"

    cold_rid, _, cold_body, _ = _invoke(lam, fn, {})
    warm_rid, _, warm_body, _ = _invoke(lam, fn, {})
    assert warm_body["env"] == cold_body["env"], (
        f"the back-to-back second invocation must reuse the first environment for the warm leg to "
        f"mean anything; env ids were {cold_body['env']!r} then {warm_body['env']!r}"
    )

    # Force a new execution environment: any configuration change retires the old one.
    lam.update_function_configuration(
        FunctionName=fn, Environment={"Variables": {"SIM2REAL_GENERATION": "2"}}
    )
    _wait_ready(lam, fn)
    recold_rid, _, recold_body, _ = _invoke(lam, fn, {})
    assert recold_body["env"] != cold_body["env"], (
        f"after UpdateFunctionConfiguration the invocation must run in a new environment; it "
        f"reported the old env id {recold_body['env']!r}"
    )

    streams = _await_group(
        logs, group,
        lambda s: all(_has_report(r)(s) for r in (cold_rid, warm_rid, recold_rid)),
        f"REPORT lines for {cold_rid}, {warm_rid} and {recold_rid} in {group}",
    )

    cold = _report_of(streams, cold_rid)
    warm = _report_of(streams, warm_rid)
    recold = _report_of(streams, recold_rid)

    # Positive control: the cold REPORT carries Init Duration.
    assert cold["init"] is not None and float(cold["init"]) > 0.0, (
        f"the cold invocation's REPORT must carry a positive Init Duration; fields {cold!r}"
    )
    # The claim: the warm REPORT, same environment, does NOT.
    assert warm["init"] is None, (
        f"the warm invocation ran in the already-initialized environment {warm_body['env']!r}, yet "
        f"its REPORT carries Init Duration {warm['init']!r}"
    )
    # Second positive control: a new environment brings Init Duration back.
    assert recold["init"] is not None and float(recold["init"]) > 0.0, (
        f"the invocation in the NEW environment must carry Init Duration again; fields {recold!r}"
    )
    for label, rep in (("cold", cold), ("warm", warm), ("re-cold", recold)):
        assert int(rep["mem"]) == MEMORY_MB, f"{label} REPORT Memory Size {rep['mem']!r} != {MEMORY_MB}"

    # The warm Billed Duration is the Duration rounded up to the next millisecond (the displayed
    # Duration is truncated to 2 decimals, hence the 1.01 ms upper bound). The cold one is billed
    # for the init phase too, so it covers Init Duration as well.
    warm_dur, warm_billed = float(warm["dur"]), int(warm["billed"])
    assert warm_dur <= warm_billed < warm_dur + 1.01, (
        f"warm Billed Duration {warm_billed} ms is not Duration {warm_dur} ms rounded up to 1 ms"
    )
    assert int(cold["billed"]) >= float(cold["init"]), (
        f"cold Billed Duration {cold['billed']} ms must cover Init Duration {cold['init']} ms"
    )

    # INIT_START is written once per environment, immediately before that environment's first
    # START, and never before a warm START.
    cold_stream = _stream_of(streams, f"START RequestId: {cold_rid} Version: $LATEST\n")
    warm_stream = _stream_of(streams, f"START RequestId: {warm_rid} Version: $LATEST\n")
    msgs = streams[cold_stream]
    cold_start_at = msgs.index(f"START RequestId: {cold_rid} Version: $LATEST\n")
    warm_start_at = streams[warm_stream].index(f"START RequestId: {warm_rid} Version: $LATEST\n")
    assert cold_start_at > 0 and msgs[cold_start_at - 1].startswith("INIT_START Runtime Version: "), (
        f"the cold START must be preceded by INIT_START; stream {cold_stream} begins {msgs[:3]!r}"
    )
    assert not streams[warm_stream][warm_start_at - 1].startswith("INIT_START"), (
        f"the warm START must not be preceded by INIT_START: {streams[warm_stream][:6]!r}"
    )
    inits = [m for m in msgs if m.startswith("INIT_START")]
    assert len(inits) == 1, f"one environment must write INIT_START once, {cold_stream} holds {inits!r}"


# ===== helpers =====

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
    """This check's own tagged execution role (AWSLambdaBasicExecutionRole)."""
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
