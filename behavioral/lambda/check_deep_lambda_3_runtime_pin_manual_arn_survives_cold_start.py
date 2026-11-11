"""deep-lambda-3-runtime-pin-manual-arn-survives-cold-start."""

from __future__ import annotations

import io
import json
import re
import sys
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-3-runtime-pin-manual-arn-survives-cold-start"
GROUP = "runtime_management"
SERVICES = ["lambda"]

# ENV_ID is minted once per execution environment (module scope runs during INIT only), so the
# handler's own answer proves which environment served each invocation, independently of logs.
HANDLER = """\
import uuid
ENV_ID = uuid.uuid4().hex


def handler(event, context):
    return {"env": ENV_ID}
"""


@tags("concern:representation", "axis:happy-path", "cap:c3", "dp:api", "plane:control",
      "plane:data")
def run(ctx) -> None:
    """The runtime version ARN in a cold start's INIT_START log line is accepted by
    PutRuntimeManagementConfig(Manual), and the next cold start in a new environment reports it.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-update.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _make_role(ctx, ctx.client("iam"))

    fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-rtpin-"),
        Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip(HANDLER)}, MemorySize=128, Timeout=30,
        Tags={"sim2real": CHECK},
    )
    group = f"/aws/lambda/{fn}"

    before = lam.get_runtime_management_config(FunctionName=fn)
    assert before["UpdateRuntimeOn"] == "Auto", (
        f"a new function must start in Auto runtime-update mode, got {before['UpdateRuntimeOn']!r}"
    )

    # Leg 1: a cold start, and the ARN its own INIT_START line reports.
    cold_rid, cold_body = _invoke(lam, fn)
    streams = _await_group(logs, group, _has_start(cold_rid), f"START for {cold_rid} in {group}")
    cold_version, cold_arn = _init_start_before(streams, cold_rid)
    assert re.fullmatch(rf"arn:aws:lambda:{re.escape(ctx.region)}::runtime:[0-9a-f]{{64}}", cold_arn), (
        f"INIT_START Runtime Version ARN is not a regional runtime ARN: {cold_arn!r}"
    )
    assert cold_version.startswith("python:3.12."), (
        f"a python3.12 function's INIT_START must name a python:3.12 build, got {cold_version!r}"
    )
    reported = lam.get_function_configuration(FunctionName=fn)["RuntimeVersionConfig"]
    assert reported.get("RuntimeVersionArn") == cold_arn, (
        f"GetFunctionConfiguration reports runtime {reported!r}, but the environment initialised "
        f"on {cold_arn!r}"
    )

    # Leg 2: pin that exact ARN.
    put = lam.put_runtime_management_config(
        FunctionName=fn, UpdateRuntimeOn="Manual", RuntimeVersionArn=cold_arn
    )
    assert put["UpdateRuntimeOn"] == "Manual" and put["RuntimeVersionArn"] == cold_arn, (
        f"PutRuntimeManagementConfig must echo Manual + the pinned ARN, got "
        f"{ {k: v for k, v in put.items() if k != 'ResponseMetadata'}!r}"
    )
    got = lam.get_runtime_management_config(FunctionName=fn)
    assert got["UpdateRuntimeOn"] == "Manual" and got["RuntimeVersionArn"] == cold_arn, (
        f"GetRuntimeManagementConfig after the pin returned "
        f"{ {k: v for k, v in got.items() if k != 'ResponseMetadata'}!r}"
    )
    _wait_ready(lam, fn)

    # Leg 3: force a brand-new environment and read ITS INIT_START.
    lam.update_function_configuration(
        FunctionName=fn, Environment={"Variables": {"SIM2REAL_GENERATION": "2"}}
    )
    _wait_ready(lam, fn)
    recold_rid, recold_body = _invoke(lam, fn)
    assert recold_body["env"] != cold_body["env"], (
        f"after UpdateFunctionConfiguration the invocation must run in a NEW environment; it "
        f"reported the old env id {recold_body['env']!r}"
    )
    streams = _await_group(logs, group, _has_start(recold_rid), f"START for {recold_rid} in {group}")
    recold_version, recold_arn = _init_start_before(streams, recold_rid)
    assert recold_arn == cold_arn, (
        f"the function is pinned (Manual) to {cold_arn!r}, but the new environment initialised on "
        f"{recold_arn!r}"
    )
    assert recold_version == cold_version, (
        f"same pinned ARN must be the same runtime build: {cold_version!r} then {recold_version!r}"
    )
    inits = [m for msgs in streams.values() for m in msgs if m.startswith("INIT_START")]
    assert len(inits) == 2, f"two environments must write exactly two INIT_START lines, got {inits!r}"

    after = lam.get_function_configuration(FunctionName=fn)["RuntimeVersionConfig"]
    assert after.get("RuntimeVersionArn") == cold_arn, (
        f"a pinned function must keep reporting the pinned ARN after an update, got {after!r}"
    )


_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"
_INIT_START_RE = re.compile(
    r"^INIT_START Runtime Version: (?P<ver>\S+)\tRuntime Version ARN: (?P<arn>\S+)\n$"
)


def _zip(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


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
    """This check's own execution role (AWSLambdaBasicExecutionRole), tagged for cleanup."""
    name = ctx.unique_name("sim2real-behav-rtpin-")
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


def _invoke(lam, fn: str):
    """Synchronous invoke. Returns (request_id, parsed body)."""
    resp = lam.invoke(FunctionName=fn, Payload=b"{}")
    raw = resp["Payload"].read().decode()
    assert resp["StatusCode"] == 200, f"Invoke StatusCode {resp['StatusCode']!r}: {raw[:300]!r}"
    assert "FunctionError" not in resp, f"{fn} raised: {resp.get('FunctionError')!r} {raw[:400]!r}"
    rid = resp["ResponseMetadata"]["RequestId"]
    assert re.fullmatch(r"[0-9a-f-]{36}", rid or ""), f"Invoke returned no usable RequestId: {rid!r}"
    return rid, json.loads(raw)


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


def _has_start(rid: str):
    line = f"START RequestId: {rid} Version: $LATEST\n"
    return lambda streams: any(line in msgs for msgs in streams.values())


def _init_start_before(streams: dict[str, list[str]], rid: str) -> tuple[str, str]:
    """(runtime version, runtime version ARN) from the INIT_START line that immediately precedes
    this request's START in its own stream — i.e. the init of the environment that served it."""
    line = f"START RequestId: {rid} Version: $LATEST\n"
    holders = [s for s, msgs in streams.items() if line in msgs]
    assert len(holders) == 1, f"{line!r} must be in exactly one stream, found in {holders!r}"
    msgs = streams[holders[0]]
    at = msgs.index(line)
    assert at > 0, f"START for {rid} is the first line of {holders[0]}; no INIT_START precedes it"
    m = _INIT_START_RE.match(msgs[at - 1])
    assert m, (
        f"the line before a cold START must be INIT_START with a Runtime Version ARN, got "
        f"{msgs[at - 1]!r}"
    )
    return m.group("ver"), m.group("arn")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
