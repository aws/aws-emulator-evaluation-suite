"""deep-lambda-3-runtime-pin-foreign-runtime-arn-rejected."""

from __future__ import annotations

import io
import json
import re
import sys
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-3-runtime-pin-foreign-runtime-arn-rejected"
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


NODE_HANDLER = "exports.handler = async () => ({ ok: true });\n"


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "cap:c3",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """PutRuntimeManagementConfig(Manual) refuses a nodejs22.x runtime version ARN on a python3.12
    function, leaving it in Auto and the next cold start on its own ARN; its own ARN is accepted.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-update.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _make_role(ctx, ctx.client("iam"))

    py_fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-rtpin-"),
        Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip(HANDLER)}, MemorySize=128, Timeout=30,
        Tags={"sim2real": CHECK},
    )
    node_fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-rtpin-"),
        Runtime="nodejs22.x", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip(NODE_HANDLER, "index.js")}, MemorySize=128, Timeout=30,
        Tags={"sim2real": CHECK},
    )
    group = f"/aws/lambda/{py_fn}"
    node_arn = lam.get_function_configuration(FunctionName=node_fn)["RuntimeVersionConfig"][
        "RuntimeVersionArn"
    ]

    cold_rid, cold_body = _invoke(lam, py_fn)
    streams = _await_group(logs, group, _has_start(cold_rid), f"START for {cold_rid} in {group}")
    _, py_arn = _init_start_before(streams, cold_rid)
    assert py_arn != node_arn, (
        f"python3.12 and nodejs22.x must not share a runtime version ARN, both are {py_arn!r}"
    )

    # The break: offer the python function the nodejs function's ARN.
    code, msg = _error(lambda: lam.put_runtime_management_config(
        FunctionName=py_fn, UpdateRuntimeOn="Manual", RuntimeVersionArn=node_arn
    ))
    assert code == "InvalidParameterValueException", (
        f"a foreign-runtime ARN must be refused with InvalidParameterValueException, got {code!r}: {msg!r}"
    )
    expected_msg = (
        f"Runtime version ARN ({node_arn}) is not compatible with your function's runtime (python3.12)."
    )
    assert msg == expected_msg, (
        f"the refusal must name the runtime mismatch: expected {expected_msg!r}, got {msg!r}"
    )
    state = lam.get_runtime_management_config(FunctionName=py_fn)
    assert state["UpdateRuntimeOn"] == "Auto" and not state.get("RuntimeVersionArn"), (
        f"a refused pin must leave the function in Auto with no pinned ARN, got "
        f"{ {k: v for k, v in state.items() if k != 'ResponseMetadata'}!r}"
    )

    # Effect absent at runtime: a NEW environment still initialises on the python ARN.
    lam.update_function_configuration(
        FunctionName=py_fn, Environment={"Variables": {"SIM2REAL_GENERATION": "2"}}
    )
    _wait_ready(lam, py_fn)
    recold_rid, recold_body = _invoke(lam, py_fn)
    assert recold_body["env"] != cold_body["env"], (
        f"after UpdateFunctionConfiguration the invocation must run in a NEW environment; it "
        f"reported the old env id {recold_body['env']!r}"
    )
    streams = _await_group(logs, group, _has_start(recold_rid), f"START for {recold_rid} in {group}")
    _, recold_arn = _init_start_before(streams, recold_rid)
    assert recold_arn == py_arn, (
        f"after the refused pin the new environment must still run {py_arn!r}, got {recold_arn!r}"
    )

    # Positive control: the function's OWN ARN is an acceptable Manual pin.
    put = lam.put_runtime_management_config(
        FunctionName=py_fn, UpdateRuntimeOn="Manual", RuntimeVersionArn=py_arn
    )
    assert put["UpdateRuntimeOn"] == "Manual" and put["RuntimeVersionArn"] == py_arn, (
        f"pinning the function's own ARN must be accepted, got "
        f"{ {k: v for k, v in put.items() if k != 'ResponseMetadata'}!r}"
    )
    got = lam.get_runtime_management_config(FunctionName=py_fn)
    assert got["UpdateRuntimeOn"] == "Manual" and got["RuntimeVersionArn"] == py_arn, (
        f"GetRuntimeManagementConfig after the accepted pin returned "
        f"{ {k: v for k, v in got.items() if k != 'ResponseMetadata'}!r}"
    )


_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"
_INIT_START_RE = re.compile(
    r"^INIT_START Runtime Version: (?P<ver>\S+)\tRuntime Version ARN: (?P<arn>\S+)\n$"
)


def _zip(source: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _error(call) -> tuple[str, str]:
    """(code, message) of a call that MUST fail. Raises if it succeeds — never a falsy sentinel."""
    try:
        result = call()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
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
