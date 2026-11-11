"""logging-config-json-format-filters-application-log-level."""

from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "logging-config-json-format-filters-application-log-level"
GROUP = 'function_config'
SERVICES = ['lambda']

# The handler emits one line at each of three levels plus one bare print. Under
# ApplicationLogLevel=WARN only the WARNING line may be DELIVERED to CloudWatch Logs, and under
# LogFormat=JSON that line must arrive as a structured record rather than free text.
HANDLER = """\
import logging

log = logging.getLogger()
log.setLevel(logging.DEBUG)


def handler(event, context):
    marker = event["marker"]
    log.debug("sim2real-debug-%s", marker)
    log.info("sim2real-info-%s", marker)
    log.warning("sim2real-warn-%s", marker)
    print("sim2real-print-%s" % marker)
    return {"marker": marker}
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _role_arn(ctx):
    """Create this run's own Lambda execution role (once per run) and return its ARN."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_ready = (err.get("Code") == "InvalidParameterValueException"
                         and err.get("Message") == _ROLE_NOT_READY)
            if not not_ready or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        # The service creates /aws/lambda/<fn> on first invoke and it OUTLIVES the function.
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll(probe, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = probe()
        if got:
            return got
        time.sleep(interval_s)
    return None


def _wait_active(lam, fn, timeout_s=180):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')}")
        if cfg["State"] == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        return None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not reach State=Active within {timeout_s}s"
    return cfg


def _all_log_messages(ctx, group, timeout_s, until):
    """Paginate filter_log_events over the whole group until `until(messages)` holds.

    Absence assertions are only meaningful once the line that MUST be there has been observed.
    """
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    messages: list[str] = []
    while time.monotonic() < deadline:
        messages = []
        try:
            paginator = logs.get_paginator("filter_log_events")
            for page in paginator.paginate(logGroupName=group):
                messages.extend(e["message"] for e in page.get("events", []))
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(2)
            continue
        if until(messages):
            return messages
        time.sleep(2)
    return messages


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """LogFormat=JSON with ApplicationLogLevel=WARN delivers only the WARNING line, as a JSON record
    with level and requestId; DEBUG/INFO lines and prints shown in the Tail never reach CloudWatch.
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-logfn-")
    _create_function(lam,
        FunctionName=fn, Runtime="python3.12", Handler="index.handler",
        Role=_role_arn(ctx), Code={"ZipFile": _make_zip(HANDLER)},
        MemorySize=256, Timeout=30,
        LoggingConfig={
            "LogFormat": "JSON", "ApplicationLogLevel": "WARN", "SystemLogLevel": "INFO",
        },
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    cfg = _wait_active(lam, fn)
    stored = cfg.get("LoggingConfig") or {}
    assert stored.get("LogFormat") == "JSON", f"LogFormat did not round-trip: {stored!r}"
    assert stored.get("ApplicationLogLevel") == "WARN", (
        f"ApplicationLogLevel did not round-trip: {stored!r}"
    )

    marker = ctx.unique_name("m").rsplit("-", 1)[-1]
    warn_marker = f"sim2real-warn-{marker}"
    info_marker = f"sim2real-info-{marker}"
    debug_marker = f"sim2real-debug-{marker}"
    print_marker = f"sim2real-print-{marker}"

    resp = lam.invoke(
        FunctionName=fn, LogType="Tail", Payload=json.dumps({"marker": marker}).encode()
    )
    body = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"StatusCode {resp['StatusCode']!r}: {body!r}"
    assert "FunctionError" not in resp, (
        f"the handler failed with {resp.get('FunctionError')!r}: {body!r}"
    )
    assert json.loads(body) == {"marker": marker}, f"unexpected return value: {body!r}"
    request_id = resp["ResponseMetadata"]["RequestId"]
    tail = base64.b64decode(resp["LogResult"]).decode()

    # The control leg for every absence below: the handler DID emit the quieter lines. Their later
    # absence from CloudWatch is therefore the ApplicationLogLevel filter and not a silent handler.
    assert debug_marker in tail, (
        f"the DEBUG line never reached the invocation's own tail log, so its absence from "
        f"CloudWatch would prove nothing about filtering: {tail!r}"
    )
    assert info_marker in tail, (
        f"the INFO line never reached the invocation's own tail log: {tail!r}"
    )
    assert warn_marker in tail, f"the WARNING line never reached the tail log: {tail!r}"

    group = f"/aws/lambda/{fn}"
    messages = _all_log_messages(
        ctx, group, timeout_s=240, until=lambda ms: any(warn_marker in m for m in ms)
    )
    assert any(warn_marker in m for m in messages), (
        f"the WARNING line was never delivered to {group} within 240s; delivered messages were "
        f"{messages!r}"
    )

    # Application records carry a "level"; platform records carry "type": "platform.*". Split
    # structurally rather than by string surgery on the message.
    app_records = []
    for msg in messages:
        stripped = msg.strip()
        if not stripped.startswith("{"):
            continue
        try:
            rec = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and "level" in rec:
            app_records.append(rec)

    warn_records = [r for r in app_records if warn_marker in str(r.get("message", ""))]
    assert len(warn_records) == 1, (
        f"expected exactly one structured application record carrying {warn_marker!r}, got "
        f"{warn_records!r}"
    )
    warn_record = warn_records[0]
    # ApplicationLogLevel is 'WARN' but the record carries Python's own level NAME, 'WARNING'.
    assert warn_record["level"] == "WARNING", (
        f"the JSON log record does not carry the emitting level: {warn_record!r}"
    )
    assert warn_record.get("requestId") == request_id, (
        f"JSON log record requestId {warn_record.get('requestId')!r} does not match the "
        f"invocation {request_id!r} — the record is not correlated to its invocation"
    )
    assert warn_record.get("timestamp"), (
        f"the JSON log record carries no timestamp field: {warn_record!r}"
    )

    # Effect-absent: everything below WARN was dropped on the way to CloudWatch.
    for name, quiet in (("DEBUG", debug_marker), ("INFO", info_marker)):
        leaked = [m for m in messages if quiet in m]
        assert leaked == [], (
            f"a {name} line was delivered to CloudWatch Logs despite ApplicationLogLevel=WARN: "
            f"{leaked!r}"
        )
    leaked_print = [m for m in messages if print_marker in m]
    assert leaked_print == [], (
        f"an unstructured print() reached CloudWatch Logs despite ApplicationLogLevel=WARN: "
        f"{leaked_print!r}"
    )

    # LogFormat=JSON applies to the platform records too, so nothing in the group is free text.
    unstructured = [m for m in messages if not m.strip().startswith("{")]
    assert unstructured == [], (
        f"LogFormat=JSON left unstructured lines in {group}: {unstructured!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
