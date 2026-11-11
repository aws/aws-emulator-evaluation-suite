"""provided-al2023-application-log-level-fatal-drops-plain-stdout-from-cloudwatch."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provided-al2023-application-log-level-fatal-drops-plain-stdout-from-cloudwatch"
GROUP = "function_config"
SERVICES = ["lambda"]

# A plain stdout line has no "level" key, so Lambda assigns it INFO; a JSON line with
# "level": "FATAL" passes every threshold. The FATAL line is written after the plain one.
BOOTSTRAP = r'''#!/bin/sh
set -u
API="$AWS_LAMBDA_RUNTIME_API"
while true; do
  curl -sS -LD /tmp/hdr -o /tmp/evt "http://$API/2018-06-01/runtime/invocation/next"
  RID=$(awk 'BEGIN{IGNORECASE=1} /^Lambda-Runtime-Aws-Request-Id:/ {print $2}' /tmp/hdr | tr -d '\r')
  MARKER=$(sed -n 's/.*"marker"[ ]*:[ ]*"\([^"]*\)".*/\1/p' /tmp/evt)
  echo "plain-line-$MARKER"
  echo "{\"level\":\"FATAL\",\"message\":\"fatal-line-$MARKER\"}"
  printf '{"ok":true}' > /tmp/resp.json
  curl -sS -X POST "http://$API/2018-06-01/runtime/invocation/$RID/response" -d @/tmp/resp.json >/dev/null
done
'''


def _make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            zf.writestr(info, data)
    return buf.getvalue()


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """With LogFormat=JSON, ApplicationLogLevel=FATAL keeps a provided.al2023 bootstrap's plain
    stdout line (level INFO) out of CloudWatch Logs while its later FATAL line arrives; an
    INFO-threshold twin delivers both. https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-log-level.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _make_role(ctx, ctx.client("iam"))
    code = {"ZipFile": _make_zip([("bootstrap", BOOTSTRAP, 0o100755)])}
    marker = ctx.unique_name("m-")
    plain, fatal = f"plain-line-{marker}", f"fatal-line-{marker}"

    # Positive control: at INFO the plain line is delivered beside the FATAL line.
    control = _create_function(
        ctx, lam,
        FunctionName=ctx.unique_name("sim2real-behav-rtlvl-ctl-"),
        Runtime="provided.al2023", Role=role_arn, Handler="bootstrap", Code=code,
        MemorySize=256, Timeout=30,
        LoggingConfig={"LogFormat": "JSON", "ApplicationLogLevel": "INFO", "SystemLogLevel": "WARN"},
        Tags={"sim2real": CHECK},
    )
    _invoke(lam, control, {"marker": marker})
    control_msgs = _await_messages(
        ctx, logs, f"/aws/lambda/{control}", lambda ms: any(fatal in m for m in ms) and any(plain in m for m in ms),
        f"both lines for {marker!r} in the INFO-threshold function's log group",
    )
    assert any(plain in m for m in control_msgs), f"INFO must deliver the plain line: {control_msgs!r}"

    fn = _create_function(
        ctx, lam,
        FunctionName=ctx.unique_name("sim2real-behav-rtlvl-"),
        Runtime="provided.al2023", Role=role_arn, Handler="bootstrap", Code=code,
        MemorySize=256, Timeout=30,
        LoggingConfig={"LogFormat": "JSON", "ApplicationLogLevel": "FATAL", "SystemLogLevel": "WARN"},
        Tags={"sim2real": CHECK},
    )
    stored = lam.get_function_configuration(FunctionName=fn).get("LoggingConfig") or {}
    assert stored.get("ApplicationLogLevel") == "FATAL", f"ApplicationLogLevel=FATAL not stored: {stored!r}"
    _invoke(lam, fn, {"marker": marker})
    # The FATAL line follows the plain one on the same stream: once it is delivered, the plain
    # line has been filtered rather than delayed.
    msgs = _await_messages(
        ctx, logs, f"/aws/lambda/{fn}", lambda ms: any(fatal in m for m in ms),
        f"the FATAL line for {marker!r} in the FATAL-threshold function's log group",
    )
    leaked = [m for m in msgs if plain in m]
    assert leaked == [], f"ApplicationLogLevel=FATAL must drop the plain (INFO) stdout line, got {leaked!r}"


# ===== helpers =====

_BASIC_EXEC = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the check's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the check's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not observed within {timeout_s:.0f}s; last saw {last!r}")


def _make_role(ctx, iam, *, basic_exec: bool = True) -> str:
    name = ctx.unique_name("sim2real-behav-rtlvl-")
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
        partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
        policy = _BASIC_EXEC.format(partition=partition)
        iam.attach_role_policy(RoleName=name, PolicyArn=policy)
        ctx.on_cleanup(_teardown(
            lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy), "NoSuchEntity",
        ))
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


def _create_function(ctx, lam, **kwargs) -> str:
    name = kwargs["FunctionName"]
    logs = ctx.client("logs")
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
    _wait_ready(ctx, lam, name)
    return name


def _wait_ready(ctx, lam, name: str) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed" or cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{name} failed: {cfg.get('StateReason')} {cfg.get('LastUpdateStatusReason')}"
            )
        return cfg

    return _poll_until(
        ctx, _probe,
        lambda cfg: cfg.get("State") == "Active"
        and cfg.get("LastUpdateStatus") in (None, "Successful"),
        timeout_s=180.0, interval_s=2.0, description=f"{name} Active + LastUpdateStatus=Successful",
    )


def _invoke(lam, fn: str, payload: dict) -> None:
    resp = lam.invoke(FunctionName=fn, Payload=json.dumps(payload).encode())
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"Invoke({fn}) failed: {resp['StatusCode']!r} {resp.get('FunctionError')!r} {raw[:300]!r}"
    )


def _messages(logs, group: str) -> list[str]:
    out: list[str] = []
    kw: dict = {"logGroupName": group}
    try:
        while True:
            page = logs.filter_log_events(**kw)
            out += [e["message"] for e in page.get("events", [])]
            if not page.get("nextToken"):
                return out
            kw["nextToken"] = page["nextToken"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise


def _await_messages(ctx, logs, group: str, predicate, description: str) -> list[str]:
    return _poll_until(
        ctx, lambda: _messages(logs, group), predicate,
        timeout_s=180.0, interval_s=2.0, description=description,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
