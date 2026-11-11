"""ruby-application-log-level-error-drops-warn-from-cloudwatch-delivery."""

from __future__ import annotations

import json
import re
import time
import zipfile
import io

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ruby-application-log-level-error-drops-warn-from-cloudwatch-delivery"
GROUP = "logs"
SERVICES = ["lambda", "logs"]

HANDLER = """\
require "logger"

def handler(event:, context:)
  marker = event["marker"]
  logger = Logger.new($stdout)
  logger.warn("sim2real-warn-#{marker}")
  logger.error("sim2real-error-#{marker}")
  { marker: marker }
end
"""


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """ApplicationLogLevel=ERROR delivers the ERROR line to CloudWatch Logs but never the WARN
    line, while a WARN-threshold twin of the same handler delivers both — the threshold that
    reaches CloudWatch is the configured one, not just whatever the runtime happened to write.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-advanced.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _make_role(ctx, ctx.client("iam"))

    marker = ctx.unique_name("m-")
    warn_marker = f"sim2real-warn-{marker}"
    error_marker = f"sim2real-error-{marker}"

    # Positive control: ApplicationLogLevel=WARN admits both WARN and ERROR to CloudWatch.
    control_fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-rbael-ctl-"),
        Runtime="ruby3.4", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip("index.rb", HANDLER)}, MemorySize=128, Timeout=30,
        LoggingConfig={"LogFormat": "JSON", "ApplicationLogLevel": "WARN", "SystemLogLevel": "WARN"},
        Tags={"sim2real": CHECK},
    )
    control_group = f"/aws/lambda/{control_fn}"
    _invoke(lam, control_fn, {"marker": marker})
    _, control_events = _await_events(
        logs, control_group, lambda evs: any(error_marker in e["message"] for e in evs),
        f"the ERROR line for {marker!r} in {control_group}",
    )
    assert any(warn_marker in e["message"] for e in control_events), (
        f"ApplicationLogLevel=WARN must deliver the WARN line to CloudWatch too: "
        f"{[e['message'] for e in control_events]!r}"
    )

    # Restricted: ApplicationLogLevel=ERROR admits ERROR but drops WARN.
    fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-rbael-"),
        Runtime="ruby3.4", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip("index.rb", HANDLER)}, MemorySize=128, Timeout=30,
        LoggingConfig={"LogFormat": "JSON", "ApplicationLogLevel": "ERROR", "SystemLogLevel": "WARN"},
        Tags={"sim2real": CHECK},
    )
    group = f"/aws/lambda/{fn}"
    _invoke(lam, fn, {"marker": marker})
    _, events = _await_events(
        logs, group, lambda evs: any(error_marker in e["message"] for e in evs),
        f"the ERROR line for {marker!r} in {group}",
    )
    leaked = [e["message"] for e in events if warn_marker in e["message"]]
    assert leaked == [], (
        f"ApplicationLogLevel=ERROR must drop the WARN line from CloudWatch delivery, got {leaked!r}"
    )
    assert any(error_marker in e["message"] for e in events), (
        f"ApplicationLogLevel=ERROR must still deliver the ERROR line: "
        f"{[e['message'] for e in events]!r}"
    )


# ===== helpers =====

_BASIC_EXEC = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_PROPAGATION = "cannot be assumed by Lambda"
_RID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _zip(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _make_role(ctx, iam, *, basic_exec: bool = True) -> str:
    name = ctx.unique_name("sim2real-behav-rbael-")
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
    name = kwargs["FunctionName"]
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


def _invoke(lam, fn: str, payload: dict) -> str:
    deadline = time.monotonic() + 90.0
    while True:
        try:
            resp = lam.invoke(FunctionName=fn, Payload=json.dumps(payload).encode())
            break
        except ClientError as exc:
            if "cannot be assumed" not in str(exc) or time.monotonic() > deadline:
                raise
            time.sleep(3)
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"Invoke StatusCode {resp['StatusCode']!r}: {raw[:300]!r}"
    assert "FunctionError" not in resp, f"{fn} raised unexpectedly: {resp.get('FunctionError')!r} {raw[:400]!r}"
    rid = resp["ResponseMetadata"]["RequestId"]
    assert _RID.fullmatch(rid or ""), f"Invoke returned no usable RequestId: {rid!r}"
    return rid


def _events(logs, group: str) -> list[dict]:
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
    start = time.monotonic()
    events = _poll_until(
        lambda: _events(logs, group), predicate,
        timeout_s=150.0, interval_s=2.0, description=description,
    )
    return time.monotonic() - start, events


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
