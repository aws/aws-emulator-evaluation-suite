"""ruby-filter-log-events-start-end-report-and-handler-output."""

from __future__ import annotations

import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ruby-filter-log-events-start-end-report-and-handler-output"
GROUP = "logs"
SERVICES = ["lambda", "logs"]

HANDLER = """\
def handler(event:, context:)
  puts event["marker"]
  { ok: true }
end
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ruby3.4 invocation's START/END/REPORT platform lines and the handler's own stdout line
    land, each as its own event, in the function's log stream, readable via FilterLogEvents.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _make_role(ctx, ctx.client("iam"))
    fn = _create_function(
        ctx, lam, logs,
        FunctionName=ctx.unique_name("sim2real-behav-rbfl-"),
        Runtime="ruby3.4", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip("index.rb", HANDLER)}, MemorySize=128, Timeout=30,
        Tags={"sim2real": CHECK},
    )
    group = f"/aws/lambda/{fn}"
    marker = ctx.unique_name("sim2real-marker-")

    rid = _invoke(lam, fn, {"marker": marker})

    def _msg(e: dict) -> str:
        """CloudWatch Logs events carry the line's own trailing newline in ``message``."""
        return e["message"].rstrip("\n")

    def _own_events(evs):
        return [e for e in evs if f"RequestId: {rid}" in e["message"] or _msg(e) == marker]

    def _has_all_four(evs):
        own = _own_events(evs)
        return (
            any(_msg(e).startswith("START RequestId:") for e in own)
            and any(_msg(e).startswith("END RequestId:") for e in own)
            and any(_msg(e).startswith("REPORT RequestId:") for e in own)
            and any(_msg(e) == marker for e in own)
        )

    _, events = _await_events(
        logs, group, _has_all_four,
        f"START/marker/END/REPORT lines for request {rid} in {group}",
    )
    own = sorted(_own_events(events), key=lambda e: e["timestamp"])

    starts = [e for e in own if _msg(e).startswith("START RequestId:")]
    ends = [e for e in own if _msg(e).startswith("END RequestId:")]
    reports = [e for e in own if _msg(e).startswith("REPORT RequestId:")]
    markers = [e for e in own if _msg(e) == marker]

    assert len(starts) == 1, f"expected exactly one START line for {rid}, got {starts!r}"
    assert _msg(starts[0]) == f"START RequestId: {rid} Version: $LATEST", (
        f"START line was {_msg(starts[0])!r}"
    )
    assert len(ends) == 1, f"expected exactly one END line for {rid}, got {ends!r}"
    assert _msg(ends[0]) == f"END RequestId: {rid}", f"END line was {_msg(ends[0])!r}"
    assert len(reports) == 1, f"expected exactly one REPORT line for {rid}, got {reports!r}"
    report = _msg(reports[0])
    assert report.startswith(f"REPORT RequestId: {rid}\t"), f"REPORT line was {report!r}"
    for token in ("Duration:", "Billed Duration:", "Memory Size: 128 MB", "Max Memory Used:"):
        assert token in report, f"REPORT line missing {token!r}: {report!r}"

    assert len(markers) == 1, (
        f"expected the handler's own stdout line to appear exactly once, unprefixed, got {markers!r}"
    )

    order = [starts[0]["timestamp"], markers[0]["timestamp"], ends[0]["timestamp"],
             reports[0]["timestamp"]]
    assert order == sorted(order), (
        f"START/handler-output/END/REPORT must be non-decreasing in timestamp, got {order!r}"
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
    """This check's own execution role, tagged with its own scenario id; AWSLambdaBasicExecutionRole if asked."""
    name = ctx.unique_name("sim2real-behav-rbfl-")
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


def _invoke(lam, fn: str, payload: dict) -> str:
    """Synchronous invoke; retries while the role is still propagating. Returns the request id."""
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
    """Every event in ``group`` as {stream, message, timestamp}; [] while the group does not exist."""
    out: list[dict] = []
    kw: dict = {"logGroupName": group}
    try:
        while True:
            page = logs.filter_log_events(**kw)
            out += [
                {"stream": e["logStreamName"], "message": e["message"], "timestamp": e["timestamp"]}
                for e in page.get("events", [])
            ]
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
