"""logging-config-log-group-override-routes-logs-and-leaves-the-default-group-absent."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logging-config-log-group-override-routes-logs-and-leaves-the-default-group-absent"
GROUP = "logs"
SERVICES = ["lambda"]

_HANDLER = """\
import logging

logging.getLogger().setLevel(logging.INFO)


def handler(event, context):
    logging.getLogger().info("routed-marker %s", event["marker"])
    return {"marker": event["marker"]}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """LoggingConfig.LogGroup redirects logs: the named group receives the invocation's records, the
    default /aws/lambda/<name> group is never created, and pointing back moves the next invocation.
    Each absence is asserted only after the marker arrived at the group it was routed to.
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    role_arn = _create_execution_role(ctx, iam)

    custom_group = f"/sim2real/behav/{ctx.unique_name('logroute-')}"
    logs.create_log_group(logGroupName=custom_group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=custom_group))

    fn = ctx.unique_name("sim2real-behav-logroute-")
    default_group = f"/aws/lambda/{fn}"
    _create_function(
        ctx,
        lam,
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.py": _HANDLER})},
        MemorySize=128,
        Timeout=30,
        LoggingConfig={"LogFormat": "JSON", "LogGroup": custom_group},
        Tags={"sim2real": CHECK},
    )
    _wait_active(lam, fn)

    stored = lam.get_function_configuration(FunctionName=fn).get("LoggingConfig") or {}
    assert stored.get("LogGroup") == custom_group, (
        f"LoggingConfig.LogGroup did not round-trip: expected {custom_group!r}, got "
        f"{stored.get('LogGroup')!r} (full LoggingConfig {stored!r})"
    )

    # ---- leg 1: the custom group receives the invocation; the default group is not even created --
    marker_custom = ctx.unique_name("marker-custom-")
    t0_ms = int(time.time() * 1000) - 5_000
    request_id = _invoke(lam, fn, marker_custom)

    record = _await_marker(logs, custom_group, marker_custom, t0_ms, timeout_s=90.0)
    assert record.get("requestId") == request_id, (
        f"the record delivered to {custom_group} must carry the invocation's request id "
        f"{request_id!r}, it carried {record.get('requestId')!r} (record {record!r})"
    )
    assert marker_custom in record["message"], (
        f"the record delivered to {custom_group} must carry the marker in its `message` field, got "
        f"{record!r}"
    )

    # Lambda must not have created the conventional group at all.
    assert not _log_group_exists(logs, default_group), (
        f"{fn} has LoggingConfig.LogGroup={custom_group!r}, yet {default_group} exists — the "
        f"override was stored but not honoured"
    )

    # ---- leg 2: point the config back at the default group; the NEXT invocation moves ----
    lam.update_function_configuration(
        FunctionName=fn, LoggingConfig={"LogFormat": "JSON", "LogGroup": default_group}
    )
    _wait_last_update_successful(lam, fn)
    ctx.on_cleanup(lambda: _delete_log_group_if_present(logs, default_group))

    marker_default = ctx.unique_name("marker-default-")
    t1_ms = int(time.time() * 1000) - 5_000
    request_id_2 = _invoke(lam, fn, marker_default)

    moved = _await_marker(logs, default_group, marker_default, t1_ms, timeout_s=90.0)
    assert moved.get("requestId") == request_id_2, (
        f"after pointing LoggingConfig.LogGroup at {default_group}, the record there must carry the "
        f"second invocation's request id {request_id_2!r}, it carried {moved.get('requestId')!r}"
    )

    # Only now — with arrival at the new destination proven on the same wiring — assert the old
    # destination received nothing for the second marker.
    stale = _find_marker(logs, custom_group, marker_default, t1_ms)
    assert stale == [], (
        f"{custom_group} is no longer the configured destination yet it received "
        f"{len(stale)} event(s) carrying {marker_default!r}: {stale[:2]}"
    )
    # ...and that the first marker is still only in the custom group, so nothing was duplicated.
    duplicated = _find_marker(logs, default_group, marker_custom, t0_ms)
    assert duplicated == [], (
        f"the first invocation's marker {marker_custom!r} was routed to {custom_group} but also "
        f"appears in {default_group}: {duplicated[:2]}"
    )


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _invoke(lam, fn: str, marker: str) -> str:
    resp = lam.invoke(
        FunctionName=fn,
        InvocationType="RequestResponse",
        Payload=json.dumps({"marker": marker}).encode(),
    )
    body = resp["Payload"].read().decode()
    assert "FunctionError" not in resp, (
        f"{fn} raised instead of logging {marker!r}: {resp.get('FunctionError')} {body[:300]}"
    )
    assert json.loads(body) == {"marker": marker}, (
        f"{fn} returned {body[:300]!r}, expected the marker echoed back"
    )
    request_id = resp["ResponseMetadata"]["RequestId"]
    assert request_id, f"Invoke response carried no RequestId: {resp['ResponseMetadata']!r}"
    return request_id


def _log_group_exists(logs, name: str) -> bool:
    found = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
    return any(g["logGroupName"] == name for g in found)


def _delete_log_group_if_present(logs, name: str) -> None:
    """Teardown for a group Lambda may or may not have created. Scoped to this check's own group."""
    if _log_group_exists(logs, name):
        logs.delete_log_group(logGroupName=name)


def _find_marker(logs, group: str, marker: str, since_ms: int) -> list[dict]:
    """Every event in `group` since `since_ms` containing `marker`. Empty list if the group is
    absent — used ONLY on the assert-not side, where an absent group is the correct answer."""
    if not _log_group_exists(logs, group):
        return []
    events: list[dict] = []
    token = None
    while True:
        kwargs = {
            "logGroupName": group,
            "startTime": since_ms,
            "filterPattern": f'"{marker}"',
            "limit": 100,
        }
        if token:
            kwargs["nextToken"] = token
        page = logs.filter_log_events(**kwargs)
        events.extend(page.get("events", []))
        token = page.get("nextToken")
        if not token:
            return events


def _await_marker(logs, group: str, marker: str, since_ms: int, *, timeout_s: float) -> dict:
    """Bounded retry until the marker's JSON record is filterable in `group`; raises on timeout."""
    def _probe():
        for event in _find_marker(logs, group, marker, since_ms):
            raw = event.get("message", "")
            try:
                parsed = json.loads(raw)
            except ValueError:
                raise AssertionError(
                    f"the function's LogFormat is JSON, but {group} holds an unstructured line "
                    f"carrying {marker!r}: {raw[:300]!r}"
                ) from None
            if marker in str(parsed.get("message", "")):
                return parsed
        return None

    return _poll_until(
        _probe,
        lambda found: found is not None,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"a JSON record carrying {marker!r} arriving in {group}",
    )


def _create_execution_role(ctx, iam) -> str:
    """Create this check's own execution role.

    AWSLambdaBasicExecutionRole grants logs:CreateLogStream/PutLogEvents on any group in the
    account, which is what lets the function write to a non-/aws/lambda group."""
    role_name = ctx.unique_name("sim2real-behav-logroute-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs):
    """CreateFunction, retrying only the documented role-propagation refusal; raises on deadline."""
    name = kwargs["FunctionName"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidParameterValueException", "ResourceConflictException"):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateFunction({name}) never succeeded within 90s; last error {last}")


def _wait_active(lam, name: str, timeout_s: float = 120.0) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed":
            raise AssertionError(
                f"{name} entered State=Failed: {cfg.get('StateReasonCode')} {cfg.get('StateReason')}"
            )
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"{name} reaching State=Active",
    )


def _wait_last_update_successful(lam, name: str, timeout_s: float = 120.0) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{name} update failed: {cfg.get('LastUpdateStatusReasonCode')} "
                f"{cfg.get('LastUpdateStatusReason')}"
            )
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("LastUpdateStatus") == "Successful" and cfg.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"{name} reaching LastUpdateStatus=Successful",
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry with a deadline. RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
