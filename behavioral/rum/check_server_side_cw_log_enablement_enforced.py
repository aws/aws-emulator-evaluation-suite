"""server-side-cw-log-enablement-enforced."""
from __future__ import annotations

import json

import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-cw-log-enablement-enforced"
GROUP = "server-side"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateAppMonitor(CwLogEnabled=True) makes RUM itself create the CwLogGroup it reports, which
    DescribeLogGroups lists; GetAppMonitorData still answers with an Events list, and
    CwLogEnabled=False turns the setting back off."""
    rum = ctx.client("rum")
    logs = ctx.client("logs")

    name = ctx.unique_name("sim2real-rum-cwlog-")
    created = rum.create_app_monitor(Name=name, Domain="example.com", Tags={"sim2real:managed": "true"})
    monitor_id = created["Id"]
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))

    before = rum.get_app_monitor(Name=name)["AppMonitor"].get("DataStorage", {}).get("CwLog", {})
    assert not before.get("CwLogEnabled"), f"CwLog should start disabled, got {before!r}"

    rum.update_app_monitor(Name=name, CwLogEnabled=True)

    # the managed service -- not this client -- provisions the log group
    log_group = _wait_for_cw_log_group(rum, name, timeout_s=60.0)
    assert log_group, "CwLogGroup was enabled but no log group name was returned"

    # that log group must be a REAL CloudWatch Logs resource, not just a config
    # string RUM invented -- this check never calls logs:CreateLogGroup itself
    described = logs.describe_log_groups(logGroupNamePrefix=log_group)
    matching = [g for g in described.get("logGroups", []) if g["logGroupName"] == log_group]
    assert matching, f"RUM advertised CwLogGroup {log_group!r} but it does not exist in CloudWatch Logs"

    # the app monitor keeps accepting data-plane traffic once CW log delivery
    # is enabled -- exercises PutRumEvents and the GetAppMonitorData read path
    marker = uuid.uuid4().hex
    _send_marked_rum_event(rum, monitor_id, marker)
    now_ms = int(time.time() * 1000)
    data_resp = rum.get_app_monitor_data(
        Name=name,
        TimeRange={"After": now_ms - 3_600_000, "Before": now_ms + 60_000},
        MaxResults=10,
    )
    assert isinstance(data_resp.get("Events"), list), f"unexpected GetAppMonitorData shape: {data_resp!r}"

    # disabling flips the managed config back off (round-trip of the same transition)
    rum.update_app_monitor(Name=name, CwLogEnabled=False)
    after = _wait_for_cw_log_disabled(rum, name, timeout_s=60.0)
    assert not after.get("CwLogEnabled"), f"CwLog should be disabled again, got {after!r}"


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as err:
        return err.response["Error"]["Code"]


def _wait_for_cw_log_group(rum, name: str, timeout_s: float = 60.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_seen: dict[str, Any] = {}
    while time.monotonic() < deadline:
        cw_log = rum.get_app_monitor(Name=name)["AppMonitor"].get("DataStorage", {}).get("CwLog", {})
        last_seen = cw_log
        if cw_log.get("CwLogEnabled") and cw_log.get("CwLogGroup"):
            return cw_log["CwLogGroup"]
        time.sleep(2.0)
    raise AssertionError(f"CwLogGroup was never populated after enabling CwLogEnabled: {last_seen!r}")


def _wait_for_cw_log_disabled(rum, name: str, timeout_s: float = 60.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_seen: dict[str, Any] = {}
    while time.monotonic() < deadline:
        cw_log = rum.get_app_monitor(Name=name)["AppMonitor"].get("DataStorage", {}).get("CwLog", {})
        last_seen = cw_log
        if not cw_log.get("CwLogEnabled"):
            return cw_log
        time.sleep(2.0)
    raise AssertionError(f"CwLog was never disabled after UpdateAppMonitor(CwLogEnabled=False): {last_seen!r}")


def _send_marked_rum_event(rum, app_monitor_id: str, marker: str) -> None:
    event_id = str(uuid.uuid4())
    rum.put_rum_events(
        Id=app_monitor_id,
        BatchId=str(uuid.uuid4()),
        AppMonitorDetails={"id": app_monitor_id, "version": "1.0"},
        UserDetails={"sessionId": str(uuid.uuid4()), "userId": str(uuid.uuid4())},
        RumEvents=[
            {
                "id": event_id,
                "timestamp": int(time.time()),
                "type": "com.amazon.rum.page_view_event",
                "details": f'{{"pageId": "/sim2real-{marker}"}}',
                "metadata": json.dumps({"version": "1.0.0", "domain": "example.com", "marker": marker}),
            }
        ],
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


