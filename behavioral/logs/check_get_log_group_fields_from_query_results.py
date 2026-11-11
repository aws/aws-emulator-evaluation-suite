"""get-log-group-fields-from-query-results."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-log-group-fields-from-query-results"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetLogGroupFields discovers field names/percentages from sampled JSON log events."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lgf-")
    stream_name = "stream-1"
    logs.create_log_group(
        logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"}
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    # 4 JSON events: "requestId" only present on 3/4 -> distinct percent from "service"/"level" (4/4).
    payloads = [
        {"level": "INFO", "service": "orders", "requestId": "r-1"},
        {"level": "ERROR", "service": "orders", "requestId": "r-2"},
        {"level": "INFO", "service": "orders"},
        {"level": "INFO", "service": "orders", "requestId": "r-4"},
    ]
    events = [
        {"timestamp": now_ms + i * 1000, "message": json.dumps(p)}
        for i, p in enumerate(payloads)
    ]
    logs.put_log_events(logGroupName=group_name, logStreamName=stream_name, logEvents=events)
    center_time_s = (now_ms // 1000) + 2

    fields = _poll_until(
        lambda: logs.get_log_group_fields(logGroupName=group_name, time=center_time_s).get(
            "logGroupFields", []
        ),
        lambda f: len(f) > 0,
        timeout_s=90.0,
        interval_s=5.0,
    )
    if not fields:
        raise AssertionError("GetLogGroupFields never reported any discovered fields")

    by_name = {f["name"]: f["percent"] for f in fields}
    for expected in ("@timestamp", "@message", "level", "service", "requestId"):
        assert expected in by_name, f"expected field {expected!r} in {sorted(by_name)}"

    # requestId is present on 3/4 events; service/level are present on 4/4 -> strictly lower percent.
    assert by_name["requestId"] < by_name["service"], (
        f"requestId percent {by_name['requestId']} should be less than service percent "
        f"{by_name['service']} (present in fewer events)"
    )
    assert by_name["service"] == by_name["level"] == 100, (
        f"expected service and level percent == 100 (present in every event), got "
        f"service={by_name['service']} level={by_name['level']}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
