"""server-side-put-trace-segments-async-service-graph-population."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "server-side-put-trace-segments-async-service-graph-population"
GROUP = "server-side"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutTraceSegments has no accompanying 'index this trace' or 'rebuild service graph' call --
    AWS's own backend must asynchronously process the submitted segment and populate
    GetServiceGraph with the new service node, with no explicit trigger from the caller."""
    xray = ctx.client("xray")
    service_name = ctx.unique_name("sim2real-behav-svcgraph-")
    trace_id, segment_doc, start_time, end_time = _build_root_segment(service_name)

    resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment_doc)])
    assert resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment for {trace_id} was rejected: {resp.get('UnprocessedTraceSegments')}"
    )

    timeout_s = 240
    interval_s = 2
    deadline = time.monotonic() + timeout_s
    found_names: set[str] = set()
    while time.monotonic() < deadline:
        graph = xray.get_service_graph(StartTime=start_time - 60, EndTime=end_time + 600)
        found_names = {svc.get("Name") for svc in graph.get("Services", [])}
        if service_name in found_names:
            return
        time.sleep(interval_s)

    raise AssertionError(
        f"service {service_name!r} submitted via PutTraceSegments never appeared in "
        f"GetServiceGraph within {timeout_s}s (saw services: {sorted(found_names)})"
    )


def _hex(n: int) -> str:
    return "".join(random.choices("0123456789abcdef", k=n))


def _build_root_segment(service_name: str):
    now = time.time()
    start_time = now - 5
    end_time = now
    trace_id = f"1-{format(int(now), 'x')}-{_hex(24)}"
    segment_id = _hex(16)
    doc = {
        "trace_id": trace_id,
        "id": segment_id,
        "name": service_name,
        "start_time": start_time,
        "end_time": end_time,
    }
    return trace_id, doc, start_time, end_time


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
