"""fault-error-throttle-flags-and-root-causes-derived-from-segment-document."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags

CHECK = "fault-error-throttle-flags-and-root-causes-derived-from-segment-document"
GROUP = 'trace-data-plane'
SERVICES = ['xray']

#: Root-cause derivation runs behind trace indexing, so it is polled rather than read once. The
#: _TIMEOUT_S suffix declares it as the check's poll deadline; it stays well under the run's
#: ceiling so an unmet condition fails as an assertion about content, not as a timeout.
_SUMMARY_TIMEOUT_S = 420


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def new_trace_id(epoch_seconds: float | None = None) -> str:
    """Generate a syntactically valid X-Ray trace ID: 1-<8 hex>-<24 hex>."""
    ts = int(epoch_seconds if epoch_seconds is not None else time.time())
    return f"1-{ts:08x}-{_hex(24)}"


def new_segment_id() -> str:
    """Generate a syntactically valid X-Ray segment ID: 16 hex chars."""
    return _hex(16)


def _poll_until(probe, predicate, timeout_s=180, interval_s=5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _utc(ts: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)


def _summaries(xr, start_ts, max_pages=25):
    """All TraceSummaries in [start_ts, now], following NextToken with a bounded page count."""
    out = []
    token = None
    for _ in range(max_pages):
        kw = {"StartTime": _utc(start_ts), "EndTime": _utc(time.time() + 60)}
        if token:
            kw["NextToken"] = token
        page = xr.get_trace_summaries(**kw)
        out.extend(page.get("TraceSummaries", []))
        token = page.get("NextToken")
        if not token:
            break
    return out


def _exception_names(root_causes):
    """Every Exceptions[].Name reachable through RootCause.Services[].EntityPath[]."""
    names = set()
    for rc in root_causes or []:
        for svc in rc.get("Services") or []:
            for entity in svc.get("EntityPath") or []:
                for exc in entity.get("Exceptions") or []:
                    if exc.get("Name"):
                        names.add(exc["Name"])
    return names


@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """GetTraceSummaries derives HasFault, HasError and HasThrottle independently (throttle plus
    error summarises as throttle only) and a FaultRootCause naming the submitted exception, with
    no root cause where no cause block was sent."""
    xr = ctx.client("xray")
    now = time.time()
    window_start = now - 300
    marker_type = f"Sim2RealBehav{_hex(6)}Error"

    fault_id = new_trace_id(now)
    error_id = new_trace_id(now)
    throttle_id = new_trace_id(now)
    throttle_only_id = new_trace_id(now)
    seg_name = "sim2real-behav-xray-flags-" + _hex(6)

    docs = [
        json.dumps({
            "id": new_segment_id(), "name": seg_name + "-fault", "trace_id": fault_id,
            "start_time": now - 1.0, "end_time": now, "fault": True,
            "http": {"request": {"method": "GET", "url": "https://example.invalid/boom"},
                     "response": {"status": 500}},
            "cause": {"working_directory": "/sim2real",
                      "exceptions": [{"id": new_segment_id(), "type": marker_type,
                                      "message": "probe fault"}]},
        }),
        json.dumps({
            "id": new_segment_id(), "name": seg_name + "-error", "trace_id": error_id,
            "start_time": now - 1.0, "end_time": now, "error": True,
            "http": {"request": {"method": "GET", "url": "https://example.invalid/bad"},
                     "response": {"status": 400}},
        }),
        json.dumps({
            "id": new_segment_id(), "name": seg_name + "-throttle", "trace_id": throttle_id,
            "start_time": now - 1.0, "end_time": now, "throttle": True, "error": True,
            "http": {"request": {"method": "GET", "url": "https://example.invalid/slowdown"},
                     "response": {"status": 429}},
        }),
        json.dumps({
            "id": new_segment_id(), "name": seg_name + "-throttle-only",
            "trace_id": throttle_only_id,
            "start_time": now - 1.0, "end_time": now, "throttle": True,
            "http": {"request": {"method": "GET", "url": "https://example.invalid/slowdown2"},
                     "response": {"status": 429}},
        }),
    ]
    put = xr.put_trace_segments(TraceSegmentDocuments=docs)
    assert put.get("UnprocessedTraceSegments", []) == [], (
        f"segments carrying fault/error/throttle and a cause block must all be accepted, "
        f"got {put!r}"
    )

    wanted = {fault_id, error_id, throttle_id, throttle_only_id}
    indexed = _poll_until(
        lambda: {s["Id"]: s for s in _summaries(xr, window_start)},
        lambda by_id: wanted <= set(by_id) and bool(by_id[fault_id].get("FaultRootCauses")),
        timeout_s=_SUMMARY_TIMEOUT_S,
        interval_s=5,
        description=(
            "all four flagged traces indexed in GetTraceSummaries and a FaultRootCause derived "
            "for the segment carrying a cause block"
        ),
    )
    faulty = indexed[fault_id]
    errored = indexed[error_id]
    throttled = indexed[throttle_id]
    throttle_only = indexed[throttle_only_id]

    # --- the three flags are independent -----------------------------------------------
    assert (faulty.get("HasFault"), faulty.get("HasError"), faulty.get("HasThrottle")) \
        == (True, False, False), (
        f"a segment flagged fault must summarise as HasFault and neither of the other two; an "
        f"emulator that collapses the three into one scores here, got {faulty!r}"
    )
    assert (errored.get("HasError"), errored.get("HasFault"), errored.get("HasThrottle")) \
        == (True, False, False), (
        f"a segment flagged error must summarise as HasError only -- not as a fault, got "
        f"{errored!r}"
    )
    assert throttle_only.get("HasThrottle") is True, (
        f"a segment flagged throttle must summarise as HasThrottle, got {throttle_only!r}"
    )
    assert throttle_only.get("HasFault") is not True, (
        f"a throttle is a 4xx condition and must not raise HasFault, got {throttle_only!r}"
    )

    # The one that separates a real derivation from a field copy: the client sent BOTH
    # throttle and error, and X-Ray reports only the throttle.
    assert (throttled.get("HasThrottle"), throttled.get("HasError"),
            throttled.get("HasFault")) == (True, False, False), (
        f"a segment submitting throttle=true AND error=true must summarise as HasThrottle with "
        f"HasError FALSE -- X-Ray reclassifies a throttle out of the error class rather than "
        f"unioning the two submitted members, got {throttled!r}"
    )

    # --- the fault root cause is derived from the cause block -------------------------
    root_causes = faulty.get("FaultRootCauses")
    assert root_causes, (
        f"a fault segment carrying a cause block must produce a FaultRootCause; root-cause "
        f"derivation appears in 0 of the 59 shipped xray checks, so an emulator that returns an "
        f"empty list here is currently unmeasurable, got {faulty!r}"
    )
    assert _exception_names(root_causes) == {marker_type}, (
        f"the FaultRootCause must name the exception type submitted in the cause block, got "
        f"{sorted(_exception_names(root_causes))!r} (expected {marker_type!r})"
    )
    rc = root_causes[0]
    assert rc.get("ClientImpacting") is True, (
        f"a fault on the root segment reaches the client, so the root cause must be marked "
        f"ClientImpacting, got {rc!r}"
    )
    rc_services = rc.get("Services") or []
    assert [s.get("Name") for s in rc_services] == [seg_name + "-fault"], (
        f"the root cause must be attributed to the submitted service, got {rc_services!r}"
    )
    entity_path = rc_services[0].get("EntityPath") or []
    assert [e.get("Name") for e in entity_path] == [seg_name + "-fault"], (
        f"a segment-level cause makes the segment itself the whole entity path, got "
        f"{entity_path!r}"
    )
    assert entity_path[0].get("Remote") is False, (
        f"the faulting entity is the segment the client submitted, not a remote one, got "
        f"{entity_path[0]!r}"
    )
    assert rc_services[0].get("Inferred") is False, (
        f"the faulting service was submitted, not inferred from a remote subsegment, got "
        f"{rc_services[0]!r}"
    )

    # --- absent where nothing was submitted to derive from ---------------------------
    assert errored.get("ErrorRootCauses") == [], (
        f"an error-flagged trace with no cause block must not manufacture a root cause, got "
        f"{errored.get('ErrorRootCauses')!r}"
    )
    assert errored.get("FaultRootCauses") == [], (
        f"an error-flagged trace must produce no FAULT root cause at all, got "
        f"{errored.get('FaultRootCauses')!r}"
    )
    assert throttled.get("FaultRootCauses") == [], (
        f"a throttled trace with no cause block must produce no fault root cause, got "
        f"{throttled.get('FaultRootCauses')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
