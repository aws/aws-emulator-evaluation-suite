"""trace-graph-derives-per-trace-topology-and-rejects-unknown-trace-id."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trace-graph-derives-per-trace-topology-and-rejects-unknown-trace-id"
GROUP = 'trace-data-plane'
SERVICES = ['xray']

ERR_INVALID_REQUEST = "InvalidRequestException"

# Below the harness ceiling, so an unmet condition fails with the graph's content in the message.
_TRACE_GRAPH_TIMEOUT_S = 240


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def new_trace_id(epoch_seconds: float | None = None) -> str:
    """Generate a syntactically valid X-Ray trace ID: 1-<8 hex>-<24 hex>."""
    ts = int(epoch_seconds if epoch_seconds is not None else time.time())
    return f"1-{ts:08x}-{_hex(24)}"


def new_segment_id() -> str:
    """Generate a syntactically valid X-Ray segment ID: 16 hex chars."""
    return _hex(16)


def _poll_until(probe, predicate, timeout_s=90, interval_s=3, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error_code(fn):
    """The (code, message) of the AWS error raised by fn(); raises if fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to be refused but succeeded: {result!r}")


def _trace_graph(xr, trace_ids, max_pages=20):
    """Every Service in the trace graph, following NextToken with a bounded page count."""
    out, token = [], None
    for _ in range(max_pages):
        kw = {"TraceIds": list(trace_ids)}
        if token:
            kw["NextToken"] = token
        page = xr.get_trace_graph(**kw)
        out.extend(page.get("Services", []))
        token = page.get("NextToken")
        if not token:
            break
    return out


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """GetTraceGraph derives root, remote callee, edge and synthesised client nodes from one
    segment, and refuses an unknown trace id (alone or mixed with a known one) with
    InvalidRequestException, while BatchGetTraces silently omits the unknown id.
    """
    xr = ctx.client("xray")
    now = time.time()
    trace_id = new_trace_id(now)
    seg_id = new_segment_id()
    sub_id = new_segment_id()
    caller_name = "sim2real-behav-xray-tg-caller-" + _hex(6)
    callee_name = "sim2real-behav-xray-tg-callee-" + _hex(6)

    segment = {
        "id": seg_id, "name": caller_name, "trace_id": trace_id,
        "start_time": now - 1.5, "end_time": now,
        "http": {"request": {"method": "GET", "url": "https://example.invalid/tg"},
                 "response": {"status": 200}},
        "subsegments": [{"id": sub_id, "name": callee_name, "namespace": "remote",
                         "start_time": now - 1.3, "end_time": now - 0.2}],
    }
    put = xr.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert put.get("UnprocessedTraceSegments", []) == [], (
        f"the two-tier segment must be accepted, or nothing below is about the trace graph: "
        f"{put!r}"
    )

    # A trace id that was never submitted, minted from the SAME epoch as the real one so it falls
    # in the same index window. Generated up front so the refusal below cannot be blamed on a
    # difference in age.
    unknown_id = new_trace_id(now)
    assert unknown_id != trace_id, (
        f"the unknown probe id must differ from the submitted trace id, or the refusal below "
        f"proves nothing: {unknown_id!r} == {trace_id!r}"
    )

    # The positive path is the propagation barrier: until this succeeds, a "Trace id not found"
    # is indistinguishable from "not indexed yet" -- it is the same error code.
    services = _poll_until(
        lambda: _trace_graph_or_empty(xr, [trace_id]),
        lambda svcs: {s.get("Name") for s in svcs} >= {caller_name, callee_name},
        timeout_s=_TRACE_GRAPH_TIMEOUT_S,
        interval_s=3,
        description="the submitted service and its inferred remote callee present in the trace graph",
    )

    by_ref = {s["ReferenceId"]: s for s in services}
    assert len(by_ref) == len(services), (
        f"ReferenceId must be unique within one graph, or the edges below are ambiguous: "
        f"{[s.get('ReferenceId') for s in services]!r}"
    )

    roots = [s for s in services if s.get("Root") is True]
    assert len(roots) == 1, (
        f"a single-trace graph derived from one root segment must have exactly one Root node, got "
        f"{[(s.get('Name'), s.get('Root'), s.get('Type')) for s in services]!r}"
    )
    root = roots[0]
    assert root["Name"] == caller_name, (
        f"the Root node must be the service that submitted the segment, got {root!r}"
    )
    assert root["State"] == "active", (
        f"a service that produced a segment is active, got {root.get('State')!r}"
    )
    assert root.get("Names") == [caller_name], (
        f"Names must list the one name this node was seen under, got {root!r}"
    )

    callees = [s for s in services if s.get("Name") == callee_name]
    assert len(callees) == 1, (
        f"the one remote-namespace subsegment must produce exactly one callee node, got "
        f"{callees!r}"
    )
    callee = callees[0]
    assert callee["Type"] == "remote", (
        f"a node inferred from a namespace=remote subsegment is typed remote, got "
        f"{callee.get('Type')!r}"
    )
    assert callee["State"] == "passive", (
        f"the callee never submitted a segment of its own, so X-Ray knows it only passively, got "
        f"{callee.get('State')!r}"
    )
    assert callee.get("Root") is not True, (
        f"the inferred callee is not the root of the trace, got {callee!r}"
    )
    assert callee.get("Edges") == [], (
        f"nothing downstream of the callee was traced, so it must have no outbound edges, got "
        f"{callee.get('Edges')!r}"
    )

    root_edge_refs = {e["ReferenceId"] for e in root.get("Edges") or []}
    assert root_edge_refs == {callee["ReferenceId"]}, (
        f"the root must have exactly one outbound edge and it must point at the inferred callee "
        f"(ReferenceId {callee['ReferenceId']!r}); an emulator that returns the nodes without "
        f"deriving the topology fails here, got edges {root.get('Edges')!r}"
    )

    # X-Ray also synthesises a `client` node standing in for whoever called the traced service;
    # the root node itself carries no Type.
    clients = [s for s in services if s.get("Type") == "client"]
    assert len(clients) == 1, (
        f"X-Ray synthesises exactly one client node for a traced root service, got "
        f"{[(s.get('Name'), s.get('Type')) for s in services]!r}"
    )
    client = clients[0]
    assert client["Name"] == caller_name, (
        f"the synthesised client node is named after the service it calls, got {client!r}"
    )
    assert {e["ReferenceId"] for e in client.get("Edges") or []} == {root["ReferenceId"]}, (
        f"the client node's only edge must point at the root service, got {client!r}"
    )
    assert client.get("State") == "unknown", (
        f"nothing is known about the synthesised client, got {client.get('State')!r}"
    )

    stats = root["SummaryStatistics"]
    assert stats["TotalCount"] == 1, (
        f"exactly one request was submitted for this trace, got {stats!r}"
    )
    assert stats["OkCount"] == 1, (
        f"the segment carried no error/fault/throttle member, so it must count as OK: {stats!r}"
    )
    assert stats["ErrorStatistics"]["TotalCount"] == 0, (
        f"a clean segment must contribute no errors: {stats!r}"
    )
    assert stats["FaultStatistics"]["TotalCount"] == 0, (
        f"a clean segment must contribute no faults: {stats!r}"
    )

    code, message = _error_code(lambda: xr.get_trace_graph(TraceIds=[unknown_id]))
    assert code == ERR_INVALID_REQUEST, (
        f"a well-formed trace id that was never submitted must be refused with "
        f"{ERR_INVALID_REQUEST!r}; an emulator returning an empty Services list instead is "
        f"over-permissive, got {code!r}: {message!r}"
    )
    assert message == "Trace id not found", (
        f"the refusal must name the missing trace rather than the request shape, got {message!r}"
    )

    # GetTraceGraph has no partial-result path, while BatchGetTraces given the same list drops
    # the unknown id and returns the known trace.
    mixed_code, _ = _error_code(lambda: xr.get_trace_graph(TraceIds=[trace_id, unknown_id]))
    assert mixed_code == ERR_INVALID_REQUEST, (
        f"one unknown id must refuse the whole GetTraceGraph batch -- there is no partial-result "
        f"path here, got {mixed_code!r}"
    )
    batch = xr.batch_get_traces(TraceIds=[trace_id, unknown_id])
    assert [t["Id"] for t in batch.get("Traces", [])] == [trace_id], (
        f"BatchGetTraces given the very list GetTraceGraph just refused must return the known "
        f"trace, so the refusal above is GetTraceGraph's own policy and not a property of the "
        f"input: {batch!r}"
    )
    assert batch.get("UnprocessedTraceIds", []) == [], (
        f"BatchGetTraces silently omits an unknown id rather than reporting it, which is the "
        f"third distinct behaviour for the same id -- raise, omit, or echo -- and an emulator that "
        f"picks one policy for both operations fails one of these two assertions: {batch!r}"
    )

    again = _trace_graph(xr, [trace_id])
    assert {s.get("Name") for s in again} == {caller_name, callee_name}, (
        f"the known trace's graph must be unchanged by the refused calls, got "
        f"{sorted(s.get('Name') for s in again)!r}"
    )
    assert len([s for s in again if s.get("Root") is True]) == 1, again


def _trace_graph_or_empty(xr, trace_ids):
    """The trace graph, or [] while the trace is not yet indexed: X-Ray raises 'Trace id not
    found' both for a not-yet-indexed trace and for one that does not exist."""
    try:
        return _trace_graph(xr, trace_ids)
    except ClientError:
        return []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
