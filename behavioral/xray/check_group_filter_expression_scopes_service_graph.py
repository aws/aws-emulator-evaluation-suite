"""group-filter-expression-scopes-service-graph."""
from __future__ import annotations

import datetime
import json
import random
import time

from behavioral_harness import tags

CHECK = "group-filter-expression-scopes-service-graph"
GROUP = 'groups'
SERVICES = ['xray']

#: Group scoping applies at ingestion, and when a new group is picked up is not observable, so the
#: check re-submits fresh traces each round and polls the derived graph within this bound.
_GROUP_GRAPH_TIMEOUT_S = 840

#: Budget for the unfiltered graph, read last so both filtered reads are compared against a
#: populated aggregate.
_GRAPH_TIMEOUT_S = 600


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def new_trace_id(epoch_seconds: float | None = None) -> str:
    """Generate a syntactically valid X-Ray trace ID: 1-<8 hex>-<24 hex>."""
    ts = int(epoch_seconds if epoch_seconds is not None else time.time())
    return f"1-{ts:08x}-{_hex(24)}"


def new_segment_id() -> str:
    """Generate a syntactically valid X-Ray segment ID: 16 hex chars."""
    return _hex(16)


def _poll_until(probe, predicate, timeout_s=180, interval_s=10, description="condition"):
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


def _graph_names(xr, start_ts, end_ts, group_name=None, max_pages=30):
    """Every node Name in the graph for the window, optionally scoped to a group.

    Paginated: the unscoped graph is account-wide, so page one is not the whole answer.
    """
    names = set()
    token = None
    for _ in range(max_pages):
        kw = {"StartTime": _utc(start_ts), "EndTime": _utc(end_ts)}
        if group_name:
            kw["GroupName"] = group_name
        if token:
            kw["NextToken"] = token
        page = xr.get_service_graph(**kw)
        names.update(s["Name"] for s in page.get("Services", []) if s.get("Name"))
        token = page.get("NextToken")
        if not token:
            break
    return names


def _group_names(xr, max_pages=25):
    """Every GroupName in the account, following NextToken."""
    names = set()
    token = None
    for _ in range(max_pages):
        page = xr.get_groups(**({"NextToken": token} if token else {}))
        names.update(g["GroupName"] for g in page.get("Groups", []) if g.get("GroupName"))
        token = page.get("NextToken")
        if not token:
            break
    return names


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """GetServiceGraph through a group returns only the service whose annotation matches its
    FilterExpression; the complementary group returns the other, and the unscoped graph holds both.

    Reference: https://docs.aws.amazon.com/xray/latest/devguide/xray-console-groups.html
    """
    # Groups are created before traces are sent: a group created after its traces stays empty.
    xr = ctx.client("xray")
    marker_a = _hex(10)
    marker_b = _hex(10)
    name_a = "sim2real-behav-xray-grp-a-" + _hex(6)
    name_b = "sim2real-behav-xray-grp-b-" + _hex(6)
    group_a = ctx.unique_name("sim2real-bh-xga-")
    group_b = ctx.unique_name("sim2real-bh-xgb-")
    expr_a = f'annotation.probe_tag = "{marker_a}"'
    expr_b = f'annotation.probe_tag = "{marker_b}"'

    created_a = xr.create_group(GroupName=group_a, FilterExpression=expr_a)
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=group_a))
    created_b = xr.create_group(GroupName=group_b, FilterExpression=expr_b)
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=group_b))
    assert created_a["Group"]["FilterExpression"] == expr_a, (
        f"the group did not store the expression it is about to be queried through: {created_a!r}"
    )
    assert created_b["Group"]["FilterExpression"] == expr_b, created_b

    existing = _poll_until(
        lambda: _group_names(xr),
        lambda names: {group_a, group_b} <= names,
        timeout_s=120,
        interval_s=5,
        description="both probe groups listed by GetGroups",
    )
    assert {group_a, group_b} <= existing, existing

    window_start = time.time()
    filtered_a = filtered_b = set()
    rounds = 0
    deadline = time.monotonic() + _GROUP_GRAPH_TIMEOUT_S
    while time.monotonic() < deadline:
        rounds += 1
        now = time.time()
        docs = []
        for svc_name, marker in ((name_a, marker_a), (name_b, marker_b)):
            docs.append(json.dumps({
                "id": new_segment_id(), "name": svc_name, "trace_id": new_trace_id(now),
                "start_time": now - 1.5, "end_time": now,
                "annotations": {"probe_tag": marker},
                "http": {"request": {"method": "GET",
                                     "url": f"https://example.invalid/{svc_name}"},
                         "response": {"status": 200}},
            }))
        put = xr.put_trace_segments(TraceSegmentDocuments=docs)
        assert put.get("UnprocessedTraceSegments", []) == [], (
            f"both annotated segments must be accepted, or nothing below is about group scoping: "
            f"{put!r}"
        )
        inner = time.monotonic() + 180
        while time.monotonic() < inner and time.monotonic() < deadline:
            time.sleep(2)
            end = time.time() + 300
            filtered_a = _graph_names(xr, window_start - 300, end, group_name=group_a)
            filtered_b = _graph_names(xr, window_start - 300, end, group_name=group_b)
            if name_a in filtered_a and name_b in filtered_b:
                break
        if name_a in filtered_a and name_b in filtered_b:
            break
    assert name_a in filtered_a and name_b in filtered_b, (
        f"neither group's graph became populated within {_GROUP_GRAPH_TIMEOUT_S}s over {rounds} "
        f"submission rounds; group A saw {sorted(filtered_a)!r} and group B saw "
        f"{sorted(filtered_b)!r}"
    )

    unfiltered = _poll_until(
        lambda: _graph_names(xr, window_start - 300, time.time() + 300),
        lambda names: {name_a, name_b} <= names,
        timeout_s=_GRAPH_TIMEOUT_S,
        interval_s=15,
        description="both services present in the UNSCOPED graph over the same window",
    )
    assert {name_a, name_b} <= unfiltered, (
        f"both services must be visible without a group filter, or the exclusions below prove "
        f"nothing: missing {sorted({name_a, name_b} - unfiltered)!r}"
    )

    assert filtered_a == {name_a}, (
        f"the graph read through group A must hold exactly the service whose annotation matches "
        f"A's FilterExpression {expr_a!r} -- an implementation that stores the expression and "
        f"ignores it on read returns the whole account graph here, and one that returns nothing "
        f"fails the membership above: got {sorted(filtered_a)!r}"
    )
    assert filtered_b == {name_b}, (
        f"group B must select exactly the complementary service, so neither result is an artefact "
        f"of one group being broken: got {sorted(filtered_b)!r}"
    )
    assert filtered_a < unfiltered and filtered_b < unfiltered, (
        f"a group scopes the graph by NARROWING it: each filtered result must be a strict subset "
        f"of the unscoped one, got A={sorted(filtered_a)!r} B={sorted(filtered_b)!r} against "
        f"{len(unfiltered)} unscoped names"
    )

    stored_a = xr.get_group(GroupName=group_a)
    assert stored_a["Group"]["FilterExpression"] == expr_a, (
        f"the group must still hold the expression that produced the scoping above: {stored_a!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
