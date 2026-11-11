"""e2e-trace-lifecycle-group-filter-consequence."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "e2e-trace-lifecycle-group-filter-consequence"
GROUP = "e2e"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateGroup's FilterExpression, applied to GetTraceSummaries, surfaces only the
    PutTraceSegments data that matches it; after DeleteGroup, GetGroup no longer resolves it."""
    xray = ctx.client("xray")
    marker = ctx.unique_name("s2rlc").replace("-", "")
    group_name = ctx.unique_name("sim2real-lifecycle-")[:32]
    filter_expr = f'annotation.marker = "{marker}"'

    xray.create_group(
        GroupName=group_name,
        FilterExpression=filter_expr,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_group_if_present(xray, group_name))

    group = xray.get_group(GroupName=group_name)["Group"]
    assert group["FilterExpression"] == filter_expr, (
        f"GetGroup must echo the FilterExpression CreateGroup set; "
        f"expected {filter_expr!r}, got {group['FilterExpression']!r}"
    )

    now = time.time()
    match_id = _trace_id()
    miss_id = _trace_id()
    docs = [
        _segment_doc(match_id, "svc-match", now, {"marker": marker}),
        _segment_doc(miss_id, "svc-miss", now, {"marker": marker + "no"}),
    ]
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=docs)
    unprocessed = put_resp.get("UnprocessedTraceSegments", [])
    assert unprocessed == [], f"expected both segments accepted, got unprocessed={unprocessed!r}"

    def _unfiltered():
        return {
            s["Id"]
            for s in xray.get_trace_summaries(StartTime=now - 300, EndTime=now + 300)[
                "TraceSummaries"
            ]
        }

    # Both traces must be provably indexed BEFORE the filter is trusted to exclude one --
    # otherwise "excluded by the filter" cannot be told apart from "not yet ingested".
    both_indexed = _poll_until(
        _unfiltered, lambda ids: {match_id, miss_id} <= ids, timeout_s=180, interval_s=5
    )
    assert {match_id, miss_id} <= both_indexed, (
        f"both traces must be indexed in the unfiltered window before filtering is meaningful; "
        f"got {sorted(both_indexed)!r}"
    )

    filtered = {
        s["Id"]
        for s in xray.get_trace_summaries(
            StartTime=now - 300, EndTime=now + 300, FilterExpression=filter_expr
        )["TraceSummaries"]
    }
    assert match_id in filtered, (
        f"filter {filter_expr!r} must include the matching trace {match_id}; got {sorted(filtered)!r}"
    )
    assert miss_id not in filtered, (
        f"filter {filter_expr!r} must EXCLUDE the non-matching trace {miss_id} "
        f"(it is indexed -- it appeared in the unfiltered window); got {sorted(filtered)!r}"
    )

    xray.delete_group(GroupName=group_name)

    code, message = _error(lambda: xray.get_group(GroupName=group_name))
    assert code == "InvalidRequestException", (
        f"expected GetGroup to fail with InvalidRequestException after DeleteGroup, got {code!r}"
    )
    assert message == "Group not found", f"unexpected message: {message!r}"


# ===== helpers =====

def _trace_id() -> str:
    return f"1-{int(time.time()):08x}-{uuid.uuid4().hex[:24]}"


def _segment_doc(trace_id: str, name: str, start_time: float, annotations: dict) -> str:
    return json.dumps(
        {
            "trace_id": trace_id,
            "id": uuid.uuid4().hex[:16],
            "name": name,
            "start_time": start_time,
            "end_time": start_time + 0.25,
            "annotations": annotations,
        }
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _delete_group_if_present(xray, group_name: str) -> None:
    """Teardown: the check deletes the group itself, so "Group not found" is clean; any other
    refusal is a failure."""
    from botocore.exceptions import ClientError

    try:
        xray.delete_group(GroupName=group_name)
    except ClientError as e:
        err = e.response.get("Error", {})
        if (err.get("Code"), err.get("Message")) != ("InvalidRequestException", "Group not found"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
