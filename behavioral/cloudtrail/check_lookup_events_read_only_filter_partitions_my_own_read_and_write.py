"""lookup-events-read-only-filter-partitions-my-own-read-and-write."""

from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lookup-events-read-only-filter-partitions-my-own-read-and-write"
GROUP = 'data-plane'
SERVICES = ['cloudtrail']

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# LookupEvents indexes a new event in roughly 135 s; 255 s leaves headroom.
_INDEX_BUDGET_S = 255.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded)."""
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
    return out


def _error(fn):
    """Return the exact AWS (Error.Code, Error.Message), raising if the call unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("call unexpectedly SUCCEEDED where an error was required")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _find(events, token):
    for ev in events:
        if token in ev.get("CloudTrailEvent", ""):
            return ev
    return None


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """LookupEvents' ReadOnly filter puts this run's own read marker only on the true side and its
    rejected DeleteTrail only on the false side; the two sides are disjoint and cover the window.
    """
    ct = ctx.client("cloudtrail")

    read_token = ctx.unique_name("sim2realctread").lower()
    write_token = ctx.unique_name("sim2real-behav-ct-ghost-")
    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()
    ct.describe_trails(trailNameList=[read_token])
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    # A rejected DeleteTrail provisions nothing, yet is recorded readOnly=false because
    # classification follows the operation, not the outcome.
    write_code, write_message = _error(lambda: ct.delete_trail(Name=write_token))
    assert write_code == "TrailNotFoundException", (
        f"the write marker must be a rejected DeleteTrail so it provisions nothing, but the "
        f"rejection code was {write_code!r} rather than TrailNotFoundException; if the call "
        f"took a different path the marker's readOnly classification is not interpretable"
    )
    assert write_message == (
        f"Unknown trail: arn:aws:cloudtrail:{ctx.region}:{account_id}:trail/{write_token} "
        f"for the user: {account_id}"
    ), write_message

    window_start = emitted_at - datetime.timedelta(minutes=2)
    read_ev = write_ev = None
    polls = 0
    budget_s = _budget_s(ctx, _INDEX_BUDGET_S)
    while time.monotonic() - t0 < budget_s:
        polls += 1
        end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        if read_ev is None:
            read_ev = _find(_lookup_all(
                ct, StartTime=window_start, EndTime=end, MaxResults=50,
                LookupAttributes=[{"AttributeKey": "EventName",
                                   "AttributeValue": "DescribeTrails"}]), read_token)
        if write_ev is None:
            write_ev = _find(_lookup_all(
                ct, StartTime=window_start, EndTime=end, MaxResults=50,
                LookupAttributes=[{"AttributeKey": "EventName",
                                   "AttributeValue": "DeleteTrail"}]), write_token)
        if read_ev is not None and write_ev is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    if not (read_ev is not None and write_ev is not None) and _budget_spent(ctx):
        raise TimeoutError("CloudTrail to index this check's own markers: the run budget ended "
                           "first; not graded")
    assert read_ev is not None and write_ev is not None, (
        f"{DATAPLANE_MARKER}: CloudTrail did not index this check's own markers within "
        f"{waited:.0f}s over {polls} polls (real AWS: 135s). read marker {read_token!r} "
        f"found={read_ev is not None}, write marker {write_token!r} "
        f"found={write_ev is not None}. Without both anchors the ReadOnly partition cannot be "
        f"graded non-vacuously."
    )

    # One fixed closed window, reused verbatim for all three calls, ending in the PAST so no new
    # event can arrive between them and confound the union, yet never before either marker.
    last_marker = max(read_ev["EventTime"], write_ev["EventTime"])
    win = {
        "StartTime": window_start,
        "EndTime": max(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=30),
                       last_marker + datetime.timedelta(seconds=1)),
        "MaxResults": 50,
    }
    unfiltered = _lookup_all(ct, **dict(win))
    ro_events = _lookup_all(ct, **dict(
        win, LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "true"}]))
    rw_events = _lookup_all(ct, **dict(
        win, LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}]))
    all_ids = {e["EventId"] for e in unfiltered}
    ro_ids = {e["EventId"] for e in ro_events}
    rw_ids = {e["EventId"] for e in rw_events}

    # The two anchors this check caused itself land on exactly one side each.
    assert read_ev["EventId"] in ro_ids, (
        f"this check's own read-only marker (DescribeTrails {read_token!r}, EventId "
        f"{read_ev['EventId']!r}) is missing from the ReadOnly=true result, which returned "
        f"{len(ro_ids)} events over the same window that unfiltered returned {len(all_ids)}"
    )
    assert read_ev["EventId"] not in rw_ids, (
        f"this check's own READ marker {read_ev['EventId']!r} was returned under "
        f"ReadOnly=false; the filter is not applied, or DescribeTrails is misclassified"
    )
    assert write_ev["EventId"] in rw_ids, (
        f"this check's own write marker (DeleteTrail {write_token!r}, EventId "
        f"{write_ev['EventId']!r}) is missing from the ReadOnly=false result, which returned "
        f"{len(rw_ids)} events. A target that classifies readOnly by whether the call actually "
        f"changed anything puts this REJECTED DeleteTrail on the read-only side and fails here."
    )
    assert write_ev["EventId"] not in ro_ids, (
        f"this check's own WRITE marker {write_ev['EventId']!r} was returned under "
        f"ReadOnly=true"
    )

    # The set algebra over everything in the window, not just the anchors.
    assert ro_ids & rw_ids == set(), (
        f"ReadOnly=true and ReadOnly=false returned {len(ro_ids & rw_ids)} events in common "
        f"over one identical window: {sorted(ro_ids & rw_ids)[:5]!r}"
    )
    # CloudTrail's delivery time is not guaranteed, so an event indexed after the unfiltered call
    # may appear only in a partition; every unfiltered event must still land in one.
    assert ro_ids | rw_ids == all_ids or all_ids <= ro_ids | rw_ids, (
        f"the two ReadOnly partitions do not cover the unfiltered window: "
        f"only-in-unfiltered {sorted(all_ids - (ro_ids | rw_ids))[:5]!r}, only-in-partitions "
        f"{sorted((ro_ids | rw_ids) - all_ids)[:5]!r} "
        f"(unfiltered={len(all_ids)} readonly={len(ro_ids)} write={len(rw_ids)})"
    )

    # Each record agrees with the filter that selected it. `is not True` / `is not False` rather
    # than a truthiness test, because the payload member is a JSON boolean and a target emitting
    # the string "true" must fail.
    bad_ro = [e for e in ro_events
              if json.loads(e["CloudTrailEvent"]).get("readOnly") is not True]
    assert not bad_ro, (
        f"{len(bad_ro)} of {len(ro_events)} records returned under ReadOnly=true carry "
        f"readOnly != true in their own payload, e.g. "
        f"{[(e['EventName'], json.loads(e['CloudTrailEvent']).get('readOnly')) for e in bad_ro[:5]]!r}"
    )
    bad_rw = [e for e in rw_events
              if json.loads(e["CloudTrailEvent"]).get("readOnly") is not False]
    assert not bad_rw, (
        f"{len(bad_rw)} of {len(rw_events)} records returned under ReadOnly=false carry "
        f"readOnly != false in their own payload, e.g. "
        f"{[(e['EventName'], json.loads(e['CloudTrailEvent']).get('readOnly')) for e in bad_rw[:5]]!r}"
    )
    # The stringly-typed envelope twin agrees with the payload boolean, per side.
    assert all(e["ReadOnly"] == "true" for e in ro_events), (
        f"an envelope under ReadOnly=true carries a ReadOnly member other than the string "
        f"'true': {sorted({e['ReadOnly'] for e in ro_events})!r}"
    )
    assert all(e["ReadOnly"] == "false" for e in rw_events), (
        f"an envelope under ReadOnly=false carries a ReadOnly member other than the string "
        f"'false': {sorted({e['ReadOnly'] for e in rw_events})!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
