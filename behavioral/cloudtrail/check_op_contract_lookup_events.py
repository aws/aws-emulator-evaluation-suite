"""op-contract-lookup-events."""
from __future__ import annotations

import datetime as dt
import json
import time

from behavioral_harness import tags

CHECK = "op-contract-lookup-events"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """LookupEvents surfaces a just-made management API call; StartTime after EndTime is rejected."""
    ct = ctx.client("cloudtrail")
    sts = ctx.client("sts")

    trigger_time = dt.datetime.now(dt.timezone.utc)
    sts.get_caller_identity()

    def _probe():
        return ct.lookup_events(
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "GetCallerIdentity"}],
            StartTime=trigger_time - dt.timedelta(minutes=1),
        ).get("Events", [])


    events = _poll_until_nonempty(_probe, timeout_s=150.0, interval_s=10.0)
    if events is None:
        raise AssertionError("GetCallerIdentity event did not land in CloudTrail Event history in time")

    match = events[0]
    assert match["EventName"] == "GetCallerIdentity", (
        f"expected the matched envelope's EventName to be GetCallerIdentity, got "
        f"{match.get('EventName')!r}"
    )
    assert match["EventSource"] == "sts.amazonaws.com", (
        f"expected EventSource sts.amazonaws.com, got {match.get('EventSource')!r}"
    )
    assert match["EventTime"] >= trigger_time - dt.timedelta(minutes=1), (
        f"expected EventTime {match['EventTime']!r} to be at or after "
        f"{(trigger_time - dt.timedelta(minutes=1)).isoformat()!r}"
    )
    raw = json.loads(match["CloudTrailEvent"])
    assert raw["eventName"] == "GetCallerIdentity", (
        f"expected the embedded CloudTrailEvent's eventName to be GetCallerIdentity, got "
        f"{raw.get('eventName')!r}"
    )
    assert raw["eventSource"] == "sts.amazonaws.com", (
        f"expected the embedded CloudTrailEvent's eventSource to be sts.amazonaws.com, got "
        f"{raw.get('eventSource')!r}"
    )

    # Error boundary: StartTime after EndTime is rejected.
    code, message = _error(
        lambda: ct.lookup_events(
            StartTime=trigger_time,
            EndTime=trigger_time - dt.timedelta(hours=1),
        )
    )
    assert code == "InvalidTimeRangeException", (
        f"expected LookupEvents with StartTime after EndTime to reject with "
        f"InvalidTimeRangeException, got {code!r}"
    )
    assert message == "The start time precedes the end time.", message


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until_nonempty(probe, timeout_s=150.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = probe()
        if result:
            return result
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
