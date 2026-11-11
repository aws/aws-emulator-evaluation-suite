"""put-rum-events-payload-timestamp-preserved."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "put-rum-events-payload-timestamp-preserved"
GROUP = "representation"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A sub-second-precision event timestamp submitted via PutRumEvents is not truncated
    to whole-second granularity when later surfaced via GetAppMonitorData, which reports it
    in epoch milliseconds as the event's event_timestamp."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-")
    created = rum.create_app_monitor(
        Name=name,
        DomainList=["example.com"],
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-rum"},
    )
    monitor_id = created["Id"]
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))

    event_id = str(uuid.uuid4())
    batch_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    # RUM's backend derives a UserId from the caller's identity when UserDetails.userId
    # is absent; when called with an IAM/STS principal (rather than an unauthenticated
    # Cognito identity) that derived value can exceed the ^[ -\x7f]{1,36}$ pattern.
    # Supplying an explicit, compliant userId avoids that server-side derivation.
    user_id = str(uuid.uuid4())
    # deliberately non-zero microseconds so a truncation to whole seconds is detectable
    sent_ts = datetime.now(timezone.utc).replace(microsecond=123456)
    sent_epoch = sent_ts.timestamp()

    rum.put_rum_events(
        Id=monitor_id,
        BatchId=batch_id,
        AppMonitorDetails={"id": monitor_id, "name": name, "version": "1.0.0"},
        UserDetails={"sessionId": session_id, "userId": user_id},
        RumEvents=[
            {
                "id": event_id,
                "timestamp": sent_ts,
                "type": "com.amazon.rum.session_start_event",
                "metadata": json.dumps({"version": "1.0.0", "domain": "example.com"}),
                "details": json.dumps({"version": "1.0.0"}),
            }
        ],
    )

    # RUM documents no ingestion latency; an event carrying the schema's metadata surfaces
    # within about a minute, so 220 s (bounded by the check's own budget) leaves several times that.
    budget = 220.0 if ctx.time_left() is None else min(220.0, max(ctx.time_left() - 30.0, 0.0))
    found_ts = _poll_for_event_timestamp(ctx, name, event_id, timeout_s=budget, interval_s=10.0)
    if found_ts is None:
        raise AssertionError(
            f"RUM event {event_id} never surfaced via GetAppMonitorData within {budget:.0f}s"
        )

    diff = abs(found_ts - sent_epoch)
    assert diff < 0.01, (
        f"event timestamp was not preserved at sub-second precision: sent {sent_epoch!r}, "
        f"retrieved {found_ts!r} (diff {diff}s)"
    )


def _poll_for_event_timestamp(
    ctx, app_monitor_name: str, event_id: str, *, timeout_s: float, interval_s: float
) -> float | None:
    """Epoch seconds of the event's ``event_timestamp`` (epoch milliseconds in each
    GetAppMonitorData event) once the event with ``event_id`` is readable, else None."""
    rum = ctx.client("rum")
    # GetAppMonitorData's TimeRange.After/Before are epoch *milliseconds* (a plain epoch-second
    # value is interpreted as ~1970-01-20, tripping "Time Range After must be greater than
    # 30 Days Ago").
    now_ms = int(time.time() * 1000)
    deadline = time.monotonic() + timeout_s
    while True:
        token = None
        while True:
            kwargs = {
                "Name": app_monitor_name,
                "TimeRange": {"After": now_ms - 3_600_000, "Before": int(time.time() * 1000) + 60_000},
                "MaxResults": 100,
            }
            if token:
                kwargs["NextToken"] = token
            resp = rum.get_app_monitor_data(**kwargs)
            for raw in resp.get("Events", []):
                event = json.loads(raw)
                if event.get("event_id") == event_id:
                    return event["event_timestamp"] / 1000.0
            token = resp.get("NextToken")
            if not token:
                break
        if time.monotonic() + interval_s > deadline:
            return None
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
