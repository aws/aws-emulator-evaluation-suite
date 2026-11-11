"""start-live-tail-streams-new-events."""
from __future__ import annotations

import queue
import threading
import time

from behavioral_harness import tags

CHECK = "start-live-tail-streams-new-events"
GROUP = "server-side"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartLiveTail opens a managed streaming session that emits newly
    PutLogEvents-ingested records without client polling."""
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-livetail-")
    logs.create_log_group(logGroupName=log_group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    raw_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    # DescribeLogGroups returns log group ARNs with a trailing ":*" suffix,
    # but StartLiveTail's logGroupIdentifiers validation rejects that suffix
    # ("1 validation error detected: Value ... failed to satisfy constraint").
    # Strip it before using the ARN as a live-tail identifier.
    log_group_arn = raw_arn[:-2] if raw_arn.endswith(":*") else raw_arn

    log_stream_name = ctx.unique_name("stream-")
    logs.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)

    resp = logs.start_live_tail(logGroupIdentifiers=[log_group_arn])
    stream = resp["responseStream"]
    events: "queue.Queue" = queue.Queue()
    stop = threading.Event()

    def _consume():
        try:
            for event in stream:
                events.put(event)
                if stop.is_set():
                    break
        except Exception:  # noqa: BLE001
            pass

    thread = threading.Thread(target=_consume, daemon=True)
    thread.start()

    def _close():
        stop.set()
        stream.close()
        thread.join(timeout=5)

    ctx.on_cleanup(_close)

    session_start = _drain_until(events, lambda e: "sessionStart" in e, timeout_s=30.0)
    assert session_start is not None, "StartLiveTail never sent a LiveTailSessionStart event"
    session_id = session_start["sessionStart"]["sessionId"]
    assert session_id, f"expected a non-empty sessionId on LiveTailSessionStart, got {session_id!r}"
    resolved = session_start["sessionStart"]["logGroupIdentifiers"]
    assert log_group_arn in resolved, (
        f"expected our log group ARN {log_group_arn!r} among resolved identifiers, got {resolved!r}"
    )

    # Receiving the LiveTailSessionStart event locally doesn't guarantee the
    # backend streaming pipeline is fully wired up to capture new events yet
    # -- on real AWS there can be a short additional warm-up window right
    # after session start during which an event ingested via PutLogEvents is
    # missed. Rather than sending a single probe event and waiting once
    # (which can race that warm-up window), repeatedly send a fresh marker
    # event and drain for it in a bounded loop until one is observed.
    deadline = time.monotonic() + 90.0
    found = None
    attempt = 0
    while found is None and time.monotonic() < deadline:
        attempt += 1
        marker = ctx.unique_name(f"live-tail-marker-{attempt}-")
        now_ms = int(time.time() * 1000)
        logs.put_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            logEvents=[{"timestamp": now_ms, "message": f"sim2real live tail probe {marker}"}],
        )

        def _has_marker(event, marker=marker):
            update = event.get("sessionUpdate")
            if not update:
                return False
            return any(marker in r.get("message", "") for r in update.get("sessionResults", []))

        found = _drain_until(events, _has_marker, timeout_s=10.0)

    assert found is not None, (
        "Live Tail session never streamed a newly ingested event across repeated "
        "retries of PutLogEvents"
    )


# ===== helpers =====
def _drain_until(events_queue, predicate, *, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        try:
            event = events_queue.get(timeout=max(0.1, remaining))
        except queue.Empty:
            continue
        if predicate(event):
            return event
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
