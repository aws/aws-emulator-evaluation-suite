"""start-live-tail-session-idle-stays-open."""
from __future__ import annotations

import queue
import threading
import time

from behavioral_harness import tags

CHECK = "start-live-tail-session-idle-stays-open"
GROUP = "visibility-timeout-ttl"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A StartLiveTail session on a log group receiving no matching events stays open
    and keeps emitting periodic sessionUpdate heartbeats instead of closing/timing out."""
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    group_arn = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]["arn"]
    # describe_log_groups returns the ARN with a trailing ":*" wildcard
    # suffix, which StartLiveTail's logGroupIdentifiers field rejects with
    # InvalidParameterException (the identifier pattern doesn't allow "*").
    # Strip it to get the plain group ARN the API actually accepts.
    if group_arn.endswith(":*"):
        group_arn = group_arn[: -len(":*")]

    # Filter pattern that will never match anything we send, so the session stays idle.
    resp = logs.start_live_tail(
        logGroupIdentifiers=[group_arn],
        logEventFilterPattern="sim2real-behav-pattern-that-never-matches-anything",
    )
    event_stream = resp["responseStream"]
    ctx.on_cleanup(lambda: _close(event_stream))

    saw_start = False
    saw_update = False
    saw_timeout_or_error = False
    collected = []
    max_events_to_inspect = 8
    timeout_s = 60.0

    for event in _bounded_events(event_stream, timeout_s=timeout_s):
        collected.append(list(event.keys()))
        if "sessionStart" in event:
            saw_start = True
        if "sessionUpdate" in event:
            saw_update = True
        if "SessionTimeoutException" in event or "SessionStreamingException" in event:
            saw_timeout_or_error = True
            break
        if saw_start and saw_update:
            break
        if len(collected) >= max_events_to_inspect:
            break

    assert saw_start, f"never received a sessionStart frame from an idle Live Tail session: {collected}"
    assert not saw_timeout_or_error, (
        f"idle Live Tail session raised a timeout/streaming exception almost immediately, "
        f"but real sessions only time out after a fixed 3h regardless of activity: {collected}"
    )
    assert saw_update, (
        f"never received a sessionUpdate heartbeat while idle within {max_events_to_inspect} "
        f"frames and {timeout_s:.0f}s; real AWS keeps an idle Live Tail session open and keeps "
        f"emitting periodic heartbeat updates rather than closing it: {collected}"
    )


# ===== helpers =====

def _close(stream) -> None:
    stream.close()


def _bounded_events(stream, *, timeout_s: float):
    """Yield frames off a StartLiveTail responseStream, bounded by a wall-clock deadline.

    The blocking iterator itself has no per-call timeout, so a session that stalls
    (no more frames ever) would otherwise hang the check indefinitely instead of
    failing with a clear message. Runs the read in a background thread and yields
    from the calling thread with a deadline.
    """
    q: "queue.Queue" = queue.Queue()

    def _reader():
        try:
            for event in stream:
                q.put(("event", event))
        except Exception as exc:  # noqa: BLE001
            q.put(("error", exc))
        finally:
            q.put(("done", None))

    thread = threading.Thread(target=_reader, daemon=True)
    thread.start()

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = max(0.1, deadline - time.monotonic())
        try:
            kind, payload = q.get(timeout=remaining)
        except queue.Empty:
            break
        if kind == "event":
            yield payload
        elif kind == "error":
            raise AssertionError(f"Live Tail stream raised while idle: {payload!r}")
        elif kind == "done":
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
