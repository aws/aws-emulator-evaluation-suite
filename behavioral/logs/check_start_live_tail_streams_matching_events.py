"""start-live-tail-streams-matching-events."""
from __future__ import annotations

import threading
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-live-tail-streams-matching-events"
GROUP = "server-side"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartLiveTail opens a managed server-side event stream that only emits events
    matching the requested log group/filter pattern in near-real time -- events that don't
    match the filter must never appear on the stream."""
    logs = ctx.client("logs")

    if not hasattr(logs, "start_live_tail"):
        raise AssertionError("unreachable: this boto3 version lacks StartLiveTail")

    group_name = ctx.unique_name("sim2real-livetail-")
    stream_name = "sim2real-livetail-stream"
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _delete_log_group(logs, group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    group_arn = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0]["arn"]
    # DescribeLogGroups returns ARNs with a trailing ":*" wildcard suffix, but StartLiveTail
    # rejects log group ARNs that include that suffix -- it must be stripped first.
    if group_arn.endswith(":*"):
        group_arn = group_arn[: -len(":*")]

    marker = ctx.unique_name("SIM2REALMARKER")
    resp = logs.start_live_tail(
        logGroupIdentifiers=[group_arn], logEventFilterPattern=f'"{marker}"'
    )
    stream = resp["responseStream"]
    ctx.on_cleanup(lambda: _close(stream))

    matched: list[str] = []
    unmatched: list[str] = []
    session_started = threading.Event()
    stop = threading.Event()

    def _consume() -> None:
        try:
            for event in stream:
                if stop.is_set():
                    return
                if "sessionStart" in event:
                    session_started.set()
                elif "sessionUpdate" in event:
                    for result in event["sessionUpdate"].get("sessionResults", []):
                        message = result.get("message", "")
                        if marker in message:
                            matched.append(message)
                        else:
                            unmatched.append(message)
        except Exception:  # noqa: BLE001 - session errors just end the consumer thread
            return

    consumer = threading.Thread(target=_consume, daemon=True)
    consumer.start()
    if not session_started.wait(timeout=15):
        stop.set()
        raise AssertionError("StartLiveTail never delivered a sessionStart event")

    # A single PutLogEvents right after sessionStart can race real AWS's Live Tail session
    # establishment -- the session may report "started" slightly before it's actually latched
    # onto new writes, so a one-shot put can be missed entirely (no matched AND no unmatched).
    # Re-send the same pair of events periodically until the matching one is observed (or the
    # overall deadline elapses) instead of relying on exactly one attempt.
    sent_matching: list[str] = []
    deadline = time.monotonic() + 60
    attempt = 0
    while not matched and time.monotonic() < deadline:
        attempt += 1
        now_ms = int(time.time() * 1000)
        matching_message = f"hello {marker} world (attempt {attempt})"
        sent_matching.append(matching_message)
        logs.put_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            logEvents=[
                {"timestamp": now_ms, "message": "unrelated-noise-line-should-not-match"},
                {"timestamp": now_ms + 1, "message": matching_message},
            ],
        )
        wait_until = time.monotonic() + 5
        while not matched and time.monotonic() < wait_until:
            time.sleep(0.5)

    # The noise half and the matching half of one PutLogEvents call can land in different
    # sessionUpdate frames, so absence is judged only once a later matching barrier event
    # has been delivered: any straggler from the earlier calls arrives before it.
    barrier = f"{marker} barrier"
    logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": barrier}],
    )
    left = ctx.time_left()
    barrier_deadline = time.monotonic() + (30.0 if left is None else max(1.0, min(30.0, left - 5.0)))
    while barrier not in matched and time.monotonic() < barrier_deadline:
        time.sleep(1)
    stop.set()
    _close(stream)
    consumer.join(timeout=5)

    assert matched, f"live tail never delivered the matching event within timeout; unmatched={unmatched}"
    assert barrier in matched, f"live tail never delivered the barrier event within 30 s; matched={matched!r}"
    assert any(m in sent_matching for m in matched), (
        f"live tail delivered a message that matched the filter substring but doesn't equal "
        f"anything this check sent -- content was altered in transit: delivered={matched!r}, "
        f"sent={sent_matching!r}"
    )
    assert not unmatched, f"live tail delivered non-matching event(s) despite the filter pattern: {unmatched}"


# ===== helpers =====
def _delete_log_group(logs_client: Any, group_name: str) -> None:
    try:
        logs_client.delete_log_group(logGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _close(stream: Any) -> None:
    stream.close()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
