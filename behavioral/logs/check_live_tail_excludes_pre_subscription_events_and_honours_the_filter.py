"""live-tail-excludes-pre-subscription-events-and-honours-the-filter."""
from __future__ import annotations

import threading
import time

from behavioral_harness import tags

CHECK = "live-tail-excludes-pre-subscription-events-and-honours-the-filter"
GROUP = 'live-tail'
SERVICES = ['logs']

_PRE_PREFIX = "sim2real-pre-session"
_POST_PREFIX = "sim2real-post-session"
_NOISE_PREFIX = "sim2real-post-session-noise"


# ===== helpers =====
def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A live-tail session delivers ONLY events ingested after it opened (a stored event that matches
    the filter is still never delivered) and honours the filter for new events, while every excluded
    event remains retrievable from the store, so the exclusions are about delivery, not ingestion.
    """
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-behav-lg-livetail-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: logs.delete_log_group(logGroupName=_n))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    marker = ctx.unique_name("SIM2REALLIVETAIL")
    pre_message = f"{_PRE_PREFIX} {marker} line"
    written: list[str] = [pre_message]

    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": _now_ms(), "message": pre_message}],
    )

    def _stored():
        messages: list[str] = []
        token = None
        while True:
            kwargs = {"logGroupName": group}
            if token is not None:
                kwargs["nextToken"] = token
            page = logs.filter_log_events(**kwargs)
            messages.extend(e["message"] for e in page.get("events", []))
            token = page.get("nextToken")
            if not token:
                break
        return messages

    # "Before the session" is established as a fact, not assumed from statement order.
    _poll_until(
        _stored,
        lambda msgs: pre_message in msgs,
        timeout_s=120,
        interval_s=3.0,
        description="the pre-session event is provably stored before the session is opened",
    )

    # DescribeLogGroups returns the ARN with a trailing ":*" wildcard, and StartLiveTail
    # rejects an identifier carrying it.
    arns = [
        grp["arn"]
        for page in logs.get_paginator("describe_log_groups").paginate(
            logGroupNamePrefix=group
        )
        for grp in page.get("logGroups", [])
        if grp["logGroupName"] == group
    ]
    assert len(arns) == 1, f"expected exactly one log group named {group!r}, got ARNs {arns!r}"
    group_arn = arns[0][: -len(":*")] if arns[0].endswith(":*") else arns[0]

    response_stream = logs.start_live_tail(
        logGroupIdentifiers=[group_arn], logEventFilterPattern=f'"{marker}"'
    )["responseStream"]

    delivered: list[str] = []
    session_started = threading.Event()
    stop = threading.Event()

    def _consume() -> None:
        try:
            for event in response_stream:
                if stop.is_set():
                    return
                if "sessionStart" in event:
                    session_started.set()
                elif "sessionUpdate" in event:
                    for result in event["sessionUpdate"].get("sessionResults", []):
                        delivered.append(result.get("message", ""))
        except Exception:  # noqa: BLE001 - a closed session just ends the consumer
            return

    consumer = threading.Thread(target=_consume, daemon=True)
    consumer.start()
    try:
        assert session_started.wait(timeout=30), (
            "StartLiveTail never delivered a sessionStart event within 30s, so there is no session "
            "whose delivery could be judged"
        )

        deadline = time.monotonic() + 90
        attempt = 0
        matched: list[str] = []
        while not matched and time.monotonic() < deadline:
            attempt += 1
            post_message = f"{_POST_PREFIX} {marker} line attempt {attempt}"
            noise_message = f"{_NOISE_PREFIX} line attempt {attempt}"
            now = _now_ms()
            logs.put_log_events(
                logGroupName=group,
                logStreamName=stream,
                logEvents=[
                    {"timestamp": now, "message": noise_message},
                    {"timestamp": now + 1, "message": post_message},
                ],
            )
            written.extend([noise_message, post_message])
            wait_until = time.monotonic() + 6
            while not matched and time.monotonic() < wait_until:
                matched = [
                    m for m in delivered if m.startswith(f"{_POST_PREFIX} ") and marker in m
                ]
                time.sleep(0.5)
        stop.set()
    finally:
        # A leaked generator holds the session open and would consume the suite budget.
        try:
            response_stream.close()
        except Exception:  # noqa: BLE001 - the session may already have ended
            pass

    snapshot = list(delivered)

    # --- 1. A new, matching event IS delivered.
    assert matched, (
        f"the live-tail session did not deliver any event written after it opened, across "
        f"{attempt!r} attempts; the session delivered {snapshot!r}"
    )

    # --- 2. The defining property: an event that was ALREADY STORED and that MATCHES the
    # filter is never delivered.
    assert pre_message not in snapshot, (
        "the live-tail session delivered an event ingested BEFORE it opened, which is the one "
        f"thing live tail must not do: {snapshot!r} (the pre-session event was {pre_message!r} "
        "and it deliberately matches the session's filter pattern, so time is the only reason it "
        "must be absent)"
    )

    # --- 3. The filter pattern is honoured for new events too.
    noise_delivered = [m for m in snapshot if m.startswith(_NOISE_PREFIX)]
    assert noise_delivered == [], (
        "the session ignored its logEventFilterPattern and delivered non-matching events written "
        f"after it opened: {noise_delivered!r}"
    )

    # --- 4. Both exclusions were about DELIVERY: every event is still in the store.
    stored = _poll_until(
        _stored,
        lambda msgs: set(msgs) == set(written),
        timeout_s=120,
        interval_s=3.0,
        description="every event written during the session is readable from the store",
    )
    assert set(stored) == set(written), (
        "effect present: every event must still be readable from the store regardless of what the "
        f"session delivered; got {sorted(stored)!r}, expected {sorted(set(written))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
