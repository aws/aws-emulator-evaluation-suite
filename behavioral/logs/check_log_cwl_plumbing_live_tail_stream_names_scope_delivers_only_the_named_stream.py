"""log-cwl-plumbing-live-tail-stream-names-scope-delivers-only-the-named-stream."""
from __future__ import annotations

import threading
import time

from behavioral_harness import tags

CHECK = "log-cwl-plumbing-live-tail-stream-names-scope-delivers-only-the-named-stream"
GROUP = "live-tail"
SERVICES = ["logs"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c6",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """StartLiveTail scoped to logStreamNames=[A] echoes the scope and pushes only lines written
    to A after it opened, with exact stream, group, message and timestamp; stream B never appears.
    """
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-cwlp-lt-lg-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream_a = ctx.unique_name("tail-a-")
    stream_b = ctx.unique_name("tail-b-")
    for s in (stream_a, stream_b):
        logs.create_log_stream(logGroupName=group, logStreamName=s)

    marker = ctx.unique_name("cwlp-lt-")
    pre = f"{marker} A pre-session"
    _put(logs, group, stream_a, [{"timestamp": _now_ms(), "message": pre}])
    written: dict[str, set[str]] = {stream_a: {pre}, stream_b: set()}
    _poll_until(
        lambda: _stored(logs, group),
        lambda got: pre in got,
        timeout_s=120.0,
        interval_s=3.0,
        description="the pre-session line is provably stored before the session opens",
    )

    group_arn = _group_arn(logs, group)
    session = _Tail(
        logs.start_live_tail(logGroupIdentifiers=[group_arn], logStreamNames=[stream_a])
    )
    try:
        start = session.wait_start(30.0)
        assert start["logGroupIdentifiers"] == [group_arn], (
            f"expected sessionStart to echo logGroupIdentifiers [{group_arn!r}], got "
            f"{start.get('logGroupIdentifiers')!r}"
        )
        assert start.get("logStreamNames") == [stream_a], (
            f"expected sessionStart to echo logStreamNames [{stream_a!r}], got "
            f"{start.get('logStreamNames')!r}"
        )
        assert start.get("sessionId") and start.get("requestId"), (
            f"expected sessionStart to carry a sessionId and requestId, got {start!r}"
        )

        # A session that reported sessionStart may not deliver yet, so each round writes a
        # fresh numbered pair to A and B until an A line arrives.
        sent_ts: dict[str, int] = {}
        deadline = time.monotonic() + 120.0
        attempt = 0
        while time.monotonic() < deadline and not session.messages() & written[stream_a] - {pre}:
            attempt += 1
            now = _now_ms()
            a_line, b_line = f"{marker} A post-{attempt}", f"{marker} B post-{attempt}"
            _put(logs, group, stream_a, [{"timestamp": now, "message": a_line}])
            _put(logs, group, stream_b, [{"timestamp": now, "message": b_line}])
            written[stream_a].add(a_line)
            written[stream_b].add(b_line)
            sent_ts[a_line] = sent_ts[b_line] = now
            time.sleep(4.0)
        # Barrier: one more A line after the first delivery, so B's latest line has had the
        # same time to arrive as an A line that demonstrably did.
        barrier = f"{marker} A barrier"
        now = _now_ms()
        _put(logs, group, stream_a, [{"timestamp": now, "message": barrier}])
        written[stream_a].add(barrier)
        sent_ts[barrier] = now
        _poll_until(
            session.messages,
            lambda got: barrier in got,
            timeout_s=60.0,
            interval_s=1.0,
            description="the barrier line written to the tailed stream is pushed",
        )
    finally:
        session.close()

    results = session.results()
    delivered = {r["message"] for r in results}
    ours = {r["message"] for r in results if marker in r["message"]}
    assert ours - {pre} and ours <= written[stream_a], (
        f"expected only post-session lines of {stream_a!r} delivered, got {sorted(ours)!r}"
    )
    assert not delivered & written[stream_b], (
        f"the session scoped to {stream_a!r} pushed lines from {stream_b!r}: "
        f"{sorted(delivered & written[stream_b])!r}"
    )
    assert pre not in delivered, f"the pre-session line {pre!r} was pushed: {sorted(delivered)!r}"

    for r in results:
        assert r["logStreamName"] == stream_a, f"result names the wrong stream: {r!r}"
        assert r["logGroupIdentifier"] == f"{account}:{group}", (
            f"expected logGroupIdentifier {account}:{group!r}, got {r['logGroupIdentifier']!r}"
        )
        assert r["timestamp"] == sent_ts[r["message"]], (
            f"expected timestamp {sent_ts[r['message']]} for {r['message']!r}, "
            f"got {r['timestamp']!r}"
        )
        assert isinstance(r["ingestionTime"], int) and r["ingestionTime"] >= r["timestamp"], (
            f"expected an integer ingestionTime not before timestamp, got {r!r}"
        )
    for meta in session.metadata():
        assert meta.get("sampled") is False, f"expected an unsampled session, got {meta!r}"

    every = written[stream_a] | written[stream_b]
    _poll_until(
        lambda: _stored(logs, group),
        lambda got: every <= got,
        timeout_s=120.0,
        interval_s=3.0,
        description="every line, delivered or not, is still stored in the group",
    )


def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; raise on the deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _put(logs, group: str, stream: str, events: list[dict]) -> None:
    resp = logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)
    assert not resp.get("rejectedLogEventsInfo"), (
        f"expected every event accepted, got {resp.get('rejectedLogEventsInfo')!r}"
    )


def _stored(logs, group: str) -> set[str]:
    out: set[str] = set()
    kwargs = {"logGroupName": group}
    while True:
        page = logs.filter_log_events(**kwargs)
        out |= {e["message"] for e in page.get("events", [])}
        if not page.get("nextToken"):
            return out
        kwargs["nextToken"] = page["nextToken"]


def _group_arn(logs, group: str) -> str:
    """DescribeLogGroups returns the ARN with a trailing ':*'; StartLiveTail rejects it."""
    arns = [
        g["arn"]
        for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=group)
        for g in page.get("logGroups", [])
        if g["logGroupName"] == group
    ]
    assert len(arns) == 1, f"expected one log group named {group!r}, got {arns!r}"
    return arns[0][: -len(":*")] if arns[0].endswith(":*") else arns[0]


class _Tail:
    """Consume a StartLiveTail response stream on a daemon thread."""

    def __init__(self, resp) -> None:
        self._stream = resp["responseStream"]
        self._start: dict | None = None
        self._started = threading.Event()
        self._results: list[dict] = []
        self._meta: list[dict] = []
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._consume, daemon=True)
        self._thread.start()

    def _consume(self) -> None:
        try:
            for event in self._stream:
                if "sessionStart" in event:
                    self._start = event["sessionStart"]
                    self._started.set()
                elif "sessionUpdate" in event:
                    upd = event["sessionUpdate"]
                    with self._lock:
                        self._results.extend(upd.get("sessionResults", []))
                        if upd.get("sessionResults"):
                            self._meta.append(upd.get("sessionMetadata", {}))
        except Exception:  # noqa: BLE001 - a closed session just ends the consumer
            return

    def wait_start(self, timeout_s: float) -> dict:
        assert self._started.wait(timeout=timeout_s), (
            f"StartLiveTail never delivered sessionStart within {timeout_s}s"
        )
        return dict(self._start or {})

    def results(self) -> list[dict]:
        with self._lock:
            return list(self._results)

    def metadata(self) -> list[dict]:
        with self._lock:
            return list(self._meta)

    def messages(self) -> set[str]:
        return {r.get("message", "") for r in self.results()}

    def close(self) -> None:
        try:
            self._stream.close()
        except Exception:  # noqa: BLE001 - the session may already have ended
            pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
