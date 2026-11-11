"""deleted-log-stream-refuses-events-and-recreated-stream-starts-empty-beside-its-sibling."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleted-log-stream-refuses-events-and-recreated-stream-starts-empty-beside-its-sibling"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']

#: A wait never exceeds 40 s; AWS answers well inside it.
POLL_BUDGET_S = 40.0

_STREAM_GONE = ("ResourceNotFoundException", "The specified log stream does not exist.")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=POLL_BUDGET_S, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) holds; raise on timeout (TimeoutError if the run budget ended it)."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended the wait. Last result: {last!r}")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _refused(fn, *, status=400):
    """(code, message) of the ClientError fn() raises, after grading its HTTP status; success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
        assert got_status == status, f"expected HTTP {status} with {err.get('Code')}, got {got_status!r}"
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected a refusal, but the call succeeded: {result!r}')


def _gone(fn):
    """True once fn() is refused with ResourceNotFoundException; any other error propagates."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
        return True
    return False


def _put(svc, group, stream, messages):
    base = _now_ms() - len(messages) * 10
    resp = svc.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=[{"timestamp": base + i * 10, "message": m} for i, m in enumerate(messages)],
    )
    assert "rejectedLogEventsInfo" not in resp, f"PutLogEvents rejected part of the batch: {resp!r}"


def _read(svc, group, stream):
    """Every message in one stream, oldest first, following nextForwardToken until it repeats."""
    out, token = [], None
    while True:
        kwargs = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
        if token is not None:
            kwargs["nextToken"] = token
        page = svc.get_log_events(**kwargs)
        out.extend(e["message"] for e in page.get("events", []))
        new_token = page.get("nextForwardToken")
        if new_token == token or not page.get("events"):
            return out
        token = new_token


def _stream_names(svc, group, prefix):
    return [
        s["logStreamName"]
        for page in svc.get_paginator("describe_log_streams").paginate(
            logGroupName=group, logStreamNamePrefix=prefix)
        for s in page.get("logStreams", [])
    ]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """A deleted log stream refuses Get/PutLogEvents with ResourceNotFoundException while its sibling
    in the same group keeps its events, and a stream re-created under the same name starts empty and
    serves only what is written to it afterwards."""
    rng = random.SystemRandom()
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-streams-")
    doomed = ctx.unique_name("sim2real-behav-doomed-")
    sibling = ctx.unique_name("sim2real-behav-sibling-")

    def _delete_group():
        try:
            svc.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(_delete_group)
    svc.create_log_stream(logGroupName=group, logStreamName=doomed)
    svc.create_log_stream(logGroupName=group, logStreamName=sibling)
    doomed_msgs = [f"doomed-{i}-{rng.randrange(10**9):09d}" for i in range(rng.randint(2, 5))]
    sibling_msgs = [f"sibling-{i}-{rng.randrange(10**9):09d}" for i in range(rng.randint(2, 5))]
    _put(svc, group, doomed, doomed_msgs)
    _put(svc, group, sibling, sibling_msgs)
    _poll_until(ctx, lambda: (_read(svc, group, doomed), _read(svc, group, sibling)),
                lambda got: got == (doomed_msgs, sibling_msgs), interval_s=3.0,
                description="both streams serve exactly the events written to them")

    svc.delete_log_stream(logGroupName=group, logStreamName=doomed)
    _poll_until(ctx, lambda: _stream_names(svc, group, doomed), lambda names: names == [],
                description="DescribeLogStreams stops listing the deleted stream")
    # GetLogEvents can keep serving a just-deleted stream for a while; poll it to its terminal refusal.
    _poll_until(ctx, lambda: _gone(lambda: svc.get_log_events(
        logGroupName=group, logStreamName=doomed, startFromHead=True)), bool,
        description="GetLogEvents refuses the deleted stream")
    got = _refused(lambda: svc.get_log_events(logGroupName=group, logStreamName=doomed, startFromHead=True))
    assert got == _STREAM_GONE, f"GetLogEvents on the deleted stream: expected {_STREAM_GONE}, got {got!r}"
    got = _refused(lambda: svc.put_log_events(
        logGroupName=group, logStreamName=doomed,
        logEvents=[{"timestamp": _now_ms(), "message": "write-after-delete"}]))
    assert got == _STREAM_GONE, f"PutLogEvents to the deleted stream: expected {_STREAM_GONE}, got {got!r}"
    got = _refused(lambda: svc.delete_log_stream(logGroupName=group, logStreamName=doomed))
    assert got == _STREAM_GONE, f"DeleteLogStream on the deleted stream: expected {_STREAM_GONE}, got {got!r}"

    # Twin control: the sibling in the same group is untouched.
    assert _read(svc, group, sibling) == sibling_msgs, "the sibling stream lost events when its neighbour was deleted"
    assert _stream_names(svc, group, sibling) == [sibling], "the sibling stream is no longer listed"

    svc.create_log_stream(logGroupName=group, logStreamName=doomed)
    assert _stream_names(svc, group, doomed) == [doomed], "the re-created stream is not listed"
    empty = _read(svc, group, doomed)
    assert empty == [], f"the re-created stream served the deleted stream's events: {empty!r}"
    fresh = [f"fresh-{i}-{rng.randrange(10**9):09d}" for i in range(rng.randint(1, 4))]
    _put(svc, group, doomed, fresh)
    got_fresh = _poll_until(ctx, lambda: _read(svc, group, doomed), lambda ms: len(ms) >= len(fresh),
                            interval_s=3.0, description="the re-created stream serves its new events")
    assert got_fresh == fresh, f"the re-created stream: expected only {fresh!r}, got {got_fresh!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
