"""recreated-log-group-serves-only-its-own-new-events-across-streams."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recreated-log-group-serves-only-its-own-new-events-across-streams"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']

#: A wait never exceeds 40 s; AWS answers well inside it.
POLL_BUDGET_S = 40.0

_GROUP_GONE = ("ResourceNotFoundException", "The specified log group does not exist.")
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


def _messages(rng, label, count):
    """``count`` distinct messages mixing ASCII and multi-byte UTF-8 text."""
    return [f"{label}-é-ü-日本語-{i}-{rng.randrange(10**9):09d}" for i in range(count)]


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


def _filter(svc, group):
    """Every message FilterLogEvents returns for the whole group."""
    out, kwargs = [], {"logGroupName": group}
    while True:
        page = svc.filter_log_events(**kwargs)
        out.extend(e["message"] for e in page.get("events", []))
        token = page.get("nextToken")
        if not token:
            return out
        kwargs["nextToken"] = token


def _listed(svc, name):
    return any(
        g["logGroupName"] == name
        for page in svc.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name)
        for g in page.get("logGroups", [])
    )


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """After a log group with two streams of UTF-8 events is deleted, writes to either stream are
    refused; the group re-created under the same name holds no old stream, its re-created stream
    serves exactly the new events, and FilterLogEvents finds them."""
    rng = random.SystemRandom()
    svc = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-lg-recreate-")
    stream_a = ctx.unique_name("sim2real-behav-stream-a-")
    stream_b = ctx.unique_name("sim2real-behav-stream-b-")

    def _delete_group():
        """Delete whichever incarnation holds the name; tolerate it being already gone."""
        try:
            svc.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    svc.create_log_group(logGroupName=name)
    ctx.on_cleanup(_delete_group)
    svc.create_log_stream(logGroupName=name, logStreamName=stream_a)
    svc.create_log_stream(logGroupName=name, logStreamName=stream_b)
    old_a = _messages(rng, "old-a", rng.randint(2, 6))
    old_b = _messages(rng, "old-b", rng.randint(1, 4))
    _put(svc, name, stream_a, old_a)
    _put(svc, name, stream_b, old_b)

    # Positive control: both streams served their events before the delete.
    _poll_until(ctx, lambda: (_read(svc, name, stream_a), _read(svc, name, stream_b)),
                lambda got: got == (old_a, old_b), interval_s=3.0,
                description="both streams serve exactly the events written to them")

    svc.delete_log_group(logGroupName=name)
    _poll_until(ctx, lambda: _listed(svc, name), lambda present: present is False,
                description="DescribeLogGroups stops resolving the deleted group")
    for stream in (stream_a, stream_b):
        got = _refused(lambda s=stream: svc.put_log_events(
            logGroupName=name, logStreamName=s,
            logEvents=[{"timestamp": _now_ms(), "message": "write-after-delete"}]))
        assert got == _GROUP_GONE, f"PutLogEvents to {stream} of the deleted group: expected {_GROUP_GONE}, got {got!r}"
    got = _refused(lambda: svc.describe_log_streams(logGroupName=name))
    assert got == _GROUP_GONE, f"DescribeLogStreams on the deleted group: expected {_GROUP_GONE}, got {got!r}"

    # Re-creating a just-deleted name can be refused for a short window, so retry bounded.
    def _recreate():
        try:
            svc.create_log_group(logGroupName=name)
            return True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceAlreadyExistsException":  # an earlier attempt of this loop landed
                return True
            if code != "OperationAbortedException":
                raise
            return False

    _poll_until(ctx, _recreate, bool, interval_s=3.0, description=f"CreateLogGroup re-creates {name}")
    _poll_until(ctx, lambda: _listed(svc, name), bool,
                description="DescribeLogGroups resolves the re-created group")

    streams = [s["logStreamName"] for s in svc.describe_log_streams(logGroupName=name)["logStreams"]]
    assert streams == [], f"the re-created group must start with no streams, got {streams!r}"
    got = _refused(lambda: svc.get_log_events(logGroupName=name, logStreamName=stream_b, startFromHead=True))
    assert got == _STREAM_GONE, f"GetLogEvents on {stream_b} in the re-created group: expected {_STREAM_GONE}, got {got!r}"

    svc.create_log_stream(logGroupName=name, logStreamName=stream_a)
    new_a = _messages(rng, "new-a", rng.randint(1, 5))
    _put(svc, name, stream_a, new_a)
    got_a = _poll_until(ctx, lambda: _read(svc, name, stream_a), lambda ms: len(ms) >= len(new_a),
                        interval_s=3.0, description="the re-created stream serves its new events")
    assert got_a == new_a, f"GetLogEvents on the re-created stream: expected only {new_a!r}, got {got_a!r}"
    # FilterLogEvents searches the group by name and may still surface the deleted incarnation's
    # events for a while, so only the new events' presence, in order, is required of it.
    filtered = _poll_until(ctx, lambda: _filter(svc, name),
                           lambda ms: [m for m in ms if m in new_a] == new_a,
                           interval_s=3.0, description="FilterLogEvents returns every new event in order")
    assert [m for m in filtered if m.startswith("new-")] == new_a, (
        f"FilterLogEvents on the re-created group: expected the new events {new_a!r}, got {filtered!r}"
    )

    svc.delete_log_group(logGroupName=name)
    _poll_until(ctx, lambda: _listed(svc, name), lambda present: present is False,
                description="DescribeLogGroups stops resolving the re-created group after its delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
