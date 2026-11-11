"""put-to-deleted-log-group-rejected-and-recreated-group-does-not-resurrect-events."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-to-deleted-log-group-rejected-and-recreated-group-does-not-resurrect-events"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']

_EVENT_COUNT = 3
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0


def _now_ms() -> int:
    return int(time.time() * 1000)


def _refusal(exc, *, status=400):
    """(code, message) of a ClientError, after grading its HTTP status class."""
    err = exc.response.get('Error', {})
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert isinstance(got_status, int) and got_status // 100 == status // 100, (
        f"expected HTTP {status // 100}xx with {err.get('Code')}, got {got_status!r}"
    )
    return err.get('Code'), err.get('Message')


def _refused(fn, *, status=400):
    """(code, message) of the ClientError fn() raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        return _refusal(exc, status=status)
    raise AssertionError(f'expected a refusal, but the call succeeded: {result!r}')


def _poll_until(probe, predicate, *, timeout_s=POLL_BUDGET_S, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Get/PutLogEvents on a deleted log group fail with ResourceNotFoundException, and a group
    re-created under the same name is empty: event storage is tied to the group, not its name.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html
    """
    svc = ctx.client("logs")

    name = ctx.unique_name("sim2real-behav-lg-reuse-")
    stream = ctx.unique_name("sim2real-behav-stream-")

    svc.create_log_group(logGroupName=name)

    def _delete_group(_n=name):
        """Delete whichever incarnation holds the name; tolerate it being already gone."""
        try:
            svc.delete_log_group(logGroupName=_n)
        except svc.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_delete_group)
    svc.create_log_stream(logGroupName=name, logStreamName=stream)

    written = [f"sim2real-preexisting-event-{i}" for i in range(_EVENT_COUNT)]
    base = _now_ms() - _EVENT_COUNT * 100
    resp = svc.put_log_events(
        logGroupName=name,
        logStreamName=stream,
        logEvents=[
            {"timestamp": base + i * 100, "message": msg} for i, msg in enumerate(written)
        ],
    )
    assert "rejectedLogEventsInfo" not in resp, (
        f"the fixture batch was partially rejected, so the resurrection leg below would be "
        f"asserted against an empty original group anyway: {resp!r}"
    )

    def _read(group):
        events: list[dict] = []
        token = None
        while True:
            kwargs = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
            if token is not None:
                kwargs["nextToken"] = token
            page = svc.get_log_events(**kwargs)
            events.extend(page.get("events", []))
            new_token = page.get("nextForwardToken")
            if new_token == token or not page.get("events"):
                break
            token = new_token
        return [e["message"] for e in events]

    # Positive control, established FIRST: the events really were readable.
    control_messages = _poll_until(
        lambda: _read(name),
        lambda msgs: msgs == written,
        interval_s=3.0,
        description=f"all {_EVENT_COUNT} events are readable from the original group",
    )
    assert control_messages == written, (
        "positive control: the events must have been readable before the delete, otherwise the "
        f"recreated group being empty proves nothing; got {control_messages!r} for {written!r}"
    )

    svc.delete_log_group(logGroupName=name)

    def _resolves():
        paginator = svc.get_paginator("describe_log_groups")
        for page in paginator.paginate(logGroupNamePrefix=name):
            for grp in page.get("logGroups", []):
                if grp["logGroupName"] == name:
                    return True
        return False

    _poll_until(
        _resolves,
        lambda present: present is False,
        interval_s=2.0,
        description="DescribeLogGroups stops resolving the deleted group name",
    )

    gone = ("ResourceNotFoundException", "The specified log group does not exist.")
    got = _refused(
        lambda: svc.get_log_events(logGroupName=name, logStreamName=stream, startFromHead=True),
    )
    assert got == gone, f"GetLogEvents on the deleted group: expected {gone}, got {got!r}"
    got = _refused(
        lambda: svc.put_log_events(
            logGroupName=name,
            logStreamName=stream,
            logEvents=[{"timestamp": _now_ms(), "message": "sim2real-write-after-delete"}],
        ),
    )
    assert got == gone, f"PutLogEvents to the deleted group: expected {gone}, got {got!r}"

    # Re-creating a just-deleted name can be refused for a short window, so retry bounded.
    deadline = time.monotonic() + POLL_BUDGET_S
    last_exc: Exception | None = None
    created = False
    while time.monotonic() < deadline:
        try:
            svc.create_log_group(logGroupName=name)
            created = True
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(3.0)
    assert created, (
        f"the log group name {name!r} could not be re-created after its deletion, so the "
        f"name-reuse property could not be exercised: {last_exc!r}"
    )
    svc.create_log_stream(logGroupName=name, logStreamName=stream)

    recreated = _poll_until(
        lambda: svc.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name),
        lambda pages: any(
            grp["logGroupName"] == name
            for page in pages
            for grp in page.get("logGroups", [])
        ),
        interval_s=2.0,
        description="DescribeLogGroups resolves the re-created group under the reused name",
    )
    resolved = [
        grp
        for page in svc.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name)
        for grp in page.get("logGroups", [])
        if grp["logGroupName"] == name
    ]
    assert len(resolved) == 1 and resolved[0]["logGroupName"] == name, (
        f"the re-created group did not resolve uniquely under the reused name: {resolved!r} "
        f"(pagination object was {recreated!r})"
    )

    # Held across a settle window: the new group must never serve the old events, even transiently.
    for _ in range(5):
        recreated_events = _read(name)
        assert recreated_events == [], (
            "effect not absent: a log group re-created under the same name served the DELETED "
            f"group's events: {recreated_events!r} (the deleted group held {written!r})"
        )
        time.sleep(2.0)

    svc.delete_log_group(logGroupName=name)
    _poll_until(
        _resolves,
        lambda present: present is False,
        interval_s=2.0,
        description="DescribeLogGroups stops resolving the deleted re-created group",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
