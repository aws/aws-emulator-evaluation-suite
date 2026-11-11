"""deep-cwlogs-semantics-filter-log-events-stream-names-with-prefix-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cwlogs-semantics-filter-log-events-stream-names-with-prefix-rejected"
GROUP = "retrieval"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterLogEvents refuses ``logStreamNames`` together with ``logStreamNamePrefix``
    (InvalidParameterException, exact message), though each alone returns the stored events;
    the data is unchanged afterwards. The model does not mark the pair mutually exclusive."""
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-scopeconf-")
    logs.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    base = int(time.time() * 1000) - 60_000
    for stream, offset in (("svc-a", 0), ("svc-b", 1)):
        logs.create_log_stream(logGroupName=group, logStreamName=stream)
        logs.put_log_events(logGroupName=group, logStreamName=stream,
                            logEvents=[{"timestamp": base + offset * 1000, "message": stream}])
    window = dict(startTime=base - 60_000, endTime=base + 60_000)

    by_names = _poll_until(
        lambda: _messages(logs, group, window, logStreamNames=["svc-a"]),
        lambda m: len(m) >= 1, timeout_s=90.0,
        description="logStreamNames=['svc-a'] to return its event",
    )
    assert by_names == ["svc-a"], f"logStreamNames=['svc-a'] returned {by_names!r}"
    by_prefix = _poll_until(
        lambda: _messages(logs, group, window, logStreamNamePrefix="svc-"),
        lambda m: len(m) >= 2, timeout_s=90.0,
        description="logStreamNamePrefix='svc-' to return both events",
    )
    assert by_prefix == ["svc-a", "svc-b"], f"logStreamNamePrefix='svc-' returned {by_prefix!r}"

    code, message = _error(lambda: logs.filter_log_events(
        logGroupName=group, logStreamNames=["svc-a"], logStreamNamePrefix="svc-", **window))
    assert code == "InvalidParameterException", (
        "FilterLogEvents with BOTH logStreamNames and logStreamNamePrefix must be refused with "
        f"InvalidParameterException, got {code!r}"
    )
    assert message == (
        "Cannot call FilterLogEvents with both logStreamNames and logStreamNamePrefix"
    ), (
        f"unexpected FilterLogEvents refusal message for names plus prefix: {message!r}"
    )

    after = _messages(logs, group, window, logStreamNamePrefix="svc-")
    assert after == ["svc-a", "svc-b"], (
        f"after the refused query the stored events must be unchanged; prefix read returned {after!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The AWS error (code, message). An unexpected SUCCESS raises rather than returning a
    falsy value."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last: {last!r}")


def _messages(logs, group, window, **scope):
    out, token = [], None
    for _ in range(200):
        kwargs = dict(logGroupName=group, **window, **scope)
        if token:
            kwargs["nextToken"] = token
        resp = logs.filter_log_events(**kwargs)
        out.extend(e["message"] for e in resp.get("events", []))
        token = resp.get("nextToken")
        if not token:
            return out
    raise AssertionError("FilterLogEvents pagination did not terminate within 200 pages")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
