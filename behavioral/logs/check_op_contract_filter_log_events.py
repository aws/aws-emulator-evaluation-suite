"""op-contract-filter-log-events."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-filter-log-events"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterLogEvents returns the events written with PutLogEvents and an empty searchedLogStreams list,
    and a missing log group gets ResourceNotFoundException and its exact message.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    stream_name = ctx.unique_name("sim2real-behav-ls-")

    logs.create_log_group(logGroupName=group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    messages = [f"sim2real-behav-event-{i}" for i in range(3)]
    logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[{"timestamp": now_ms + i, "message": m} for i, m in enumerate(messages)],
    )

    def _probe():
        # Scope the search to the specific stream we just wrote to. FilterLogEvents without
        # logStreamNames must first enumerate all streams in the log group, and that stream
        # listing is itself eventually consistent for a just-created stream -- so an
        # unscoped, whole-log-group search can miss freshly ingested events for far longer
        # than the per-check timeout allows, even though the events (and the stream) already
        # exist and are immediately visible once the stream is named explicitly.
        #
        # filterPattern tokenization on real AWS splits on '-' (hyphen) as a word boundary,
        # so an unquoted term containing hyphens (e.g. "sim2real-behav-event") never matches
        # any single token and the search silently returns zero events forever, regardless of
        # how long the poll runs. Quoting the term makes CloudWatch Logs match it as a literal
        # substring instead of tokenizing it.
        resp = logs.filter_log_events(
            logGroupName=group_name,
            logStreamNames=[stream_name],
            filterPattern='"sim2real-behav-event"',
        )
        return resp

    # FilterLogEvents indexing lag for freshly-ingested events on real AWS can exceed a
    # minute even when the events are already visible via GetLogEvents -- a 60s bound was
    # too tight and caused the poll to give up before the index caught up. Widen the
    # timeout (and space out the interval) rather than weakening what is polled for.
    resp = _poll_until(_probe, lambda r: len(r.get("events", [])) >= 3, timeout_s=180, interval_s=5.0)
    assert resp is not None, "filter_log_events never returned the ingested events"
    found_messages = {e["message"] for e in resp["events"]}
    assert set(messages) <= found_messages, f"missing messages: {set(messages) - found_messages}"
    # searchedLogStreams is a deprecated response field: CloudWatch Logs does not report which
    # log streams a FilterLogEvents call covered, so the field is always an empty list, even
    # though the events of the scoped stream are returned (asserted above).
    searched = resp.get("searchedLogStreams", [])
    assert searched == [], f"searchedLogStreams is documented-deprecated and always empty on real AWS, got {searched!r}"

    # error boundary: log group does not exist
    code, message = _error(
        lambda: logs.filter_log_events(
            logGroupName=ctx.unique_name("sim2real-behav-missing-lg-")
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "The specified log group does not exist.", (
        f"unexpected FilterLogEvents message for a missing log group: {message!r}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result if result is not None and predicate(result) else None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
