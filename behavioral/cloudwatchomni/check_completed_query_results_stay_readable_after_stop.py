"""completed-query-results-stay-readable-after-stop."""
from __future__ import annotations

import datetime
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "completed-query-results-stay-readable-after-stop"
GROUP = "telemetry-queries"
SERVICES = ["cloudwatchomni"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _window() -> str:
    """A WHERE predicate bounding `@timestamp` to the last hour, as the default dataset requires."""
    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = (now + datetime.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"`@timestamp` BETWEEN to_timestamp('{start}') AND to_timestamp('{end}')"


def _session(ctx, cwo) -> str:
    session_id = cwo.start_telemetry_query_session(
        sessionName=ctx.unique_name("sim2real-behav-cwo-sess-")
    )["sessionId"]
    ctx.on_cleanup(_teardown(lambda: cwo.stop_telemetry_query_session(sessionId=session_id),
                             "ResourceNotFoundException"))
    return session_id


def _results(ctx, cwo, query_id: str) -> dict:
    """GetTelemetryQueryResults once the query has left RUNNING."""
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        res = cwo.get_telemetry_query_results(queryId=query_id)
        if res["status"] != "RUNNING":
            return res
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"query {query_id} to finish: the run budget ended first; not graded")
            raise AssertionError(f"query {query_id} still RUNNING at its deadline")
        time.sleep(1.0)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A completed query's results read the same on every GetTelemetryQueryResults, StopTelemetryQuery
    on it succeeds and leaves them readable, and stopping an unknown query id is not found.
    """
    cwo = ctx.client("cloudwatchomni")
    session_id = _session(ctx, cwo)
    query_id = cwo.start_telemetry_query(
        sessionId=session_id, queryString=f"SELECT count(*) AS n FROM default WHERE {_window()}"
    )["queryId"]
    first = _results(ctx, cwo, query_id)
    assert first["status"] == "Complete", f"expected Complete, got {first['status']!r}"
    assert first["rows"] == [{"n": "0"}], f"expected one zero-count row, got {first['rows']!r}"

    again = cwo.get_telemetry_query_results(queryId=query_id)
    assert (again["status"], again["rows"]) == ("Complete", [{"n": "0"}]), (
        f"a second read changed the result: {again['status']!r} {again['rows']!r}"
    )
    cwo.stop_telemetry_query(queryId=query_id)
    after = cwo.get_telemetry_query_results(queryId=query_id)
    assert (after["status"], after["rows"]) == ("Complete", [{"n": "0"}]), (
        f"stopping a completed query changed its result: {after['status']!r} {after['rows']!r}"
    )

    code, message = _error(lambda: cwo.stop_telemetry_query(queryId=str(uuid.uuid4())))
    assert (code, message) == ("ResourceNotFoundException", "Query not found"), (
        f"unexpected answer for an unknown query id: {code}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
