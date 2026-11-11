"""redefining-a-view-changes-what-a-query-over-it-binds."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redefining-a-view-changes-what-a-query-over-it-binds"
GROUP = "views"
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
    """A query over a view binds the view's current definition: refused while the view has no
    datastore, it completes once UpdateView points the view at the default dataset.
    """
    cwo = ctx.client("cloudwatchomni")
    name = ctx.unique_name("view.sim2realbehavcwo")
    cwo.create_view(name=name, definition="SELECT 1")
    ctx.on_cleanup(_teardown(lambda: cwo.delete_view(name=name), "ResourceNotFoundException"))
    session_id = _session(ctx, cwo)
    query = f"SELECT count(*) AS n FROM `{name}`"

    code, message = _error(lambda: cwo.start_telemetry_query(sessionId=session_id, queryString=query))
    assert (code, message) == ("ValidationException", (
        f"Error during planning: Failed to bind view `{name}`: Error during planning: view body parse "
        "failed: validation error: At least one datastore is required in FROM clause"
    )), f"expected the unbindable view to be refused, got {code}: {message!r}"

    cwo.update_view(name=name, definition=f"SELECT `@message` FROM default WHERE {_window()}")
    query_id = cwo.start_telemetry_query(sessionId=session_id, queryString=query)["queryId"]
    res = _results(ctx, cwo, query_id)
    assert res["status"] == "Complete", f"expected Complete, got {res['status']!r}"
    assert res["rows"] == [{"n": "0"}], f"expected one zero-count row over the empty window, got {res['rows']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
