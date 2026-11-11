"""op-contract-stopQuery."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-stopQuery"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopQuery cancels a running/queued Insights query and it reaches a terminal state; bogus queryId -> ResourceNotFoundException."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    stream_name = ctx.unique_name("sim2real-behav-ls-")
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[{"timestamp": now_ms, "message": f"line-{i}"} for i in range(5)],
    )

    start_resp = logs.start_query(
        logGroupName=group_name,
        startTime=int(time.time()) - 3600,
        endTime=int(time.time()) + 60,
        queryString="fields @timestamp, @message | sort @timestamp desc",
    )
    query_id = start_resp["queryId"]

    stop_resp = logs.stop_query(queryId=query_id)
    assert stop_resp["success"] is True, f"expected stop_query success=True, got {stop_resp!r}"

    final_status = _poll_until(
        lambda: logs.get_query_results(queryId=query_id)["status"],
        lambda status: status in ("Cancelled", "Complete", "Failed"),
        timeout_s=30,
        interval_s=1.0,
    )
    assert final_status in ("Cancelled", "Complete"), (
        f"expected a terminal status after stop_query, got {final_status}"
    )

    # error boundary: stopping a queryId that never existed
    bogus_query_id = str(uuid.uuid4())
    code, msg = _error(lambda: logs.stop_query(queryId=bogus_query_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} {msg!r}"
    assert msg == f"The provided queryId={bogus_query_id} is invalid.", f"unexpected message: {msg!r}"


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a mere mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
