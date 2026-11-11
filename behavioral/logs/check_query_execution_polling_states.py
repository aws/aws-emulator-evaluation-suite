"""query-execution-polling-states."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-execution-polling-states"
GROUP = 'insights'
SERVICES = ['logs']


def _logs_refusal(text, code, message):
    """`text` with the suffix CloudWatch Logs appends to a refusal. Only the per-call request id is
    read from `message`, and only in its 36-character form."""
    found = re.search(r"; Request ID: ([0-9a-f-]{36}); Proxy: null\)$", message or "")
    request_id = found.group(1) if found else "<no request id>"
    return (
        f"{text} (Service: AWSLogs; Status Code: 400; Error Code: {code}; "
        f"Request ID: {request_id}; Proxy: null)"
    )


def _make_events(messages, start_ts_ms=None, step_ms=1000):
    base = start_ts_ms if start_ts_ms is not None else int(time.time() * 1000)
    return [{"timestamp": base + i * step_ms, "message": m} for i, m in enumerate(messages)]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetQueryResults status only advances Scheduled -> Running -> terminal and never reverts.
    StopQuery right after StartQuery succeeds, or is refused with InvalidParameterException and the
    exact message naming the terminal status.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-qpoll-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)
    svc.put_log_events(
        logGroupName=group, logStreamName=stream, logEvents=_make_events(["polling-probe-event"])
    )

    now = int(time.time())
    start_resp = svc.start_query(
        logGroupName=group,
        startTime=now - 3600,
        endTime=now + 3600,
        queryString="fields @timestamp, @message | limit 10",
    )
    query_id = start_resp["queryId"]

    # StopQuery may legally succeed (the query is usually still running) or be refused.
    stop_message = None
    try:
        stop_resp = svc.stop_query(queryId=query_id)
    except ClientError as exc:
        stop_code = exc.response.get("Error", {}).get("Code")
        # The ending status depends on the race and the backend Request ID varies.
        assert stop_code == "InvalidParameterException", (
            f"expected a documented StopQuery rejection code, got {stop_code!r}"
        )
        stop_message = exc.response.get("Error", {}).get("Message") or ""
    else:
        assert stop_resp.get("success") is True, (
            f"expected an accepted StopQuery to report success=True, got {stop_resp!r}"
        )

    terminal = {"Complete", "Failed", "Cancelled", "Timeout"}
    seen_statuses: list[str] = []

    def _probe():
        resp = svc.get_query_results(queryId=query_id)
        status = resp["status"]
        if not seen_statuses or seen_statuses[-1] != status:
            seen_statuses.append(status)
        return resp

    final_resp = _poll_until(
        _probe,
        lambda r: r["status"] in terminal,
        timeout_s=60,
        interval_s=1.5,
        description="query reaches a terminal status after StopQuery",
    )
    assert seen_statuses, "never observed any query status"
    assert seen_statuses[-1] in terminal, f"query never reached a terminal state: {seen_statuses!r}"
    assert final_resp["status"] == seen_statuses[-1], (
        f"final probe status {final_resp['status']!r} disagrees with tracked history {seen_statuses!r}"
    )
    if stop_message is not None:
        # A refused stop names the status the query had already ended with.
        expected = _logs_refusal(
            f"Query is already ended with {final_resp['status']}", "InvalidParameterException", stop_message
        )
        assert stop_message == expected, f"expected StopQuery refusal {expected!r}, got {stop_message!r}"

    # A later poll must never rank behind an earlier one.
    rank = {"Scheduled": 0, "Running": 1, "Complete": 2, "Failed": 2, "Cancelled": 2, "Timeout": 2}
    ranks_seen = [rank.get(s, -1) for s in seen_statuses]
    assert ranks_seen == sorted(ranks_seen), (
        f"query status sequence regressed instead of advancing monotonically: {seen_statuses!r}"
    )

    # Once terminal, a further poll must report the same terminal status.
    resp_after = svc.get_query_results(queryId=query_id)
    assert resp_after["status"] == seen_statuses[-1], (
        f"query status regressed after reaching terminal state: "
        f"{seen_statuses[-1]!r} -> {resp_after['status']!r}"
    )
    assert resp_after["status"] not in ("Running", "Scheduled"), (
        f"terminal query unexpectedly reported a non-terminal status on re-poll: {resp_after['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
