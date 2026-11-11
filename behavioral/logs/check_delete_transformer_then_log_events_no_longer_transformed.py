"""delete-transformer-then-log-events-no-longer-transformed."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-transformer-then-log-events-no-longer-transformed"
GROUP = "data-plane"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A parseKeyValue transformer adds parsed fields to GetLogRecord output; after DeleteTransformer,
    newly ingested events are stored raw: no parsed fields and @message equal to the raw text."""
    logs = ctx.client("logs")
    log_group = ctx.unique_name("sim2real-xform-lg")
    log_stream = ctx.unique_name("sim2real-xform-ls")
    marker = ctx.unique_name("sim2real-xform-mk")

    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

    # "action=login&user=<marker>1" becomes top-level fields action="login" and user="<marker>1".
    logs.put_transformer(
        logGroupIdentifier=log_group,
        transformerConfig=[{"parseKeyValue": {}}],
    )

    message1 = f"action=login&user={marker}1"
    start_sec_1 = int(time.time()) - 30
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": message1}],
    )

    record1 = _wait_for_insights_match(ctx, log_group, f"{marker}1", start_sec_1)
    log_record1 = logs.get_log_record(logRecordPointer=record1["@ptr"])["logRecord"]
    assert log_record1.get("action") == "login", log_record1
    assert log_record1.get("user") == f"{marker}1", log_record1

    logs.delete_transformer(logGroupIdentifier=log_group)

    message2 = f"action=logout&user={marker}2"
    start_sec_2 = int(time.time()) - 30
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": message2}],
    )

    record2 = _wait_for_insights_match(ctx, log_group, f"{marker}2", start_sec_2)
    log_record2 = logs.get_log_record(logRecordPointer=record2["@ptr"])["logRecord"]
    assert "action" not in log_record2, log_record2
    assert "user" not in log_record2, log_record2
    assert log_record2["@message"] == message2, log_record2


def _poll_query_result(ctx, query_id: str, timeout_s: float = 30.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    status = "Scheduled"
    results: list = []
    while time.monotonic() < deadline:
        resp = logs.get_query_results(queryId=query_id)
        status = resp["status"]
        if status in ("Complete", "Failed", "Cancelled", "Timeout"):
            results = resp.get("results", [])
            break
        time.sleep(2)
    return status, results


def _wait_for_insights_match(ctx, log_group: str, filter_substring: str, start_sec: int, timeout_s: float = 150.0):
    """Poll Logs Insights until a record whose @message contains filter_substring appears."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        end_sec = int(time.time()) + 60
        query_id = logs.start_query(
            logGroupName=log_group,
            startTime=start_sec,
            endTime=end_sec,
            queryString=f"fields @ptr, @message | filter @message like /{filter_substring}/ | limit 5",
        )["queryId"]
        status, results = _poll_query_result(ctx, query_id)
        if status == "Complete" and results:
            return {f["field"]: f["value"] for f in results[0]}
        time.sleep(4)
    raise AssertionError(f"Logs Insights never returned a match for {filter_substring!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
