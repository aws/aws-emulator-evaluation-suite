"""log-fields-and-record-pointer-errors-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "log-fields-and-record-pointer-errors-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetLogRecord and GetLogObject reject malformed pointers with InvalidParameterException,
    while GetLogGroupFields and GetLogFields answer unknown names with empty or stable fields.
    """
    logs = ctx.client("logs")

    # GetLogGroupFields does not validate log group existence; an unknown name returns [].
    bogus_log_group = ctx.unique_name("sim2real-behav-nonexistent-lg-")
    bogus_fields = logs.get_log_group_fields(logGroupName=bogus_log_group)
    assert bogus_fields["logGroupFields"] == [], (
        f"GetLogGroupFields on unknown log group returned unexpected fields: {bogus_fields}"
    )

    # This group also mints a real @ptr as the positive control for GetLogRecord.
    real_log_group = ctx.unique_name("sim2real-behav-emptyfields-lg-")
    logs.create_log_group(logGroupName=real_log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=real_log_group))
    ok = logs.get_log_group_fields(logGroupName=real_log_group)
    assert ok["logGroupFields"] == [], f"expected no fields yet on a fresh log group, got {ok}"

    real_stream = ctx.unique_name("sim2real-behav-emptyfields-ls-")
    logs.create_log_stream(logGroupName=real_log_group, logStreamName=real_stream)
    now_ms = int(time.time() * 1000)
    real_message = "sim2real-behav-real-record-marker"
    logs.put_log_events(
        logGroupName=real_log_group,
        logStreamName=real_stream,
        logEvents=[{"timestamp": now_ms, "message": real_message}],
    )
    def _run_query_for_marker():
        query_id = logs.start_query(
            logGroupName=real_log_group,
            startTime=(now_ms // 1000) - 300,
            endTime=(now_ms // 1000) + 300,
            queryString="fields @message, @ptr | limit 1",
        )["queryId"]
        ctx.on_cleanup(lambda: _best_effort_stop(logs, query_id))
        result = _poll_until(
            lambda: logs.get_query_results(queryId=query_id),
            lambda r: r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"),
            timeout_s=30.0,
            interval_s=2.0,
        )
        assert result["status"] == "Complete", (
            f"query for the positive control ended in {result['status']!r}"
        )
        return result["results"]

    # A query started before the event is indexed completes with zero rows, so re-issue it.
    rows = _poll_until(
        _run_query_for_marker,
        lambda rows: len(rows) >= 1,
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert rows, "expected the just-ingested event to appear in query results within the poll budget"
    row = {field["field"]: field["value"] for field in rows[0]}
    assert row["@message"] == real_message, row
    real_ptr = row["@ptr"]
    assert real_ptr, "expected a non-empty @ptr for a real log record"

    # Positive control: GetLogRecord resolves a real pointer.
    real_record = logs.get_log_record(logRecordPointer=real_ptr)["logRecord"]
    assert real_record.get("@message") == real_message, (
        f"GetLogRecord with a genuine @ptr did not return the expected event: {real_record}"
    )

    resp1, code1 = _try(
        lambda: logs.get_log_fields(
            dataSourceName=ctx.unique_name("sim2real-behav-nonexistent-ds-"),
            dataSourceType="LOG_GROUP",
        )
    )
    # GetLogFields does not validate a LOG_GROUP data source's existence; it returns a stable,
    # data-independent field schema, identical for any unknown name.
    assert code1 is None, f"GetLogFields on an unknown LOG_GROUP data source errored ({code1!r})"
    resp2, code2 = _try(
        lambda: logs.get_log_fields(
            dataSourceName=ctx.unique_name("sim2real-behav-nonexistent-ds2-"),
            dataSourceType="LOG_GROUP",
        )
    )
    assert code2 is None, (
        f"GetLogFields succeeded for one unknown LOG_GROUP data source but "
        f"errored ({code2!r}) for another"
    )
    assert resp1["logFields"] == resp2["logFields"], (
        f"GetLogFields returned different field sets for two different unknown "
        f"LOG_GROUP data source names ({resp1['logFields']!r} vs "
        f"{resp2['logFields']!r}) -- expected a stable, data-independent result "
        f"for names that don't correspond to real resources"
    )

    # GetLogRecord decodes the pointer before any lookup, so a malformed one is
    # InvalidParameterException rather than ResourceNotFoundException.
    code, code_msg = _error_code(lambda: logs.get_log_record(logRecordPointer="bogus-log-record-pointer"))
    assert code == "InvalidParameterException", (
        f"GetLogRecord with an invalid pointer returned {code!r}, expected InvalidParameterException"
    )
    expected = "InvalidParameter Unable to deserialize token"
    assert code_msg == expected, f"expected message {expected!r}, got {code_msg!r}"

    # A real logObjectPointer needs an OTLP record with a field over 1 MB.
    code, code_msg = _error_code(lambda: logs.get_log_object(logObjectPointer="bogus-log-object-pointer"))
    assert code == "InvalidParameterException", (
        f"GetLogObject with an invalid pointer returned {code!r}, expected InvalidParameterException"
    )
    expected = "Invalid log object pointer format."
    assert code_msg == expected, f"expected message {expected!r}, got {code_msg!r}"


def _error_code(fn):
    """The AWS (code, message) fn() raised. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but it succeeded, returning {result!r}")

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


def _try(fn):
    from botocore.exceptions import ClientError

    try:
        return fn(), None
    except ClientError as exc:
        return None, exc.response["Error"]["Code"]


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _best_effort_stop(logs, query_id):
    try:
        logs.stop_query(queryId=query_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
