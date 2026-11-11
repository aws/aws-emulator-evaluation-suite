"""e2e-lookup-table-enrichment-flow."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-lookup-table-enrichment-flow"
GROUP = "e2e"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A lookup table's CSV data enriches Logs Insights results through the `lookup` query command,
    joining ingested events against the table so the output fields carry the table's values.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-Lookup.html"""
    logs = ctx.client("logs")

    table_body = (
        "user_id,name,department\n"
        "u1,Alice,Engineering\n"
        "u2,Bob,Sales\n"
    )
    lookup_table_name = ctx.unique_name("sim2real_behav_lookup_").replace("-", "_")
    account = ctx.client("sts").get_caller_identity()["Account"]
    table = logs.create_lookup_table(lookupTableName=lookup_table_name, tableBody=table_body)
    lookup_table_arn = table["lookupTableArn"]
    ctx.on_cleanup(
        lambda: _ignore(lambda: logs.delete_lookup_table(lookupTableArn=lookup_table_arn))
    )

    log_group = ctx.unique_name("sim2real-behav-lookup-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: _ignore(lambda: logs.delete_log_group(logGroupName=log_group)))

    stream_name = ctx.unique_name("sim2real-behav-lookup-stream-")
    logs.create_log_stream(logGroupName=log_group, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    events = [
        {
            "timestamp": now_ms,
            "message": json.dumps({"user_id": "u1", "action": "login"}),
        },
        {
            "timestamp": now_ms + 1,
            "message": json.dumps({"user_id": "u2", "action": "logout"}),
        },
    ]
    logs.put_log_events(logGroupName=log_group, logStreamName=stream_name, logEvents=events)

    query_string = (
        f"fields user_id, action, name, department "
        f"| lookup {lookup_table_name} user_id OUTPUT name, department"
    )
    now_s = now_ms // 1000

    def _run_once() -> dict[str, dict[str, str]]:
        query_id = _poll_until(
            lambda: _try_start_query(logs, log_group, now_s - 600, now_s + 600, query_string),
            lambda qid: qid is not None,
            timeout_s=60,
            interval_s=5,
        )
        results = _poll_until(
            lambda: logs.get_query_results(queryId=query_id),
            lambda r: r["status"] == "Complete",
            timeout_s=90,
            interval_s=3,
        )
        assert results["status"] == "Complete", (
            f"expected query status Complete, got {results['status']!r}"
        )
        by_user: dict[str, dict[str, str]] = {}
        for row in results["results"]:
            fields = {f["field"]: f["value"] for f in row}
            if "user_id" in fields:
                by_user[fields["user_id"]] = fields
        return by_user

    # Insights indexing of new events and the lookup join are eventually consistent, so the
    # whole query cycle is retried until both rows appear, under a bounded deadline.
    by_user: dict[str, dict[str, str]] = _poll_until(
        _run_once,
        lambda bu: "u1" in bu and "u2" in bu,
        timeout_s=300,
        interval_s=15,
    )

    assert by_user["u1"]["name"] == "Alice", (
        f"expected lookup-enriched name Alice for u1, got {by_user['u1']['name']!r}"
    )
    assert by_user["u1"]["department"] == "Engineering", (
        f"expected lookup-enriched department Engineering for u1, got "
        f"{by_user['u1']['department']!r}"
    )
    assert by_user["u2"]["name"] == "Bob", (
        f"expected lookup-enriched name Bob for u2, got {by_user['u2']['name']!r}"
    )
    assert by_user["u2"]["department"] == "Sales", (
        f"expected lookup-enriched department Sales for u2, got "
        f"{by_user['u2']['department']!r}"
    )

    logs.delete_lookup_table(lookupTableArn=lookup_table_arn)
    code, message = _error(lambda: logs.get_lookup_table(lookupTableArn=lookup_table_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetLookupTable after DeleteLookupTable, "
        f"got {code!r}"
    )
    assert message == (
        f"Lookup table '{lookup_table_name}' not found in account '{account}'"
    ), (
        f"unexpected GetLookupTable message after DeleteLookupTable: {message!r}"
    )


def _try_start_query(
    logs_client: Any, log_group: str, start_time_ms: int, end_time_ms: int, query_string: str
) -> str | None:
    from botocore.exceptions import ClientError

    try:
        resp = logs_client.start_query(
            queryLanguage="CWLI",
            logGroupName=log_group,
            startTime=start_time_ms,
            endTime=end_time_ms,
            queryString=query_string,
        )
        return resp["queryId"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("ResourceNotFoundException", "LimitExceededException"):
            return None
        raise


def _ignore(fn: Any) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe: Any, predicate: Any, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
