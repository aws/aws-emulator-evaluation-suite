"""query-results-unicode-and-numeric-literal-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-results-unicode-and-numeric-literal-preserved"
GROUP = "representation"
SERVICES = ["athena"]

_UNICODE_TEXT = "h\u00e9llo w\u00f6rld \u65e5\u672c\u8a9e \U0001f389"
_NUMERIC_LITERAL = "123456789012345.123456789"
_QUERY = (
    f"SELECT '{_UNICODE_TEXT}' AS txt, "
    f"CAST('{_NUMERIC_LITERAL}' AS DECIMAL(38,9)) AS num"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query selecting a unicode string literal and a high-precision DECIMAL
    literal returns those values byte-identical in GetQueryResults, with no
    truncation or normalization."""
    athena = ctx.client("athena")
    bucket = _create_bucket(ctx)
    wg_name = ctx.unique_name("sim2real-behav-reprwg-")
    athena.create_work_group(
        Name=wg_name, Configuration={"ResultConfiguration": {"OutputLocation": f"s3://{bucket}/"}}
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    qid = athena.start_query_execution(QueryString=_QUERY, WorkGroup=wg_name)["QueryExecutionId"]
    state, execution = _wait_query_terminal(ctx, qid, timeout_s=120)
    assert state == "SUCCEEDED", f"query did not succeed: {execution['Status']}"

    result = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]
    rows = result["Rows"]
    # A SELECT always repeats its column names as row 0 before the data row.
    assert len(rows) == 2, f"expected header row + 1 data row, got {len(rows)} rows"
    header_row, data_row = rows[0]["Data"], rows[1]["Data"]
    assert header_row[0]["VarCharValue"] == "txt", (
        f"header col 0 mismatch: {header_row[0]['VarCharValue']!r} != 'txt'"
    )
    assert header_row[1]["VarCharValue"] == "num", (
        f"header col 1 mismatch: {header_row[1]['VarCharValue']!r} != 'num'"
    )
    assert data_row[0]["VarCharValue"] == _UNICODE_TEXT, (
        f"unicode text mismatch: {data_row[0]['VarCharValue']!r} != {_UNICODE_TEXT!r}"
    )
    assert data_row[1]["VarCharValue"] == _NUMERIC_LITERAL, (
        f"numeric literal mismatch: {data_row[1]['VarCharValue']!r} != {_NUMERIC_LITERAL!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-athena-repr-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _wait_query_terminal(ctx, query_execution_id: str, timeout_s: float = 120.0):
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    execution = None
    while time.monotonic() < deadline:
        execution = athena.get_query_execution(QueryExecutionId=query_execution_id)["QueryExecution"]
        state = execution["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return state, execution
        time.sleep(2)
    raise AssertionError(f"query {query_execution_id} did not reach a terminal state in {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
