"""result-csv-escapes-delimiters-and-distinguishes-null-from-empty-string."""
from __future__ import annotations

import csv
import io
import time

from behavioral_harness import tags

CHECK = "result-csv-escapes-delimiters-and-distinguishes-null-from-empty-string"
GROUP = "data-format"
SERVICES = ["athena", "s3"]

# A SQL NULL Datum carries NO `VarCharValue` key while an empty string carries
# `VarCharValue: ""` (VarCharValue is an optional member of the Smithy `Datum` shape); the S3 CSV
# follows RFC 4180, so a value holding the delimiter is quoted and an inner quote is doubled.


_COLUMNS = ("plain", "comma_val", "quote_val", "null_str", "empty_str", "ts", "d", "dec_val")


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object, then the bucket. Athena writes `<qid>.csv` and `<qid>.csv.metadata`
    into the output location, so DeleteBucket alone would fail. No bare `except Exception`: a
    teardown that cannot finish must surface rather than leak silently."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "athena-result-csv-escaping"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _wait_terminal(athena, qid, timeout_s=300, interval_s=2):
    """Poll GetQueryExecution to a REQUIRED terminal state with a bounded deadline; RAISES on
    timeout so a truncated poll can never record a wrong oracle."""
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


def _rows(result_set):
    """The raw Rows list, hard-subscripted: a target that omits ResultSet or Rows must raise here."""
    return result_set["Rows"]


def _datums(row):
    """The Data list of one Row, as the raw Datum dicts — NOT flattened with .get(), because whether
    the `VarCharValue` key is PRESENT is exactly what this check exists to measure."""
    return row["Data"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """The S3 result CSV is well-formed RFC 4180: a value with the delimiter is quoted, an inner
    double quote is doubled, both round-trip through a CSV parse, and a SQL NULL and an empty
    string stay distinguishable in both the GetQueryResults Datum and the file."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    bucket = _make_bucket(ctx, "sim2real-xsvc-athena-csv-")
    prefix = "results/"
    out = f"s3://{bucket}/{prefix}"

    marker = ctx.unique_name("").replace("-", "")[:12]
    plain = f"plain-{marker}"
    comma_val = "has,comma"
    quote_val = 'has"quote'
    # Column order matters: null_str and empty_str are ADJACENT and both surrounded by non-empty
    # fields, so an empty raw field (`,,`) and an empty quoted field (`,""`) can each come from
    # exactly one column.
    sql = (
        f"SELECT '{plain}' AS plain, "
        f"'{comma_val}' AS comma_val, "
        "'has\"quote' AS quote_val, "
        "CAST(NULL AS varchar) AS null_str, "
        "'' AS empty_str, "
        "TIMESTAMP '2024-03-05 06:07:08.123' AS ts, "
        "DATE '2024-03-05' AS d, "
        "CAST(1.05 AS DECIMAL(10,4)) AS dec_val"
    )
    qid = athena.start_query_execution(
        QueryString=sql, ResultConfiguration={"OutputLocation": out})["QueryExecutionId"]
    state = _wait_terminal(athena, qid)
    reason = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"].get(
        "StateChangeReason")
    assert state == "SUCCEEDED", (
        f"the literal SELECT must succeed before its rendering is judged; got {state!r} / "
        f"{reason!r}")

    result_set = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]
    rows = _rows(result_set)
    assert len(rows) == 2, (
        f"a single-row SELECT returns the header row plus one data row, so exactly 2 Rows; got "
        f"{len(rows)}: {rows!r}")

    header_values = [d.get("VarCharValue") for d in _datums(rows[0])]
    assert header_values == list(_COLUMNS), (
        f"row 0 must repeat the projected column names in projection order: expected "
        f"{list(_COLUMNS)!r}, got {header_values!r}")

    datums = _datums(rows[1])
    assert len(datums) == len(_COLUMNS), (
        f"the data row must carry one Datum per projected column ({len(_COLUMNS)}), got "
        f"{len(datums)}: {datums!r}")
    by_name = dict(zip(_COLUMNS, datums))

    # --- leg 1: values that stress the CSV grammar survive the API round trip byte-exactly.
    assert by_name["plain"] == {"VarCharValue": plain}, (
        f"the plain column must carry exactly {plain!r}, got {by_name['plain']!r}")
    assert by_name["comma_val"] == {"VarCharValue": comma_val}, (
        f"a value containing the CSV delimiter must survive intact: expected {comma_val!r}, got "
        f"{by_name['comma_val']!r}")
    assert by_name["quote_val"] == {"VarCharValue": quote_val}, (
        f"a value containing a double quote must survive intact: expected {quote_val!r}, got "
        f"{by_name['quote_val']!r}")

    # --- leg 2, the subject on the API side: NULL and '' are NOT the same thing.
    null_datum = by_name["null_str"]
    empty_datum = by_name["empty_str"]
    assert null_datum != empty_datum, (
        f"a SQL NULL and a SQL empty string must be distinguishable in the ResultSet, otherwise "
        f"every client conflates missing with blank; both rendered as {null_datum!r}")
    assert "VarCharValue" not in null_datum, (
        f"a NULL Datum carries no VarCharValue at all (the member is optional in the model); got "
        f"{null_datum!r}")
    assert empty_datum == {"VarCharValue": ""}, (
        f"an empty string is a PRESENT value, so its Datum must carry VarCharValue ''; got "
        f"{empty_datum!r}")

    # --- leg 3: typed rendering and the column metadata that goes with it.
    assert by_name["ts"] == {"VarCharValue": "2024-03-05 06:07:08.123"}, (
        f"a TIMESTAMP literal must render with its millisecond precision preserved; got "
        f"{by_name['ts']!r}")
    assert by_name["d"] == {"VarCharValue": "2024-03-05"}, (
        f"a DATE literal must render as an ISO date; got {by_name['d']!r}")
    assert by_name["dec_val"] == {"VarCharValue": "1.0500"}, (
        f"CAST(1.05 AS DECIMAL(10,4)) must render padded to its declared scale of 4; got "
        f"{by_name['dec_val']!r}")
    columns = {c["Name"]: c for c in result_set["ResultSetMetadata"]["ColumnInfo"]}
    types = {name: columns[name]["Type"] for name in _COLUMNS}
    assert types == {
        "plain": "varchar", "comma_val": "varchar", "quote_val": "varchar",
        "null_str": "varchar", "empty_str": "varchar",
        "ts": "timestamp", "d": "date", "dec_val": "decimal",
    }, (
        f"ColumnInfo.Type is the only place type information exists on the wire, and a JDBC client "
        f"has nothing else to go on; got {types!r}")
    assert (columns["dec_val"]["Precision"], columns["dec_val"]["Scale"]) == (10, 4), (
        f"the DECIMAL(10,4) declared by the query itself must be reported back as Precision 10, "
        f"Scale 4; got {columns['dec_val']!r}")

    # --- leg 4: the S3 artifact. Parsed as CSV, it must agree with the API, field for field.
    csv_key = f"{prefix}{qid}.csv"
    raw = s3.get_object(Bucket=bucket, Key=csv_key)["Body"].read().decode("utf-8")
    parsed = list(csv.reader(io.StringIO(raw)))
    assert len(parsed) == 2, (
        f"s3://{bucket}/{csv_key} must parse as exactly a header row plus one data row; a wrong "
        f"field count or a missing quote shows up here first. Got {len(parsed)} rows: {parsed!r}")
    assert parsed[0] == list(_COLUMNS), (
        f"the file's first line must be the same header the API returned: expected "
        f"{list(_COLUMNS)!r}, got {parsed[0]!r}")
    data_fields = parsed[1]
    assert len(data_fields) == len(_COLUMNS), (
        f"the data line must parse into exactly {len(_COLUMNS)} fields — a target that joined the "
        f"values on ',' without quoting {comma_val!r} produces {len(_COLUMNS) + 1}. Got "
        f"{len(data_fields)}: {data_fields!r}")
    parsed_by_name = dict(zip(_COLUMNS, data_fields))
    for name in ("plain", "comma_val", "quote_val", "ts", "d", "dec_val"):
        expected = by_name[name]["VarCharValue"]
        assert parsed_by_name[name] == expected, (
            f"the file and the API must agree on column {name!r}: the API returned {expected!r}, "
            f"the parsed CSV field was {parsed_by_name[name]!r}")

    # --- leg 5: the raw bytes really apply RFC 4180, and really distinguish NULL from ''.
    data_line = raw.splitlines()[1]
    assert f'"{comma_val}"' in data_line, (
        f"RFC 4180 requires a value containing the delimiter to be enclosed in double quotes, so "
        f'the raw line must contain \'"{comma_val}"\'; got {data_line!r}')
    assert '"has""quote"' in data_line, (
        f'RFC 4180 requires a literal double quote inside a quoted field to be doubled, so the raw '
        f'line must contain \'"has""quote"\'; got {data_line!r}')
    bare_empty = data_line.count(",,")
    quoted_empty = data_line.count(',""')
    assert bare_empty == 1, (
        f"the NULL column is the only empty column that is not an empty STRING, so exactly one "
        f"empty unquoted field may appear on the raw line; counted {bare_empty} in {data_line!r}")
    assert quoted_empty == 1, (
        f"the empty-string column is the only empty QUOTED field, so exactly one may appear on the "
        f"raw line; counted {quoted_empty} in {data_line!r}")

    metadata_head = s3.head_object(Bucket=bucket, Key=f"{csv_key}.metadata")
    assert metadata_head["ContentLength"] > 0, (
        f"Athena writes a non-empty `.csv.metadata` sibling carrying the result schema; S3 reported "
        f"ContentLength={metadata_head['ContentLength']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
