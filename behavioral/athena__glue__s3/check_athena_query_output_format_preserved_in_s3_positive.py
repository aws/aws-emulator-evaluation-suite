"""athena-query-output-format-preserved-in-s3-positive."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "athena-query-output-format-preserved-in-s3-positive"
GROUP = "data-format"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Athena result (.csv) and metadata (.csv.metadata) files written to S3
    preserve the column types reported by GetQueryResults, and the CSV content
    reflects the typed values from the query."""
    bucket = _create_bucket(ctx, "fmt")
    prefix = "results/"
    output_location = f"s3://{bucket}/{prefix}"

    query = (
        "SELECT CAST(42 AS INTEGER) AS int_col, CAST(3.14 AS DOUBLE) AS dbl_col, "
        "CAST(true AS BOOLEAN) AS bool_col, 'sim2real-format-marker' AS str_col"
    )
    qid, state, exec_resp = _run_query(ctx, query=query, output_location=output_location)
    assert state == "SUCCEEDED", f"query did not succeed: {exec_resp['Status']}"

    athena = ctx.client("athena")
    result_set = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]
    col_info = result_set["ResultSetMetadata"]["ColumnInfo"]
    types_by_name = {c["Name"]: c["Type"] for c in col_info}
    assert types_by_name["int_col"] == "integer", f"int_col: expected type 'integer', got {types_by_name['int_col']!r}"
    assert types_by_name["dbl_col"] == "double", f"dbl_col: expected type 'double', got {types_by_name['dbl_col']!r}"
    assert types_by_name["bool_col"] == "boolean", f"bool_col: expected type 'boolean', got {types_by_name['bool_col']!r}"
    assert types_by_name["str_col"] == "varchar", f"str_col: expected type 'varchar', got {types_by_name['str_col']!r}"

    s3 = ctx.client("s3")
    csv_key = f"{prefix}{qid}.csv"
    body = s3.get_object(Bucket=bucket, Key=csv_key)["Body"].read().decode("utf-8")
    lines = [ln for ln in body.splitlines() if ln]
    assert len(lines) == 2, f"expected header + 1 data row, got {len(lines)}: {lines}"
    header = lines[0]
    assert "int_col" in header, f"expected column 'int_col' in CSV header, got: {header!r}"
    assert "dbl_col" in header, f"expected column 'dbl_col' in CSV header, got: {header!r}"
    assert "bool_col" in header, f"expected column 'bool_col' in CSV header, got: {header!r}"
    assert "str_col" in header, f"expected column 'str_col' in CSV header, got: {header!r}"
    data_line = lines[1]
    assert "42" in data_line, f"expected '42' in CSV data row, got: {data_line!r}"
    assert "3.14" in data_line, f"expected '3.14' in CSV data row, got: {data_line!r}"
    assert "true" in data_line, f"expected 'true' in CSV data row, got: {data_line!r}"
    assert "sim2real-format-marker" in data_line, f"expected 'sim2real-format-marker' in CSV data row, got: {data_line!r}"

    # Athena writes a companion metadata file next to every CSV result object. It is a
    # binary (Thrift) blob, but real AWS embeds each column's name and type as literal
    # ASCII within it (the bytes contain
    # b"int_col"..b"integer", b"dbl_col"..b"double", b"bool_col"..b"boolean",
    # b"str_col"..b"varchar", in column order) -- so the companion file's own bytes are
    # checked against the same type contract as the CSV and the API, not just presence.
    metadata_key = f"{prefix}{qid}.csv.metadata"
    meta_body = s3.get_object(Bucket=bucket, Key=metadata_key)["Body"].read()
    assert len(meta_body) > 0, f"expected non-empty .csv.metadata companion file, got {len(meta_body)} bytes"
    assert b"int_col" in meta_body, f"expected column name 'int_col' encoded in .csv.metadata body, got {meta_body!r}"
    assert b"integer" in meta_body, f"expected type name 'integer' encoded in .csv.metadata body, got {meta_body!r}"
    assert b"dbl_col" in meta_body, f"expected column name 'dbl_col' encoded in .csv.metadata body, got {meta_body!r}"
    assert b"double" in meta_body, f"expected type name 'double' encoded in .csv.metadata body, got {meta_body!r}"
    assert b"bool_col" in meta_body, f"expected column name 'bool_col' encoded in .csv.metadata body, got {meta_body!r}"
    assert b"boolean" in meta_body, f"expected type name 'boolean' encoded in .csv.metadata body, got {meta_body!r}"
    assert b"str_col" in meta_body, f"expected column name 'str_col' encoded in .csv.metadata body, got {meta_body!r}"
    assert b"varchar" in meta_body, f"expected type name 'varchar' encoded in .csv.metadata body, got {meta_body!r}"


def _create_bucket(ctx, kind: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-athena-{kind}-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _run_query(
    ctx,
    query: str,
    output_location: str | None = None,
    database: str | None = None,
    workgroup: str | None = None,
    timeout_s: float = 120.0,
):
    athena = ctx.client("athena")
    kwargs: dict = {"QueryString": query}
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    if output_location:
        kwargs["ResultConfiguration"] = {"OutputLocation": output_location}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    resp = athena.start_query_execution(**kwargs)
    qid = resp["QueryExecutionId"]
    deadline = time.monotonic() + timeout_s
    exec_resp = None
    state = None
    while time.monotonic() < deadline:
        exec_resp = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = exec_resp["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return qid, state, exec_resp
        time.sleep(2)
    raise AssertionError(f"query {qid} did not finish in {timeout_s}s, last state {state}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
