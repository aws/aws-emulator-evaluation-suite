"""data-manifest-lists-exactly-the-objects-unload-wrote."""
from __future__ import annotations

import gzip
import json
import time

from behavioral_harness import tags

CHECK = "data-manifest-lists-exactly-the-objects-unload-wrote"
GROUP = "data-plane-depth"
SERVICES = ["athena", "s3"]


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object (query results, manifests, UNLOAD data files), then the bucket."""
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
        {"Key": "sim2real", "Value": "athena-unload-data-manifest"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _output_location(ctx):
    return f"s3://{_make_bucket(ctx, 'sim2real-xsvc-athena-results-')}/results/"


def _start_query(athena, out, query_string, database=None):
    kwargs = {"QueryString": query_string, "ResultConfiguration": {"OutputLocation": out}}
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _wait_terminal(athena, qid, timeout_s=300, interval_s=2):
    """Poll GetQueryExecution to a terminal state; raise on timeout."""
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


def _run_sql(athena, out, sql, database=None):
    qid = _start_query(athena, out, sql, database=database)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state}, expected SUCCEEDED: {sql!r} -- "
            f"{status.get('StateChangeReason')}")
    return qid


def _data_rows(results):
    """Row 0 of a SELECT ResultSet repeats the column names, so the data rows are rows[1:]."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _dml_name(database, table):
    """DML goes through the Trino parser (double-quoted identifiers); DDL through Hive
    (backticks)."""
    return f'"{database}"."{table}"'


def _split_s3_uri(uri):
    """('bucket', 'key') from an s3://bucket/key URI; fails on anything else."""
    assert uri.startswith("s3://"), f"expected an s3:// URI, got {uri!r}"
    bucket, _, key = uri[len("s3://"):].partition("/")
    assert bucket and key, f"expected s3://bucket/key, got {uri!r}"
    return bucket, key


def _list_objects(s3, bucket, prefix):
    """Every key under `prefix`."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An UNLOAD's data manifest names exactly the objects it wrote to S3, and those gzip-compressed
    JSON objects contain exactly the source rows.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/unload.html
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    out = _output_location(ctx)
    data_bucket = _make_bucket(ctx, "sim2real-xsvc-athena-data-")

    marker = ctx.unique_name("").replace("-", "")[:12]
    source = tuple((i, f"row{i}-{marker}") for i in range(1, 6))
    body = "".join(f"{i},{name}\n" for i, name in source).encode()
    s3.put_object(Bucket=data_bucket, Key="src/rows.csv", Body=body)

    database = ctx.unique_name("sim2real-xsvc-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-xsvc-tbl-").replace("-", "_")
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` (`id` int, `name` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'")

    # Sanity: the table really reads the object, so a later manifest mismatch is about the manifest.
    read_back = _data_rows(athena.get_query_results(QueryExecutionId=_run_sql(
        athena, out, f"SELECT id, name FROM {_dml_name(database, table)} ORDER BY id",
        database=database)))
    expected_rows = [[str(i), name] for i, name in source]
    assert read_back == expected_rows, (
        f"the source table must read the uploaded object before UNLOAD is judged: expected "
        f"{expected_rows!r}, got {read_back!r}")

    unload_prefix = "unloaded/"
    unload_qid = _run_sql(
        athena, out,
        f"UNLOAD (SELECT id, name FROM {_dml_name(database, table)}) "
        f"TO 's3://{data_bucket}/{unload_prefix}' WITH (format = 'JSON')",
        database=database)
    stats = athena.get_query_execution(QueryExecutionId=unload_qid)["QueryExecution"]["Statistics"]
    assert stats["DataScannedInBytes"] == len(body), (
        f"the UNLOAD must have read exactly the {len(body)} source bytes, got "
        f"DataScannedInBytes={stats['DataScannedInBytes']!r}")

    # The manifest exists, is fetchable, and names s3:// URIs under the destination.
    manifest_uri = stats["DataManifestLocation"]
    m_bucket, m_key = _split_s3_uri(manifest_uri)
    manifest_body = s3.get_object(Bucket=m_bucket, Key=m_key)["Body"].read().decode("utf-8")
    manifest_uris = [line.strip() for line in manifest_body.splitlines() if line.strip()]
    assert manifest_uris, (
        f"the UNLOAD wrote data, so its manifest at {manifest_uri!r} must list at least one file; "
        f"body was {manifest_body!r}")
    destination = f"s3://{data_bucket}/{unload_prefix}"
    off_prefix = [u for u in manifest_uris if not u.startswith(destination)]
    assert off_prefix == [], (
        f"every manifest entry must point inside the UNLOAD destination {destination!r}; these did "
        f"not: {off_prefix!r}")

    # The manifest's set of files equals what S3 holds.
    listed = sorted(_list_objects(s3, data_bucket, unload_prefix))
    claimed = sorted(_split_s3_uri(u)[1] for u in manifest_uris)
    assert claimed == listed, (
        f"the data manifest must name exactly the objects the UNLOAD created: manifest claims "
        f"{claimed!r}, S3 holds {listed!r}")

    # The objects contain the source rows as JSON. Athena always gzips JSON/TEXTFILE UNLOAD output;
    # the `compression` property applies only to ORC and Parquet.
    recovered = []
    for key in listed:
        raw = s3.get_object(Bucket=data_bucket, Key=key)["Body"].read()
        assert raw[:2] == b"\x1f\x8b", (
            f"a JSON UNLOAD object must be gzip-compressed (Athena's fixed encoding for JSON/"
            f"TEXTFILE output); {key!r} did not start with the gzip magic bytes: {raw[:16]!r}")
        text = gzip.decompress(raw).decode("utf-8")
        for line in text.splitlines():
            if line.strip():
                recovered.append(json.loads(line))
    expected_objects = sorted(({"id": i, "name": name} for i, name in source),
                              key=lambda o: o["id"])
    assert sorted(recovered, key=lambda o: o["id"]) == expected_objects, (
        f"the UNLOAD files must contain exactly the {len(source)} source rows as JSON objects "
        f"keyed by the projected column names: expected {expected_objects!r}, recovered "
        f"{recovered!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
