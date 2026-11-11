"""ctas-partitioned-by-writes-one-s3-prefix-per-partition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ctas-partitioned-by-writes-one-s3-prefix-per-partition"
GROUP = "query-execution"
SERVICES = ["athena"]

#: Deliberately uneven group sizes and a negative value, so a target that writes one object per
#: ROW, one object per TABLE, or a constant number of objects cannot coincide with the right
#: answer, and no group's byte count can equal another's.
_ROWS = (
    ("alpha", 5),
    ("alpha", 7),
    ("beta", 40),
    ("beta", 2),
    ("beta", -3),
    ("gamma", 100),
    ("gamma", -50),
    ("gamma", 7),
    ("gamma", 1),
)


def _dataset():
    """The CSV bytes and the independently computed per-group values, from one source of truth."""
    body = "".join(f"{i},{cat},{amt}\n" for i, (cat, amt) in enumerate(_ROWS)).encode()
    groups = {}
    for cat, amt in _ROWS:
        groups.setdefault(cat, []).append(amt)
    return body, groups


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object, then the bucket: Athena writes query results and CTAS data files into
    the buckets, so DeleteBucket alone would fail and leak cost."""
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
    # registered BEFORE the name is used anywhere else
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    # Tagged together with the create so tag-based cleanup can always find the bucket.
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _start_query(athena, out, query_string, database=None):
    kwargs = {"QueryString": query_string, "ResultConfiguration": {"OutputLocation": out}}
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _wait_terminal(athena, qid, timeout_s=240, interval_s=2):
    """Poll GetQueryExecution to a REQUIRED terminal state with a bounded deadline; RAISES on
    timeout so a truncated poll is never graded as a result."""
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(
            QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state!r})")


def _run_sql(athena, out, sql, database=None):
    qid = _start_query(athena, out, sql, database=database)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state!r}, expected 'SUCCEEDED': {sql!r} -- "
            f"{status.get('StateChangeReason')!r}")
    return qid


def _data_rows(athena, qid):
    """Row 0 of a SELECT ResultSet repeats the column names, so the data rows are rows[1:].
    Returned as a LIST: ORDER BY makes the order a server-side guarantee and a target that
    shuffles must fail. Hard-subscripted so a missing ResultSet raises."""
    rows = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _all_rows(athena, qid):
    """Every row, header included: SHOW PARTITIONS emits no header row, so rows[1:] drops one."""
    rows = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows]


def _dml_name(database, table):
    """Athena parses DDL with the Hive parser (BACKTICK identifiers) and DML with the Trino parser
    (DOUBLE-QUOTE identifiers). A backtick inside a SELECT makes the statement unclassifiable and
    StartQueryExecution refuses it SYNCHRONOUSLY with InvalidRequestException."""
    return f'"{database}"."{table}"'


def _scanned(athena, qid):
    return athena.get_query_execution(
        QueryExecutionId=qid)["QueryExecution"]["Statistics"]["DataScannedInBytes"]


def _keys_under(s3, bucket, prefix):
    """Every (key, size) under a prefix THIS CHECK created, paginated."""
    found = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            found.append((obj["Key"], obj["Size"]))
    return sorted(found)


def _sizes_by_partition(keys, prefix):
    """Group (key, size) pairs by the Hive partition directory immediately under `prefix`.
    An object with no `<col>=<value>` segment is grouped under None so a wrong depth is visible."""
    out = {}
    for key, size in keys:
        rest = key[len(prefix):]
        segments = rest.split("/")
        part = segments[0] if len(segments) > 1 and "=" in segments[0] else None
        out.setdefault(part, []).append((key, size))
    return out


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CTAS with partitioned_by writes one Hive partition directory per key value, registers
    exactly those partitions without MSCK REPAIR, and a one-partition read scans only its bytes.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/ctas-partitioning-and-bucketing.html
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    out = f"s3://{results_bucket}/results/"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    body, groups = _dataset()
    s3.put_object(Bucket=data_bucket, Key="src/rows.csv", Body=body)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    src = ctx.unique_name("sim2real-behav-src-").replace("-", "_")
    dest = ctx.unique_name("sim2real-behav-dest-").replace("-", "_")
    dest_prefix = "dest/"
    # Registered BEFORE the CREATE it undoes: CASCADE drops the tables too, and DROP DATABASE is
    # itself an Athena query, so LIFO keeps the results bucket alive until after it runs.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{src}` "
        "(`id` int, `cat` string, `amount` bigint) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'")

    # The destination prefix is one only this check writes, in a bucket it just created, so
    # "empty" here is a property of the query and not a snapshot of the account.
    before = _keys_under(s3, data_bucket, dest_prefix)
    assert before == [], (
        f"the CTAS destination prefix s3://{data_bucket}/{dest_prefix} must be empty before the "
        f"CTAS runs, got {before!r}")

    # --- the CTAS itself: partition column LAST in the SELECT list ---
    ctas_qid = _run_sql(
        athena, out,
        f"CREATE TABLE {_dml_name(database, dest)} WITH (format = 'TEXTFILE', "
        f"external_location = 's3://{data_bucket}/{dest_prefix}', "
        "partitioned_by = ARRAY['cat']) AS "
        f"SELECT amount, cat FROM {_dml_name(database, src)}",
        database=database)
    ctas_scanned = _scanned(athena, ctas_qid)
    assert ctas_scanned == len(body), (
        f"the CTAS must have read exactly the {len(body)} source bytes this check uploaded, not "
        f"fabricated its output: DataScannedInBytes was {ctas_scanned!r}")

    # --- leg 1: one S3 partition directory per distinct key value, each holding real bytes ---
    written = _keys_under(s3, data_bucket, dest_prefix)
    by_partition = _sizes_by_partition(written, dest_prefix)
    assert None not in by_partition, (
        f"every object the CTAS wrote must sit under a `<col>=<value>` partition directory; these "
        f"did not: {by_partition.get(None)!r}")
    expected_dirs = sorted(f"cat={cat}" for cat in groups)
    assert sorted(by_partition) == expected_dirs, (
        f"a partitioned CTAS must write exactly one S3 directory per distinct key value: "
        f"expected {expected_dirs!r}, got {sorted(by_partition)!r} (keys {written!r})")
    for part, objs in by_partition.items():
        assert objs and all(size > 0 for _, size in objs), (
            f"partition directory {part!r} must hold at least one NON-EMPTY object, got {objs!r}")

    part_bytes = {part: sum(size for _, size in objs) for part, objs in by_partition.items()}
    total_bytes = sum(part_bytes.values())

    # --- leg 2: CTAS registered those partitions in the catalogue, with no MSCK REPAIR ---
    # SHOW PARTITIONS order is not deterministic, so the listing is sorted.
    show_qid = _run_sql(athena, out, f"SHOW PARTITIONS `{database}`.`{dest}`")
    listed = sorted(r[0] for r in _all_rows(athena, show_qid))
    assert listed == expected_dirs, (
        f"CTAS must register its partitions without an MSCK REPAIR: expected {expected_dirs!r} "
        f"from SHOW PARTITIONS, got {listed!r}")

    # --- leg 3: reading ONE partition of the new table returns that group's values and reads
    #     exactly that directory's bytes. The group is the smallest one, so a target that reads
    #     everything and filters afterwards cannot match the byte count. DataScannedInBytes counts
    #     the compressed object bytes, hence S3 object sizes rather than row text.
    target = min(groups, key=lambda cat: len(groups[cat]))
    one_qid = _run_sql(
        athena, out,
        f"SELECT amount FROM {_dml_name(database, dest)} WHERE cat = '{target}' ORDER BY amount",
        database=database)
    one_rows = _data_rows(athena, one_qid)
    expected_one = [[str(amt)] for amt in sorted(groups[target])]
    assert one_rows == expected_one, (
        f"WHERE cat = {target!r} must return exactly that group's amounts in bigint order: "
        f"expected {expected_one!r}, got {one_rows!r}")
    one_scanned = _scanned(athena, one_qid)
    assert one_scanned == part_bytes[f"cat={target}"], (
        f"reading partition cat={target} must scan exactly the "
        f"{part_bytes[f'cat={target}']} bytes CTAS wrote under that directory, got "
        f"DataScannedInBytes={one_scanned!r} (per-partition sizes {part_bytes!r})")

    # --- leg 4: the unpruned read sees every row and every byte, so leg 3 was a real reduction ---
    all_qid = _run_sql(
        athena, out, f"SELECT count(*) FROM {_dml_name(database, dest)}", database=database)
    all_rows_out = _data_rows(athena, all_qid)
    assert all_rows_out == [[str(len(_ROWS))]], (
        f"the CTAS table must hold all {len(_ROWS)} source rows, got {all_rows_out!r}")
    all_scanned = _scanned(athena, all_qid)
    assert all_scanned == total_bytes, (
        f"the unpruned read must scan every byte CTAS wrote ({total_bytes}), got "
        f"DataScannedInBytes={all_scanned!r}")
    assert one_scanned < all_scanned, (
        f"no pruning happened on the CTAS-written layout: one partition read {one_scanned!r} "
        f"bytes and the whole table read {all_scanned!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
