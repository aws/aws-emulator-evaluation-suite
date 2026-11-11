"""iceberg-time-travel-returns-the-snapshot-before-the-row-level-update."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "iceberg-time-travel-returns-the-snapshot-before-the-row-level-update"
GROUP = "query-execution"
SERVICES = ["athena"]

# The Iceberg CREATE TABLE takes a BARE, unquoted table name with LOCATION/TBLPROPERTIES (the
# documented form); a double-quoted name or a Trino `WITH (...)` clause is refused synchronously.
# Row-level UPDATE/DELETE need Athena engine version 3, so every statement runs in a dedicated
# workgroup pinned to it rather than the account's default workgroup.


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object, then the bucket. Athena writes `<qid>.csv`, `<qid>.csv.metadata` and
    `<qid>.txt` into the output location, and an Iceberg table leaves data plus a metadata tree
    under its LOCATION, so DeleteBucket alone would fail. No bare `except Exception`: a teardown
    that cannot finish must surface rather than leak silently."""
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
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _output_location(ctx):
    return f"s3://{_make_bucket(ctx, 'sim2real-behav-athena-results-')}/results/"


def _make_workgroup(ctx, athena, out):
    """A dedicated workgroup pinned to Athena engine version 3, tagged and torn down.

    Row-level UPDATE/DELETE and time-travel `FOR VERSION AS OF` are Trino-engine features:
    the account's default "primary" workgroup may still be pinned to an older engine version,
    in which case the syntax is refused.
    """
    wg = ctx.unique_name("sim2real-behav-athena-ice-wg-")
    athena.create_work_group(
        Name=wg,
        Configuration={
            "ResultConfiguration": {"OutputLocation": out},
            "EngineVersion": {"SelectedEngineVersion": "Athena engine version 3"},
        },
        Tags=[
            {"Key": "sim2real", "Value": CHECK},
            {"Key": "sim2real:managed", "Value": "true"},
        ],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))
    return wg


def _start_query(athena, out, query_string, database=None, workgroup=None):
    kwargs = {"QueryString": query_string, "ResultConfiguration": {"OutputLocation": out}}
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _wait_terminal(athena, qid, timeout_s=300, interval_s=3):
    """Poll GetQueryExecution to a REQUIRED terminal state with a bounded deadline; RAISES on
    timeout so a truncated poll can never record a wrong oracle. 300s per statement because an
    Iceberg commit pays metadata rewrite and Glue optimistic-lock retries on top of the scan."""
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


def _run_sql(athena, out, sql, database=None, workgroup=None):
    qid = _start_query(athena, out, sql, database=database, workgroup=workgroup)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state}, expected SUCCEEDED: {sql!r} -- "
            f"{status.get('StateChangeReason')}")
    return qid


def _data_rows(results):
    """Row 0 of a SELECT ResultSet repeats the column names, so the data rows are rows[1:].
    Hard-subscripted so a missing ResultSet raises rather than degrading to an empty list."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _dml_name(database, table):
    """DML (INSERT/UPDATE/DELETE/SELECT, including `FOR VERSION AS OF` and `$snapshots` reads)
    goes through the Trino parser, which quotes identifiers with DOUBLE QUOTES. Measured on real
    AWS: this does NOT extend to the Iceberg `CREATE TABLE ... LOCATION ... TBLPROPERTIES (...)`
    statement, which needs a bare, unquoted table name (see the note at the top of this file)
    — so this helper is deliberately not reused for CREATE TABLE."""
    return f'"{database}"."{table}"'


def _select(athena, out, sql, database, workgroup=None):
    """Run a SELECT to SUCCEEDED and return its data rows."""
    return _data_rows(
        athena.get_query_results(
            QueryExecutionId=_run_sql(athena, out, sql, database=database, workgroup=workgroup)))


def _snapshots(athena, out, database, table, workgroup=None):
    """Every row of the table's `$snapshots` metadata table as
    (committed_at, snapshot_id, parent_id_or_None), newest last.

    Nothing here is a literal: the ids and timestamps are produced by the engine's own Iceberg
    commit log, so none of them can be a literal.
    """
    sql = (
        "SELECT CAST(committed_at AS varchar) AS committed_at, CAST(snapshot_id AS varchar) AS sid, "
        f"CAST(parent_id AS varchar) AS pid FROM \"{database}\".\"{table}$snapshots\" "
        "ORDER BY committed_at")
    rows = _select(athena, out, sql, database, workgroup=workgroup)
    return [(r[0], r[1], r[2]) for r in rows]


def _single_parent_chain(snapshots):
    """True when the snapshots form ONE unbroken parent chain rooted at a parent-less snapshot.

    This is the structural invariant Iceberg guarantees and an emulator that fabricates a metadata
    table cannot satisfy without modelling lineage. Deliberately independent of HOW MANY snapshots
    a row-level UPDATE produces (copy-on-write emits one overwrite commit, merge-on-read may emit
    more), so the assertion does not encode a guess.
    """
    by_id = {sid: pid for _, sid, pid in snapshots}
    roots = [sid for sid, pid in by_id.items() if not pid]
    if len(roots) != 1 or len(by_id) != len(snapshots):
        return False
    # Walk forward from the root through the unique child of each node.
    children = {}
    for sid, pid in by_id.items():
        if pid:
            children.setdefault(pid, []).append(sid)
    seen = 1
    node = roots[0]
    while node in children:
        if len(children[node]) != 1:
            return False
        node = children[node][0]
        seen += 1
    return seen == len(by_id)


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An Iceberg table keeps its history: after a row-level UPDATE, `FOR VERSION AS OF` the first
    snapshot still returns the pre-update rows, a DELETE removes exactly one live row without
    touching that snapshot, and `$snapshots` records the commits as one unbroken parent chain."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    # Registered FIRST so it is the LAST cleanup to run — after DROP TABLE and DROP DATABASE
    # below, which are themselves Athena queries that must execute IN this workgroup.
    workgroup = _make_workgroup(ctx, athena, out)
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-ice-")

    marker = ctx.unique_name("").replace("-", "")[:12]
    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-behav-ice-").replace("-", "_")
    # Registered BEFORE the CREATEs they undo, innermost last: LIFO runs DROP TABLE, then
    # DROP DATABASE, then the buckets, and DROP is itself an Athena query so the results bucket
    # must outlive both.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE",
                                    workgroup=workgroup))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`", workgroup=workgroup)

    tname = _dml_name(database, table)
    _run_sql(
        athena, out,
        f"CREATE TABLE {table} (id int, name string) "
        f"LOCATION 's3://{data_bucket}/ice/' "
        "TBLPROPERTIES ('table_type'='ICEBERG', 'format'='parquet')",
        database=database, workgroup=workgroup)
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP TABLE IF EXISTS {tname}",
                                    database=database, workgroup=workgroup))

    # --- leg 1: the first commit. Three rows, and exactly one root snapshot.
    _run_sql(
        athena, out,
        f"INSERT INTO {tname} VALUES (1, 'one-{marker}'), (2, 'two-{marker}'), "
        f"(3, 'three-{marker}')",
        database=database, workgroup=workgroup)
    before_rows = _select(
        athena, out, f"SELECT id, name FROM {tname} ORDER BY id", database, workgroup=workgroup)
    expected_before = [["1", f"one-{marker}"], ["2", f"two-{marker}"], ["3", f"three-{marker}"]]
    assert before_rows == expected_before, (
        f"the Iceberg table must hold exactly the three inserted rows: expected "
        f"{expected_before!r}, got {before_rows!r}")

    first_snaps = _snapshots(athena, out, database, table, workgroup=workgroup)
    assert len(first_snaps) == 1, (
        f"one INSERT into a fresh Iceberg table must produce exactly one snapshot, got "
        f"{first_snaps!r}")
    root_id = first_snaps[0][1]
    assert not first_snaps[0][2], (
        f"the first snapshot has no ancestor, so its parent_id must be NULL (an absent "
        f"VarCharValue); got {first_snaps[0]!r}")
    assert root_id and root_id.strip("-").isdigit(), (
        f"snapshot_id must be a real engine-assigned numeric id, got {root_id!r}")

    # --- leg 2: a ROW-LEVEL update. Hive external tables cannot do this at all.
    _run_sql(athena, out, f"UPDATE {tname} SET name = 'updated-{marker}' WHERE id = 2",
             database=database, workgroup=workgroup)
    after_update = _select(
        athena, out, f"SELECT id, name FROM {tname} ORDER BY id", database, workgroup=workgroup)
    expected_after = [["1", f"one-{marker}"], ["2", f"updated-{marker}"],
                      ["3", f"three-{marker}"]]
    assert after_update == expected_after, (
        f"the row-level UPDATE must change exactly row id=2 and leave the others untouched: "
        f"expected {expected_after!r}, got {after_update!r}")

    # --- leg 3, the subject: the OLD snapshot is still readable, by the id the engine gave us.
    travelled = _select(
        athena, out,
        f"SELECT id, name FROM {tname} FOR VERSION AS OF {root_id} ORDER BY id",
        database, workgroup=workgroup)
    assert travelled == expected_before, (
        f"FOR VERSION AS OF {root_id} must return the table as it was before the UPDATE — the "
        f"pre-update rows {expected_before!r} — not the current {after_update!r}; got "
        f"{travelled!r}")

    # --- leg 4: a DELETE moves the live view again, and still does not disturb the old snapshot.
    _run_sql(athena, out, f"DELETE FROM {tname} WHERE id = 3", database=database,
             workgroup=workgroup)
    after_delete = _select(
        athena, out, f"SELECT id, name FROM {tname} ORDER BY id", database, workgroup=workgroup)
    assert after_delete == expected_after[:2], (
        f"the DELETE must remove exactly row id=3: expected {expected_after[:2]!r}, got "
        f"{after_delete!r}")
    travelled_again = _select(
        athena, out,
        f"SELECT id, name FROM {tname} FOR VERSION AS OF {root_id} ORDER BY id",
        database, workgroup=workgroup)
    assert travelled_again == expected_before, (
        f"the first snapshot must be unchanged by the later UPDATE and DELETE: expected "
        f"{expected_before!r}, got {travelled_again!r}")

    # --- leg 5: the commit log itself. Asserted as a derived structural rule, not as a count.
    final_snaps = _snapshots(athena, out, database, table, workgroup=workgroup)
    assert len(final_snaps) > len(first_snaps), (
        f"the UPDATE and DELETE must each have committed, so the snapshot count must have grown "
        f"beyond {len(first_snaps)}; got {final_snaps!r}")
    assert final_snaps[0][1] == root_id, (
        f"the oldest snapshot must still be the one the time-travel query named ({root_id!r}); "
        f"the log now starts at {final_snaps[0]!r}")
    assert _single_parent_chain(final_snaps), (
        f"Iceberg snapshots must form one unbroken parent chain rooted at a parent-less snapshot; "
        f"got {final_snaps!r}")
    committed_ats = [s[0] for s in final_snaps]
    assert committed_ats == sorted(committed_ats) and len(set(committed_ats)) == len(committed_ats), (
        f"the commit timestamps must be distinct and strictly increasing along the chain, got "
        f"{committed_ats!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
