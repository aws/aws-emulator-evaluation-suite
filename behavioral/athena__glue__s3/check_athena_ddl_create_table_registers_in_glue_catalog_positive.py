"""athena-ddl-create-table-registers-in-glue-catalog-positive."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "athena-ddl-create-table-registers-in-glue-catalog-positive"
GROUP = "metastore-binding"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An Athena CREATE EXTERNAL TABLE DDL statement registers a matching entry in the Glue Data Catalog."""
    bucket = _create_bucket(ctx)
    db = _sql_name(ctx, "sim2real_ga_ddl_db_")
    table = _sql_name(ctx, "ddl_tbl_")
    _create_glue_database(ctx, db)
    location = f"s3://{bucket}/ddl-data/"

    athena = ctx.client("athena")
    output = f"s3://{bucket}/athena-results/"
    ddl = (
        f"CREATE EXTERNAL TABLE {db}.{table} (id INT, val STRING) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' "
        f"LOCATION '{location}'"
    )
    qid, state, reason = _run_query(athena, ddl, db, output)
    assert state == "SUCCEEDED", f"DDL failed: state={state} reason={reason}"
    ctx.on_cleanup(lambda: _delete_table_if_present(ctx.client("glue"), db, table))

    glue = ctx.client("glue")
    described = glue.get_table(DatabaseName=db, Name=table)["Table"]
    assert described["Name"] == table, f"expected Glue table {table!r}, got {described['Name']!r}"
    columns = described["StorageDescriptor"]["Columns"]
    col_names = [c["Name"] for c in columns]
    assert col_names == ["id", "val"], col_names
    col_types = [c["Type"] for c in columns]
    assert col_types == ["int", "string"], (
        f"DDL declared (id INT, val STRING) but Glue catalog stored types {col_types}"
    )
    catalog_location = described["StorageDescriptor"]["Location"]
    assert catalog_location.rstrip("/") == location.rstrip("/"), (
        f"expected the DDL's LOCATION {location!r} to land in the catalog, got {catalog_location!r}"
    )

    # The delete registered above already tears the table down; make that teardown a free
    # negative — an independent read confirms it is gone, and a second delete on the same
    # (now dead) id fails the same way rather than silently no-opping.
    glue.delete_table(DatabaseName=db, Name=table)
    read_code, read_message = _err_code(lambda: glue.get_table(DatabaseName=db, Name=table))
    assert read_code == "EntityNotFoundException", (
        f"expected the deleted table to read back EntityNotFoundException, got {read_code}"
    )
    delete_code, delete_message = _err_code(lambda: glue.delete_table(DatabaseName=db, Name=table))
    assert read_message == "Entity Not Found", (
        f"the deleted table's read was refused with {read_message!r}"
    )
    assert delete_code == "EntityNotFoundException", (
        f"expected a second delete on the dead table id to fail EntityNotFoundException, got {delete_code}"
    )
    assert delete_message == f"Table {table} not found.", (
        f"the second delete on the dead table was refused with {delete_message!r}"
    )


def _sql_name(ctx: Any, prefix: str) -> str:
    return ctx.unique_name(prefix).replace("-", "_").lower()


def _err_code(fn) -> tuple[str, str]:
    """fn()'s error code and message; a call that succeeds where a refusal is expected fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_table_if_present(glue, db: str, table: str) -> None:
    """Teardown for a table the check itself deletes on its success path."""
    try:
        glue.delete_table(DatabaseName=db, Name=table)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
            raise


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ga-").lower()
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint;
    # this branches on the S3 API's own quirk, not an assumption about where the check runs.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            )
    s3.delete_bucket(Bucket=bucket)


def _create_glue_database(ctx: Any, name: str) -> str:
    glue = ctx.client("glue")
    glue.create_database(DatabaseInput={"Name": name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))
    return name


def _run_query(athena, sql: str, database: str | None, output_location: str, timeout_s: float = 90.0):
    kwargs: dict[str, Any] = {"QueryString": sql, "ResultConfiguration": {"OutputLocation": output_location}}
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    qid = athena.start_query_execution(**kwargs)["QueryExecutionId"]
    deadline = time.monotonic() + timeout_s
    state = None
    reason = None
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = resp["Status"]["State"]
        reason = resp["Status"].get("StateChangeReason")
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return qid, state, reason
        time.sleep(1.5)
    raise AssertionError(f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
