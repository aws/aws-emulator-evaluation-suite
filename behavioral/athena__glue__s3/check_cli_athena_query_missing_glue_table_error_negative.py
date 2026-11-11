"""cli-athena-query-missing-glue-table-error-negative."""
from __future__ import annotations

import json
import subprocess
import time

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-athena-query-missing-glue-table-error-negative"
GROUP = "permission-boundary"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An Athena query on a table missing from an existing Glue database ends FAILED with a
    table-not-found reason and no results, while a query on a created table in it succeeds."""
    require_tools("aws")

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    data_key = "data/rows.csv"
    s3.put_object(Bucket=bucket, Key=data_key, Body=b"id,name\n1,alice\n2,bob\n")

    database = ctx.unique_name("sim2real_missingdb_").replace("-", "_")
    _create_glue_database(ctx, database)
    output_location = f"s3://{bucket}/athena-results/"

    # --- negative: query a table that was never created in this real database ---
    missing_table = "no_such_table_xyz"
    bad_exec_id = _start_athena_query(
        ctx,
        f"SELECT * FROM {database}.{missing_table} LIMIT 10",
        database=database,
        output_location=output_location,
    )
    bad_execution = _wait_athena_query(ctx, bad_exec_id, timeout_s=120.0)
    assert bad_execution["Status"]["State"] == "FAILED", bad_execution["Status"]
    reason = bad_execution["Status"].get("StateChangeReason", "")
    # Column 15 is where the table reference starts in the fixed SQL text above.
    assert reason == (
        f"TABLE_NOT_FOUND: line 1:15: Table 'awsdatacatalog.{database}.{missing_table}' "
        "does not exist"
    ), reason

    # effect absent: results are not retrievable for a failed query execution
    athena = ctx.client("athena")
    code, message = _error_code(lambda: athena.get_query_results(QueryExecutionId=bad_exec_id))
    assert code == "InvalidRequestException", code
    assert message == "Query did not finish successfully. Final query state: FAILED", message

    # --- positive control: same database, a table that really exists ---
    real_table = "real_tbl"
    _create_glue_csv_table(
        ctx,
        database,
        real_table,
        location=f"s3://{bucket}/data/",
        columns=["id", "name"],
    )
    good_exec_id = _start_athena_query(
        ctx,
        f"SELECT id, name FROM {database}.{real_table} ORDER BY id",
        database=database,
        output_location=output_location,
    )
    good_execution = _wait_athena_query(ctx, good_exec_id, timeout_s=120.0)
    assert good_execution["Status"]["State"] == "SUCCEEDED", good_execution["Status"]
    rows = _athena_result_rows(ctx, good_exec_id)
    assert rows[1:] == [["1", "alice"], ["2", "bob"]], rows


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _error_code(fn):
    """fn()'s error code and message; a call that succeeds where a refusal is expected fails."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-missing-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            )
    s3.delete_bucket(Bucket=name)


def _create_glue_database(ctx, name):
    _run_aws(ctx, "glue", "create-database", "--database-input", json.dumps({"Name": name}))
    ctx.on_cleanup(lambda: ctx.client("glue").delete_database(Name=name))


def _create_glue_csv_table(ctx, database, table, location, columns, skip_header=True):
    table_input = {
        "Name": table,
        "TableType": "EXTERNAL_TABLE",
        "Parameters": {"classification": "csv"},
        "StorageDescriptor": {
            "Columns": [{"Name": c, "Type": "string"} for c in columns],
            "Location": location,
            "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
            "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
            "SerdeInfo": {
                "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                "Parameters": {"field.delim": ","},
            },
        },
    }
    if skip_header:
        table_input["Parameters"]["skip.header.line.count"] = "1"
    _run_aws(
        ctx,
        "glue",
        "create-table",
        "--database-name",
        database,
        "--table-input",
        json.dumps(table_input),
    )
    ctx.on_cleanup(lambda: ctx.client("glue").delete_table(DatabaseName=database, Name=table))


def _start_athena_query(ctx, query, database=None, output_location=None):
    args = ["athena", "start-query-execution", "--query-string", query]
    if database:
        args += ["--query-execution-context", json.dumps({"Database": database})]
    if output_location:
        args += ["--result-configuration", json.dumps({"OutputLocation": output_location})]
    resp = _run_aws(ctx, *args)
    return resp["QueryExecutionId"]


def _wait_athena_query(ctx, exec_id, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = _run_aws(ctx, "athena", "get-query-execution", "--query-execution-id", exec_id)
        state = resp["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return resp["QueryExecution"]
        time.sleep(interval_s)
    raise AssertionError(f"query {exec_id} did not reach terminal state within {timeout_s}s")


def _athena_result_rows(ctx, exec_id):
    resp = _run_aws(ctx, "athena", "get-query-results", "--query-execution-id", exec_id)
    rows = resp["ResultSet"]["Rows"]
    return [[c.get("VarCharValue") for c in row["Data"]] for row in rows]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
