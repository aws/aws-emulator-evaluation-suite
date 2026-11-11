"""cli-glue-create-table-athena-query-s3-roundtrip."""
from __future__ import annotations

import json
import subprocess
import time

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-glue-create-table-athena-query-s3-roundtrip"
GROUP = "cli-workflow"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws glue create-table` followed by `aws athena start-query-execution` returns rows
    that match the bytes actually uploaded to S3 -- proving the Glue Data Catalog table is
    bound to the real S3 object, not a stub schema that Athena queries against a fake engine."""

    require_tools("aws")

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    data_key = "data/rows.csv"
    csv_body = "id,name\n1,alice\n2,bob\n3,carol\n"
    s3.put_object(Bucket=bucket, Key=data_key, Body=csv_body.encode("utf-8"))

    database = ctx.unique_name("sim2real_gluedb_").replace("-", "_")
    table = "roundtrip_tbl"
    _create_glue_database(ctx, database)
    _create_glue_csv_table(
        ctx,
        database,
        table,
        location=f"s3://{bucket}/data/",
        columns=["id", "name"],
    )

    output_location = f"s3://{bucket}/athena-results/"
    exec_id = _start_athena_query(
        ctx,
        f"SELECT id, name FROM {database}.{table} ORDER BY id",
        database=database,
        output_location=output_location,
    )
    execution = _wait_athena_query(ctx, exec_id, timeout_s=180.0)
    assert execution["Status"]["State"] == "SUCCEEDED", execution["Status"]

    rows = _athena_result_rows(ctx, exec_id)
    header, data_rows = rows[0], rows[1:]
    assert header == ["id", "name"], f"unexpected header: {header}"
    expected_rows = [["1", "alice"], ["2", "bob"], ["3", "carol"]]
    assert data_rows == expected_rows, f"expected {expected_rows}, got {data_rows}"


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


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-glue-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
    _run_aws(
        ctx,
        "glue",
        "create-database",
        "--database-input",
        json.dumps({"Name": name}),
        "--tags",
        json.dumps({"sim2real": CHECK}),
    )
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
