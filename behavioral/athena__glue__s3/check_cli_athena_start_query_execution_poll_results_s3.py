"""cli-athena-start-query-execution-poll-results-s3."""
from __future__ import annotations

import csv
import io
import json
import subprocess
import time
from urllib.parse import urlparse

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-athena-start-query-execution-poll-results-s3"
GROUP = "cli-workflow"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CLI script starts an Athena query, polls get-query-execution to a terminal state,
    then downloads the result CSV directly from S3 via get-object and confirms its contents
    match what get-query-results reports through the Athena API."""

    require_tools("aws")

    bucket = _create_bucket(ctx)
    output_location = f"s3://{bucket}/athena-results/"

    exec_id = _start_athena_query(
        ctx,
        "SELECT 1 AS num, 'hello-world' AS txt",
        output_location=output_location,
    )
    execution = _wait_athena_query(ctx, exec_id, timeout_s=180.0)
    assert execution["Status"]["State"] == "SUCCEEDED", execution["Status"]

    result_uri = execution["ResultConfiguration"]["OutputLocation"]
    result_bucket, result_key = _parse_s3_uri(result_uri)

    s3 = ctx.client("s3")
    body = s3.get_object(Bucket=result_bucket, Key=result_key)["Body"].read().decode("utf-8")
    csv_rows = list(csv.reader(io.StringIO(body)))
    assert csv_rows[0] == ["num", "txt"], csv_rows
    assert csv_rows[1] == ["1", "hello-world"], csv_rows

    api_rows = _athena_result_rows(ctx, exec_id)
    assert api_rows[0] == ["num", "txt"], f"expected header ['num', 'txt'], got {api_rows[0]!r}"
    assert api_rows[1] == ["1", "hello-world"], (
        f"expected data row ['1', 'hello-world'], got {api_rows[1]!r}"
    )


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
    name = ctx.unique_name("sim2real-athena-s3-")
    # CreateBucketConfiguration is rejected for the us-east-1 region specifically; every
    # other region requires it. This branches on ctx.region's value, it does not pin one.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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


def _parse_s3_uri(uri):
    parsed = urlparse(uri)
    return parsed.netloc, parsed.path.lstrip("/")


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
