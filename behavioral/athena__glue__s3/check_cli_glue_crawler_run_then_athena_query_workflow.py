"""cli-glue-crawler-run-then-athena-query-workflow."""
from __future__ import annotations

import json
import subprocess
import time

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-glue-crawler-run-then-athena-query-workflow"
GROUP = "cli-workflow"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CLI script runs a Glue crawler to READY with a SUCCEEDED last crawl, then an Athena CLI query on
    the table it cataloged returns the rows of the S3 object, so the schema was really inferred."""

    require_tools("aws")

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(
        Bucket=bucket,
        Key="crawler-data/rows.csv",
        Body=b"id,name\n1,alice\n2,bob\n3,carol\n",
    )

    role_arn = _create_glue_crawler_role(ctx, bucket)
    database = ctx.unique_name("sim2real_crawldb_").replace("-", "_")
    crawler_name = ctx.unique_name("sim2real-crawler-")
    _create_glue_database(ctx, database)
    _create_crawler(ctx, crawler_name, role_arn, database, f"s3://{bucket}/crawler-data/")

    _start_crawler_with_retry(ctx, crawler_name)
    last_crawl = _wait_crawler_ready(ctx, crawler_name, timeout_s=480.0)
    assert last_crawl["Status"] == "SUCCEEDED", last_crawl

    tables = _run_aws(ctx, "glue", "get-tables", "--database-name", database)["TableList"]
    assert len(tables) >= 1, "crawler did not create any table"
    table_name = tables[0]["Name"]

    output_location = f"s3://{bucket}/athena-results/"
    exec_id = _start_athena_query(
        ctx,
        f"SELECT name FROM {database}.{table_name} WHERE id = 2",
        database=database,
        output_location=output_location,
    )
    execution = _wait_athena_query(ctx, exec_id, timeout_s=180.0)
    assert execution["Status"]["State"] == "SUCCEEDED", execution["Status"]

    rows = _athena_result_rows(ctx, exec_id)
    data_rows = rows[1:]
    assert data_rows == [["bob"]], rows


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
    name = ctx.unique_name("sim2real-glue-crawler-")
    if ctx.region == "us-east-1":
        # us-east-1 rejects an explicit LocationConstraint on CreateBucket.
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


def _create_glue_crawler_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-crawler-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    inline_name = "s3-data-access"
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=inline_name, PolicyDocument=json.dumps(inline_policy))

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName=inline_name)
        iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


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


def _create_crawler(ctx, name, role_arn, database, s3_path, attempts=6, interval_s=10.0):
    """Glue validates the role's assumability synchronously inside CreateCrawler, and a
    freshly created role can take a few seconds to become assumable; retry through that
    documented eventual-consistency window instead of sleeping blind before the call."""
    targets = {"S3Targets": [{"Path": s3_path}]}
    args = [
        "aws",
        "--output",
        "json",
        "glue",
        "create-crawler",
        "--name",
        name,
        "--role",
        role_arn,
        "--database-name",
        database,
        "--targets",
        json.dumps(targets),
        "--tags",
        json.dumps({"sim2real": CHECK}),
    ]
    last_stderr = ""
    for attempt in range(attempts):
        proc = _run_shell(ctx, args, check=False)
        if proc.returncode == 0:
            ctx.on_cleanup(lambda: ctx.client("glue").delete_crawler(Name=name))
            return
        last_stderr = proc.stderr
        if "unable to assume" not in last_stderr.lower() or attempt == attempts - 1:
            raise AssertionError(
                f"create-crawler failed (rc={proc.returncode}):\n  stderr: {last_stderr[-500:]}"
            )
        time.sleep(interval_s)


def _start_crawler_with_retry(ctx, name, attempts=6, interval_s=10.0):
    last_stderr = ""
    for _ in range(attempts):
        proc = _run_shell(
            ctx,
            ["aws", "glue", "start-crawler", "--name", name],
            check=False,
        )
        if proc.returncode == 0:
            return
        last_stderr = proc.stderr
        time.sleep(interval_s)
    raise AssertionError(f"start-crawler never succeeded (last stderr: {last_stderr[-500:]})")


def _wait_crawler_ready(ctx, name, timeout_s=480.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = _run_aws(ctx, "glue", "get-crawler", "--name", name)
        crawler = resp["Crawler"]
        if crawler["State"] == "READY" and "LastCrawl" in crawler:
            return crawler["LastCrawl"]
        time.sleep(interval_s)
    raise AssertionError(f"crawler {name} did not reach READY with a LastCrawl within {timeout_s}s")


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
