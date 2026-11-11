"""cli-glue-crawler-missing-s3-permission-rejected."""
from __future__ import annotations

import json
import subprocess
import time

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-glue-crawler-missing-s3-permission-rejected"
GROUP = "permission-boundary"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue crawler whose role lacks s3:GetObject/s3:ListBucket on the target bucket fails and creates
    no table; after granting them, the same crawler succeeds and creates the table."""
    require_tools("aws")

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(
        Bucket=bucket,
        Key="crawler-data/rows.csv",
        Body=b"id,name\n1,alice\n2,bob\n",
    )

    role_name, role_arn = _create_glue_crawler_role_without_s3_access(ctx)
    database = ctx.unique_name("sim2real_permdb_").replace("-", "_")
    crawler_name = ctx.unique_name("sim2real-crawler-perm-")
    _create_glue_database(ctx, database)
    _create_crawler(ctx, crawler_name, role_arn, database, f"s3://{bucket}/crawler-data/")

    # --- negative: crawler role has Glue Data Catalog + CloudWatch Logs access (via
    # AWSGlueServiceRole, attached at role-creation time) but no read on the target
    # bucket, since that managed policy only reaches aws-glue-* prefixed buckets ---
    _start_crawler_with_retry(ctx, crawler_name)
    _wait_crawler_left_ready(ctx, crawler_name)
    last_crawl = _wait_crawler_ready(ctx, crawler_name, timeout_s=300.0)
    # Real AWS crawlers report LastCrawl.Status == SUCCEEDED even when every object
    # under the target path was inaccessible -- it silently skips what it cannot
    # list/read rather than failing the crawl outright. The real behavioral boundary
    # is therefore whether a table got published, not the textual status.
    assert last_crawl["Status"] in ("SUCCEEDED", "FAILED"), last_crawl

    tables = _run_aws(ctx, "glue", "get-tables", "--database-name", database)["TableList"]
    assert tables == [], f"crawler created a table despite missing S3 permission: {tables}"

    # --- positive control: grant the withheld S3 permission (the only variable
    # that changes), re-run the SAME crawler ---
    iam = ctx.client("iam")
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
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_name))

    _start_crawler_with_retry(ctx, crawler_name)
    _wait_crawler_left_ready(ctx, crawler_name)
    last_crawl2 = _wait_crawler_ready(ctx, crawler_name, timeout_s=300.0)
    assert last_crawl2["Status"] == "SUCCEEDED", last_crawl2

    tables2 = _run_aws(ctx, "glue", "get-tables", "--database-name", database)["TableList"]
    assert len(tables2) >= 1, "positive control crawler did not create a table"


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
    name = ctx.unique_name("sim2real-glue-crawler-perm-")
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


def _create_glue_crawler_role_without_s3_access(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-noperm-role-")
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

    def _cleanup():
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)

    # AWSGlueServiceRole grants Glue Data Catalog writes and CloudWatch Logs, plus S3
    # access ONLY to aws-glue-* prefixed buckets -- never to our own bucket. Attaching it
    # here isolates the missing s3:GetObject/s3:ListBucket on the target bucket as the
    # ONLY permission this role lacks, rather than leaving it with zero permissions
    # whatsoever (which would fail the crawl for reasons unrelated to S3 access).
    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))
    return role_name, role_arn


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
    """A role attached moments ago may not yet be assumable by Glue -- CreateCrawler
    validates assumability synchronously, so retry through that documented IAM
    propagation window instead of sleeping unconditionally before the first attempt."""
    targets = {"S3Targets": [{"Path": s3_path}]}
    last_stderr = ""
    for _ in range(attempts):
        proc = _run_shell(
            ctx,
            [
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
            ],
            check=False,
        )
        if proc.returncode == 0:
            ctx.on_cleanup(lambda: ctx.client("glue").delete_crawler(Name=name))
            return
        last_stderr = proc.stderr
        if "unable to assume" in proc.stderr.lower():
            time.sleep(interval_s)
            continue
        raise AssertionError(f"create-crawler failed (rc={proc.returncode}):\n  stderr: {proc.stderr[-500:]}")
    raise AssertionError(
        f"create-crawler never succeeded, role never became assumable (last stderr: {last_stderr[-500:]})"
    )


def _start_crawler_with_retry(ctx, name, attempts=6, interval_s=10.0):
    """A just-attached/put IAM policy may take a few seconds to become visible to
    Glue, so retry start-crawler through that propagation window instead of
    sleeping unconditionally before the first attempt."""
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


def _wait_crawler_left_ready(ctx, name, timeout_s=60.0, interval_s=3.0):
    """Poll until the crawler leaves READY (i.e. it actually picked up the start-crawler
    call) so a subsequent wait for READY cannot spuriously match a stale prior LastCrawl."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = _run_aws(ctx, "glue", "get-crawler", "--name", name)
        if resp["Crawler"]["State"] != "READY":
            return
        time.sleep(interval_s)
    raise AssertionError(f"crawler {name} never left READY state after start-crawler")


def _wait_crawler_ready(ctx, name, timeout_s=300.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = _run_aws(ctx, "glue", "get-crawler", "--name", name)
        crawler = resp["Crawler"]
        if crawler["State"] == "READY" and "LastCrawl" in crawler:
            return crawler["LastCrawl"]
        time.sleep(interval_s)
    raise AssertionError(f"crawler {name} did not reach READY with a LastCrawl within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
