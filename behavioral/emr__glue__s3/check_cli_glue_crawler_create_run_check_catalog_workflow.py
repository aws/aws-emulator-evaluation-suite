"""cli-glue-crawler-create-run-check-catalog-workflow."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-glue-crawler-create-run-check-catalog-workflow"
GROUP = "cli-workflow"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """CLI creates a Glue crawler over S3 CSV data, runs it, and the Data Catalog table it
    produces is verified via the SDK (columns + storage location back to the S3 prefix)."""
    require_tools("aws")

    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    s3.put_object(Bucket=bucket, Key="data/sample.csv", Body=b"id,name\n1,alice\n2,bob\n")

    role_name, role_arn = _create_role(ctx, "glue.amazonaws.com", "sim2real-crawler-role-")
    iam = ctx.client("iam")
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )

    db_name = ctx.unique_name("sim2real_crawler_db_").replace("-", "_")
    crawler_name = ctx.unique_name("sim2real-crawler-")
    ctx.on_cleanup(lambda: _delete_database(ctx, db_name))
    ctx.on_cleanup(lambda: _delete_crawler(ctx, crawler_name))

    _run_aws(ctx, "glue", "create-database", "--database-input", json.dumps({"Name": db_name}))

    # CreateCrawler synchronously validates that Glue can assume the role, so a role created
    # moments ago can still lose the race against IAM trust-policy propagation. Retry the create
    # call itself, bounded by a deadline, rather than guessing a fixed sleep up front.
    _create_crawler_retrying_role_propagation(
        ctx,
        crawler_name=crawler_name,
        role_arn=role_arn,
        db_name=db_name,
        bucket=bucket,
        deadline_s=120.0,
    )

    # The inline S3-access policy is a second, independent eventually-consistent grant: Glue can
    # now assume the role but the crawl itself can still fail until that policy has propagated
    # too, so the run (not just the create) is retried, bounded by its own deadline.
    last_crawl = _run_crawler_until_succeeded(ctx, glue, crawler_name, deadline_s=180.0)

    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert len(tables) == 1, f"expected exactly one crawled table, got {len(tables)}"
    table = tables[0]
    columns = {c["Name"].lower() for c in table["StorageDescriptor"]["Columns"]}
    assert columns == {"id", "name"}, columns
    assert table["StorageDescriptor"]["Location"] == f"s3://{bucket}/data/"


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
        env_extra={"AWS_PAGER": ""},
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _create_crawler_retrying_role_propagation(
    ctx, *, crawler_name: str, role_arn: str, db_name: str, bucket: str, deadline_s: float = 120.0
):
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            _run_aws(
                ctx,
                "glue",
                "create-crawler",
                "--name",
                crawler_name,
                "--role",
                role_arn,
                "--database-name",
                db_name,
                "--targets",
                json.dumps({"S3Targets": [{"Path": f"s3://{bucket}/data/"}]}),
            )
            return
        except AssertionError as e:
            if "unable to assume provided role" not in str(e) or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


def _run_crawler_until_succeeded(ctx, glue, crawler_name: str, *, deadline_s: float = 180.0):
    """Start the crawler and poll it to completion, retrying the whole run while a fresh IAM
    role's permissions are still propagating. Never returns a non-SUCCEEDED result."""
    deadline = time.monotonic() + deadline_s
    last = None
    while True:
        _run_aws(ctx, "glue", "start-crawler", "--name", crawler_name)
        last = _poll_until(
            lambda: glue.get_crawler(Name=crawler_name)["Crawler"],
            lambda crawler: crawler["State"] == "READY" and "LastCrawl" in crawler,
            timeout_s=300,
            interval_s=15,
        )
        if last["LastCrawl"]["Status"] == "SUCCEEDED":
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"crawler {crawler_name} did not succeed within {deadline_s}s "
                f"of IAM-propagation retries; last={last['LastCrawl']}"
            )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-crawler-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is create_bucket's implicit default; passing a matching
        # LocationConstraint there is itself rejected, so it is omitted only for that region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [
                {"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_role(ctx, service_principal: str, prefix: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    return name, resp["Role"]["Arn"]


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol_name in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pol_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_crawler(ctx, name: str) -> None:
    try:
        ctx.client("glue").delete_crawler(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _delete_database(ctx, name: str) -> None:
    try:
        ctx.client("glue").delete_database(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
