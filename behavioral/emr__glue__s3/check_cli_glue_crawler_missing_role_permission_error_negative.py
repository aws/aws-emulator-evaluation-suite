"""cli-glue-crawler-missing-role-permission-error-negative."""
from __future__ import annotations

import json
import re
import subprocess
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-glue-crawler-missing-role-permission-error-negative"
GROUP = "permission-boundary"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue crawler whose role has Glue permissions but no S3 access to the target bucket catalogues no
    table, while an otherwise identical crawler whose role can read the bucket succeeds and creates one."""
    require_tools("aws")

    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    s3.put_object(Bucket=bucket, Key="data/sample.csv", Body=b"id,name\n1,alice\n2,bob\n")

    db_name = ctx.unique_name("sim2real_permbound_db_").replace("-", "_")
    ctx.on_cleanup(lambda: _delete_database(ctx, db_name))
    _run_aws(ctx, "glue", "create-database", "--database-input", json.dumps({"Name": db_name}))

    # --- broken role: Glue service permissions only, NO access to this bucket ---
    broken_role, broken_arn = _create_role(ctx, "glue.amazonaws.com", "sim2real-noperm-role-")
    ctx.client("iam").attach_role_policy(
        RoleName=broken_role,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )

    broken_crawler = ctx.unique_name("sim2real-noperm-crawler-")
    ctx.on_cleanup(lambda: _delete_crawler(ctx, broken_crawler))
    # CreateCrawler synchronously verifies Glue can assume the role, so it rejects with
    # InvalidInputException ("Service is unable to assume provided role") for a few seconds
    # after the trust policy is attached, until IAM propagation catches up. Retry the call
    # itself (bounded, with a deadline) instead of sleeping blind.
    _run_aws_with_role_retry(
        ctx,
        "glue",
        "create-crawler",
        "--name",
        broken_crawler,
        "--role",
        broken_arn,
        "--database-name",
        db_name,
        "--targets",
        json.dumps({"S3Targets": [{"Path": f"s3://{bucket}/data/"}]}),
        "--tags",
        json.dumps({"sim2real-check": CHECK}),
    )
    _run_aws(ctx, "glue", "start-crawler", "--name", broken_crawler)

    broken_result = _poll_until(
        lambda: glue.get_crawler(Name=broken_crawler)["Crawler"],
        lambda crawler: crawler["State"] == "READY" and "LastCrawl" in crawler,
        timeout_s=600,
        interval_s=15,
    )
    # AWSGlueServiceRole alone grants s3:ListBucket (Resource "*") but NOT s3:GetObject outside
    # "aws-glue-*" paths, so the crawl can list the prefix but cannot read object content to
    # infer a schema. Real Glue often reports the crawl itself as SUCCEEDED (no hard failure)
    # while still cataloging ZERO tables — the object-content access denial is swallowed as a
    # per-file skip rather than a crawl-level FAILED status. The behavioral effect we assert on
    # is therefore "no table got created", not a specific LastCrawl.Status literal.
    assert broken_result["LastCrawl"]["Status"] in ("SUCCEEDED", "FAILED"), broken_result["LastCrawl"]
    assert glue.get_tables(DatabaseName=db_name)["TableList"] == [], (
        "no table should be cataloged when the crawler role lacks S3 object-read access"
    )

    # --- positive control: identical setup, role also has S3 access ---
    good_role, good_arn = _create_role(ctx, "glue.amazonaws.com", "sim2real-goodperm-role-")
    iam = ctx.client("iam")
    iam.attach_role_policy(
        RoleName=good_role,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    iam.put_role_policy(
        RoleName=good_role,
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

    good_crawler = ctx.unique_name("sim2real-goodperm-crawler-")
    ctx.on_cleanup(lambda: _delete_crawler(ctx, good_crawler))
    _run_aws_with_role_retry(
        ctx,
        "glue",
        "create-crawler",
        "--name",
        good_crawler,
        "--role",
        good_arn,
        "--database-name",
        db_name,
        "--targets",
        json.dumps({"S3Targets": [{"Path": f"s3://{bucket}/data/"}]}),
        "--tags",
        json.dumps({"sim2real-check": CHECK}),
    )
    _run_aws(ctx, "glue", "start-crawler", "--name", good_crawler)

    good_result = _poll_until(
        lambda: glue.get_crawler(Name=good_crawler)["Crawler"],
        lambda crawler: crawler["State"] == "READY" and "LastCrawl" in crawler,
        timeout_s=600,
        interval_s=15,
    )
    assert good_result["LastCrawl"]["Status"] == "SUCCEEDED", good_result["LastCrawl"]
    assert len(glue.get_tables(DatabaseName=db_name)["TableList"]) >= 1, (
        "control crawler with proper S3 access should have cataloged a table"
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


_ROLE_PROPAGATION_RETRYABLE_CODES = (
    "AccessDeniedException",
    "InvalidInputException",
    "EntityNotFoundException",
)


def _cli_error_code(message: str) -> str | None:
    match = re.search(r"An error occurred \(([A-Za-z]+)\)", message)
    return match.group(1) if match else None


def _run_aws_with_role_retry(ctx, *args: str, timeout_s: float = 90.0, interval_s: float = 10.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _run_aws(ctx, *args)
        except AssertionError as err:
            code = _cli_error_code(str(err))
            if code not in _ROLE_PROPAGATION_RETRYABLE_CODES or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-permbound-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
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
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
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
