"""cli-glue-job-create-start-monitor-s3-output-workflow."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-glue-job-create-start-monitor-s3-output-workflow"
GROUP = "cli-workflow"
SERVICES = ["emr", "glue", "s3"]

_JOB_SCRIPT = """
import sys
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext

args = getResolvedOptions(sys.argv, ["JOB_NAME", "OUTPUT_PATH"])
sc = SparkContext()
glueContext = GlueContext(sc)
df = glueContext.spark_session.createDataFrame([(1, "sim2real"), (2, "behavioral")], ["id", "name"])
df.write.mode("overwrite").json(args["OUTPUT_PATH"])
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """CLI creates and starts a Glue ETL job whose script writes JSON rows to S3; the SDK is
    used to poll the job run to SUCCEEDED and confirm the expected output objects landed."""
    require_tools("aws")

    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    s3.put_object(Bucket=bucket, Key="scripts/job.py", Body=_JOB_SCRIPT.encode())

    role_name, role_arn = _create_role(ctx, "glue.amazonaws.com", "sim2real-glue-job-role-")
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
                        "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )
    job_name = ctx.unique_name("sim2real-glue-job-")
    output_uri = f"s3://{bucket}/output/"
    ctx.on_cleanup(lambda: _delete_job(ctx, job_name))

    _run_aws(
        ctx,
        "glue",
        "create-job",
        "--name",
        job_name,
        "--role",
        role_arn,
        "--glue-version",
        "3.0",
        "--number-of-workers",
        "2",
        "--worker-type",
        "G.1X",
        "--command",
        json.dumps(
            {
                "Name": "glueetl",
                "ScriptLocation": f"s3://{bucket}/scripts/job.py",
                "PythonVersion": "3",
            }
        ),
        "--default-arguments",
        json.dumps({"--OUTPUT_PATH": output_uri}),
        "--tags",
        f"sim2real={CHECK}",
        timeout_s=60,
    )
    job_run = _run_job_with_retry(ctx, glue, job_name, output_uri)
    assert job_run["JobRunState"] == "SUCCEEDED", job_run

    listing = s3.list_objects_v2(Bucket=bucket, Prefix="output/")
    keys = [o["Key"] for o in listing.get("Contents", [])]
    assert any(k.endswith(".json") or "part-" in k for k in keys), (
        f"expected job output objects under output/, got {keys}"
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


_ROLE_PROPAGATION_ERROR = "should be given assume role permissions"


def _run_job_with_retry(ctx, glue, job_name: str, output_uri: str, *, timeout_s=180.0, interval_s=15.0) -> dict:
    """Start the job run and poll it to a terminal state, tolerating the brief window where
    Glue's control plane has not yet observed the freshly-created execution role's trust
    policy and fails the run immediately with an assume-role error. Restarting a fresh run is
    the only lever available here: the failure is only visible after start-job-run has already
    returned successfully."""
    deadline = time.monotonic() + timeout_s
    while True:
        run_id = _run_aws(
            ctx,
            "glue",
            "start-job-run",
            "--job-name",
            job_name,
            "--arguments",
            json.dumps({"--OUTPUT_PATH": output_uri}),
        )["JobRunId"]
        job_run = _poll_until(
            lambda: glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"],
            lambda jr: jr["JobRunState"] in ("SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"),
            timeout_s=900,
            interval_s=20,
        )
        propagation_race = (
            job_run["JobRunState"] == "FAILED"
            and _ROLE_PROPAGATION_ERROR in job_run.get("ErrorMessage", "")
        )
        if not propagation_race or time.monotonic() >= deadline:
            return job_run
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
    name = ctx.unique_name("sim2real-glue-job-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _delete_job(ctx, name: str) -> None:
    ctx.client("glue").delete_job(JobName=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
