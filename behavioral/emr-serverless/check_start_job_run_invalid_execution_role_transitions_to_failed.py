"""start-job-run-invalid-execution-role-transitions-to-failed."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-job-run-invalid-execution-role-transitions-to-failed"
GROUP = "job-run-lifecycle"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "plane:control")
def run(ctx) -> None:
    """StartJobRun with an execution role that emr-serverless.amazonaws.com cannot assume is accepted, and the
    job run then ends FAILED with a non-empty stateDetails."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    emrs = ctx.client("emr-serverless")

    bucket = ctx.unique_name("sim2real-emrs-badrole-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    script = (
        "from pyspark.sql import SparkSession\n"
        "spark = SparkSession.builder.appName('sim2real-emrs-badrole-check').getOrCreate()\n"
        "spark.stop()\n"
    )
    s3.put_object(Bucket=bucket, Key="job.py", Body=script.encode("utf-8"))

    role_name = ctx.unique_name("sim2real-emrs-badrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": "start-job-run-invalid-execution-role-transitions-to-failed"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        tags={"sim2real-check": "start-job-run-invalid-execution-role-transitions-to-failed"},
    )["applicationId"]
    ctx.on_cleanup(lambda: _cleanup_application(emrs, app_id))

    job_run_id = emrs.start_job_run(
        applicationId=app_id,
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        executionRoleArn=role_arn,
        jobDriver={"sparkSubmit": {"entryPoint": f"s3://{bucket}/job.py"}},
    )["jobRunId"]

    final = _poll_until(
        lambda: emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"],
        lambda jr: jr["state"] in ("SUCCESS", "FAILED", "CANCELLED"),
        timeout_s=420.0,
        interval_s=10.0,
    )
    assert final["state"] == "FAILED", f"expected FAILED, got {final['state']} (stateDetails={final.get('stateDetails')!r})"
    assert final.get("stateDetails"), "FAILED job run must report a non-empty stateDetails explaining the failure"


def _create_bucket(ctx, s3, bucket):
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _cleanup_application(emrs, app_id):
    try:
        state = emrs.get_application(applicationId=app_id)["application"]["state"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if state in ("STARTED", "STARTING"):
        try:
            emrs.stop_application(applicationId=app_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            try:
                state = emrs.get_application(applicationId=app_id)["application"]["state"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                return
            if state == "STOPPED":
                break
            time.sleep(5)
    try:
        emrs.delete_application(applicationId=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
