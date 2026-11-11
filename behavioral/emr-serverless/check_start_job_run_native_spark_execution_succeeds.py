"""start-job-run-native-spark-execution-succeeds."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-job-run-native-spark-execution-succeeds"
GROUP = "native-protocol"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SparkSubmit job run reads its driver script from S3, reaches SUCCESS and writes non-empty output
    objects to S3."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    emrs = ctx.client("emr-serverless")

    bucket = ctx.unique_name("sim2real-emrs-nat-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    script = (
        "import sys\n"
        "from pyspark.sql import SparkSession\n"
        "spark = SparkSession.builder.appName('sim2real-emrs-native-check').getOrCreate()\n"
        "spark.createDataFrame([(1, 'sim2real-ok')], ['id', 'marker']).write.mode('overwrite').json(sys.argv[1])\n"
        "spark.stop()\n"
    )
    s3.put_object(Bucket=bucket, Key="job.py", Body=script.encode("utf-8"))

    role_arn = _create_execution_role(ctx, iam, bucket)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        tags={"sim2real": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: _cleanup_application(emrs, app_id))

    output_prefix = f"s3://{bucket}/output/"
    job_run_id = _start_job_run_with_retry(
        emrs,
        app_id,
        role_arn,
        {
            "sparkSubmit": {
                "entryPoint": f"s3://{bucket}/job.py",
                "entryPointArguments": [output_prefix],
                "sparkSubmitParameters": (
                    "--conf spark.executor.cores=1 --conf spark.executor.memory=2g "
                    "--conf spark.driver.cores=1 --conf spark.driver.memory=2g"
                ),
            }
        },
        ctx,
    )

    final_state = _poll_until(
        lambda: emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"],
        lambda jr: jr["state"] in ("SUCCESS", "FAILED", "CANCELLED"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert final_state["state"] == "SUCCESS", final_state.get("stateDetails")

    objects = s3.list_objects_v2(Bucket=bucket, Prefix="output/").get("Contents", [])
    assert objects, "Spark job reported SUCCESS but wrote no output objects to S3"
    assert any(o["Size"] > 0 for o in objects), (
        f"all objects under output/ are zero-length, so Spark wrote no real data: {objects}"
    )


def _create_bucket(ctx, s3, bucket):
    kwargs = {"Bucket": bucket}
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for; not a region pin.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _create_execution_role(ctx, iam, bucket):
    role_name = ctx.unique_name("sim2real-emrs-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "emr-serverless.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-s3-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-s3-access"))
    return role_arn


def _start_job_run_with_retry(emrs, app_id, role_arn, job_driver, ctx):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = emrs.start_job_run(
                applicationId=app_id,
                clientToken=ctx.unique_name("sim2real-emrs-tok-"),
                executionRoleArn=role_arn,
                jobDriver=job_driver,
            )
            return resp["jobRunId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"StartJobRun never succeeded after IAM propagation wait: {last_exc}")


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
