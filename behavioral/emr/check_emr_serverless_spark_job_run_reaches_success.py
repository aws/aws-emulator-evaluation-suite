"""emr-serverless-spark-job-run-reaches-success."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "emr-serverless-spark-job-run-reaches-success"
GROUP = 'data-plane'
SERVICES = ['emr']

# The body drives the separate EMR Serverless API through ctx.client("emr-serverless"), never the
# EMR on EC2 client.

RELEASE_LABEL = "emr-6.15.0"

MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

_EMR_SERVERLESS_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "emr-serverless.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

TERMINAL_JOB_STATES = {"SUCCESS", "FAILED", "CANCELLED"}

# A PySpark entry point that writes its argv nonce through Spark's own writer, so
# the object in S3 can only exist if a real Spark driver+executor ran.
_JOB_SOURCE = '''import sys


def main():
    """Write argv[1] to argv[2] through Spark's own RDD writer."""
    from pyspark.sql import SparkSession

    nonce, out_uri = sys.argv[1], sys.argv[2]
    spark = SparkSession.builder.appName("sim2real-behav-emr-serverless").getOrCreate()
    spark.sparkContext.parallelize([nonce], 1).saveAsTextFile(out_uri)
    spark.stop()


main()
'''


def _gone(fn, *codes):
    """Run a teardown call; return quietly only on the given not-found codes, raise the rest."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in codes:
            raise


def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _make_bucket(ctx, s3):
    """Create a script/output bucket and register recursive teardown (registered
    FIRST, so LIFO cleanup drains the application and role before it)."""
    bucket = ctx.unique_name("sim2real-behav-emr-srvless-")

    def _cleanup() -> None:
        def _purge_and_delete() -> None:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                victims = [
                    {"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
                ]
                if victims:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": victims}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)

        _gone(_purge_and_delete, "NoSuchBucket")

    ctx.on_cleanup(_cleanup)
    # us-east-1 is CreateBucket's own carve-out: passing LocationConstraint there is
    # itself rejected, so this branches on the run's region, not a pinned one.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    return bucket


def _make_execution_role(ctx, iam, bucket):
    """Create the job execution role scoped to `bucket`, with teardown registered
    before the role is usable, and return its ARN."""
    role_name = ctx.unique_name("sim2real-behav-emr-srvless-role-")
    policy_name = "sim2real-behav-emr-serverless-s3"

    def _cleanup() -> None:
        _gone(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity")
        _gone(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")

    ctx.on_cleanup(_cleanup)

    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_EMR_SERVERLESS_TRUST_POLICY),
        Tags=[{"Key": k, "Value": v} for k, v in MANAGED_TAGS.items()],
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                        "Resource": f"arn:aws:s3:::{bucket}",
                    },
                ],
            }
        ),
    )
    return arn


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EMR Serverless Spark job run reaches SUCCESS, GetJobRun echoes its entry point and execution
    role with a non-zero duration, its single part file in S3 holds exactly the nonce it was given, and
    ListJobRuns reports it as SUCCESS."""
    emrs = ctx.client("emr-serverless")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = _make_bucket(ctx, s3)
    script_key = "job/write_nonce.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=_JOB_SOURCE.encode("utf-8"))
    role_arn = _make_execution_role(ctx, iam, bucket)

    nonce = ctx.unique_name("emr-srvless-nonce-")
    out_prefix = "job-output"
    out_uri = f"s3://{bucket}/{out_prefix}"

    app_name = ctx.unique_name("sim2real-behav-emr-srvless-app-")
    app_id = emrs.create_application(
        name=app_name,
        releaseLabel=RELEASE_LABEL,
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        # No initialCapacity: nothing is pre-warmed, so the application costs
        # nothing until a job run actually asks for workers.
        maximumCapacity={"cpu": "8 vCPU", "memory": "32 GB"},
        autoStartConfiguration={"enabled": True},
        autoStopConfiguration={"enabled": True, "idleTimeoutMinutes": 1},
        tags=MANAGED_TAGS,
    )["applicationId"]

    def _app_state():
        return emrs.get_application(applicationId=app_id)["application"]["state"]

    def _live_runs():
        return [
            jr["id"]
            for page in emrs.get_paginator("list_job_runs").paginate(applicationId=app_id)
            for jr in page.get("jobRuns", [])
            if jr["state"] not in TERMINAL_JOB_STATES
        ]

    def _cleanup_app() -> None:
        # StopApplication needs every job run finished, and DeleteApplication a CREATED or
        # STOPPED application: cancel live runs, wait for them, then stop and delete.
        for run_id in _live_runs():
            emrs.cancel_job_run(applicationId=app_id, jobRunId=run_id)
        _poll(_live_runs, lambda live: not live, timeout_s=300, interval_s=2,
              description=f"job runs of {app_id} reach a terminal state")
        settled = _poll(_app_state, lambda s: s not in {"CREATING", "STARTING", "STOPPING"},
                        timeout_s=300, interval_s=2, description=f"application {app_id} settles")
        if settled == "STARTED":
            emrs.stop_application(applicationId=app_id)
        _poll(
            _app_state,
            lambda s: s in {"CREATED", "STOPPED", "TERMINATED"},
            timeout_s=300,
            interval_s=2,
            description=f"application {app_id} reaches STOPPED",
        )
        _gone(lambda: emrs.delete_application(applicationId=app_id), "ResourceNotFoundException")

    ctx.on_cleanup(_cleanup_app)  # registered immediately after creation

    state = _poll(
        _app_state,
        lambda s: s in {"CREATED", "STARTED", "STOPPED", "TERMINATED"},
        timeout_s=300,
        interval_s=10,
        description=f"application {app_id} leaves CREATING",
    )
    assert state in {"CREATED", "STARTED"}, (
        f"a freshly created application must be CREATED or STARTED, got {state!r}"
    )
    if state != "STARTED":
        emrs.start_application(applicationId=app_id)
    started = _poll(
        _app_state,
        lambda s: s in {"STARTED", "STOPPED", "TERMINATED"},
        timeout_s=300,
        interval_s=10,
        description=f"application {app_id} reaches STARTED",
    )
    assert started == "STARTED", f"application must reach STARTED, got {started!r}"

    job_run_id = emrs.start_job_run(
        applicationId=app_id,
        clientToken=ctx.unique_name("tok-"),
        executionRoleArn=role_arn,
        name="sim2real-behav-emr-srvless-write-nonce",
        jobDriver={
            "sparkSubmit": {
                "entryPoint": f"s3://{bucket}/{script_key}",
                "entryPointArguments": [nonce, out_uri],
                "sparkSubmitParameters": (
                    "--conf spark.executor.cores=1 "
                    "--conf spark.executor.memory=2g "
                    "--conf spark.driver.cores=1 "
                    "--conf spark.driver.memory=2g "
                    "--conf spark.executor.instances=1"
                ),
            }
        },
        tags=MANAGED_TAGS,
    )["jobRunId"]

    def _job():
        return emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]

    final = _poll(
        lambda: _job()["state"],
        lambda s: s in TERMINAL_JOB_STATES,
        timeout_s=900,
        interval_s=20,
        description=f"job run {job_run_id} reaches a terminal state",
    )
    job = _job()
    assert final == "SUCCESS", (
        f"the Spark job run must reach SUCCESS, got {final!r} "
        f"(stateDetails: {job.get('stateDetails')!r})"
    )

    # The job run must describe the artifact it was actually given.
    driver = job.get("jobDriver", {}).get("sparkSubmit", {})
    assert driver.get("entryPoint") == f"s3://{bucket}/{script_key}", (
        f"GetJobRun must echo the submitted entryPoint, got {driver.get('entryPoint')!r}"
    )
    assert job.get("executionRole") == role_arn, (
        f"GetJobRun must echo the execution role, got {job.get('executionRole')!r}"
    )
    assert job.get("totalExecutionDurationSeconds", 0) > 0, (
        f"a SUCCESSful job run must report a non-zero "
        f"totalExecutionDurationSeconds, got {job.get('totalExecutionDurationSeconds')!r}"
    )

    # THE assertion: Spark's own writer produced these exact bytes.
    def _output_parts():
        try:
            resp = s3.list_objects_v2(Bucket=bucket, Prefix=f"{out_prefix}/part-")
        except ClientError:
            return []
        return [o["Key"] for o in resp.get("Contents", [])]

    parts = _poll(
        _output_parts,
        lambda ks: bool(ks),
        timeout_s=180,
        interval_s=10,
        description=f"Spark output committed under s3://{bucket}/{out_prefix}/",
    )
    assert len(parts) == 1, (
        f"a single-partition RDD must commit exactly one part file, got {parts!r}"
    )
    body = s3.get_object(Bucket=bucket, Key=parts[0])["Body"].read().decode("utf-8")
    assert body.strip() == nonce, (
        f"the Spark job's output must be exactly the nonce it was given; expected "
        f"{nonce!r}, got {body!r}"
    )

    # The run must be discoverable through the listing, not only by id.
    listed = {
        jr["id"]: jr["state"]
        for page in emrs.get_paginator("list_job_runs").paginate(applicationId=app_id)
        for jr in page.get("jobRuns", [])
    }
    assert listed.get(job_run_id) == "SUCCESS", (
        f"ListJobRuns must report {job_run_id} as SUCCESS, got {listed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
