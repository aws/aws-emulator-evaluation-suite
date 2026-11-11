"""emr-serverless-start-job-run-on-stopped-non-autostart-application-is-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "emr-serverless-start-job-run-on-stopped-non-autostart-application-is-rejected"
GROUP = 'errors'
SERVICES = ['emr']

# SERVICES is 'emr' but the check drives the separate emr-serverless model.

RELEASE_LABEL = "emr-6.15.0"

MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav",
                "sim2real": "emr-serverless-autostart-disabled"}

_EMR_SERVERLESS_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "emr-serverless.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}

TERMINAL_JOB_STATES = {"SUCCESS", "FAILED", "CANCELLED"}

_JOB_SOURCE = '''import sys


def main():
    from pyspark.sql import SparkSession

    nonce, out_uri = sys.argv[1], sys.argv[2]
    spark = SparkSession.builder.appName("sim2real-behav-emr-srvless-autostart").getOrCreate()
    spark.sparkContext.parallelize([nonce], 1).saveAsTextFile(out_uri)
    spark.stop()


main()
'''

_SPARK_SUBMIT_PARAMS = (
    "--conf spark.executor.cores=1 "
    "--conf spark.executor.memory=2g "
    "--conf spark.driver.cores=1 "
    "--conf spark.driver.memory=2g "
    "--conf spark.executor.instances=1"
)


def _swallow(fn):
    """Run fn(), swallowing any exception. Teardown-only — never an assertion."""
    try:
        fn()
    except Exception:  # noqa: BLE001 — best-effort teardown
        pass


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


def _error(fn):
    """Return (code, message) for the ClientError fn() raises; raise if fn() succeeds."""
    try:
        resp = fn()
    except Exception as exc:  # noqa: BLE001
        err = (getattr(exc, "response", None) or {}).get("Error", {})
        return err.get("Code", type(exc).__name__), err.get("Message", str(exc))
    raise AssertionError(
        f"the call was expected to be REJECTED but SUCCEEDED, returning {resp!r}"
    )


def _make_bucket(ctx, s3):
    """Create the script/output bucket; teardown registered FIRST so LIFO drains it last."""
    bucket = ctx.unique_name("sim2real-behav-emr-srvauto-")

    def _cleanup() -> None:
        def _purge_and_delete() -> None:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                victims = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                           for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                if victims:
                    s3.delete_objects(Bucket=bucket, Delete={"Objects": victims})
            s3.delete_bucket(Bucket=bucket)

        _swallow(_purge_and_delete)

    ctx.on_cleanup(_cleanup)
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    return bucket


def _make_execution_role(ctx, iam, bucket):
    """Create the job execution role scoped to `bucket`, teardown registered before first use."""
    role_name = ctx.unique_name("sim2real-behav-emr-srvauto-role-")
    policy_name = "sim2real-behav-emr-serverless-s3"

    def _cleanup() -> None:
        _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
        _swallow(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_EMR_SERVERLESS_TRUST_POLICY),
        Tags=[{"Key": k, "Value": v} for k, v in MANAGED_TAGS.items()],
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow",
                 "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                 "Resource": f"arn:aws:s3:::{bucket}/*"},
                {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                 "Resource": f"arn:aws:s3:::{bucket}"},
            ],
        }),
    )
    return arn


@tags("axis:rejection", "concern:negative-classes", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """StartJobRun on a non-STARTED application with autoStart disabled fails with
    ValidationException, records no run, and does not start the app; the same call succeeds
    once the application is started.
    """
    emrs = ctx.client("emr-serverless")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = _make_bucket(ctx, s3)
    script_key = "job/write_nonce.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=_JOB_SOURCE.encode("utf-8"))
    role_arn = _make_execution_role(ctx, iam, bucket)

    nonce = ctx.unique_name("emr-srvauto-nonce-")
    out_prefix = "job-output"
    out_uri = f"s3://{bucket}/{out_prefix}"

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-behav-emr-srvauto-app-"),
        releaseLabel=RELEASE_LABEL, type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        maximumCapacity={"cpu": "8 vCPU", "memory": "32 GB"},
        # With the AWS default (enabled) StartJobRun would start the application itself and
        # there would be no refusal to observe.
        autoStartConfiguration={"enabled": False},
        autoStopConfiguration={"enabled": True, "idleTimeoutMinutes": 1},
        tags=MANAGED_TAGS,
    )["applicationId"]

    def _app():
        return emrs.get_application(applicationId=app_id)["application"]

    def _cleanup_app() -> None:
        def _cancel_running() -> None:
            for page in emrs.get_paginator("list_job_runs").paginate(applicationId=app_id):
                for jr in page.get("jobRuns", []):
                    if jr["state"] not in TERMINAL_JOB_STATES:
                        _swallow(lambda jr=jr: emrs.cancel_job_run(
                            applicationId=app_id, jobRunId=jr["id"]))

        _swallow(_cancel_running)
        _swallow(lambda: emrs.stop_application(applicationId=app_id))
        _swallow(lambda: _poll(lambda: _app()["state"], lambda s: s in {"STOPPED", "TERMINATED"},
                               timeout_s=300, interval_s=10,
                               description=f"application {app_id} reaches STOPPED"))
        _swallow(lambda: emrs.delete_application(applicationId=app_id))

    ctx.on_cleanup(_cleanup_app)  # registered immediately after creation

    # With autoStart disabled EMR Serverless leaves a fresh application in CREATED.
    state_before = _poll(lambda: _app()["state"], lambda s: s != "CREATING",
                         timeout_s=300, interval_s=10,
                         description=f"application {app_id} leaves CREATING")
    assert state_before == "CREATED", (
        f"an application created with autoStart disabled must settle in CREATED and stay there, "
        f"got {state_before!r}"
    )
    assert _app().get("autoStartConfiguration", {}).get("enabled") is False, (
        f"GetApplication must report autoStart as disabled, got "
        f"{_app().get('autoStartConfiguration')!r}"
    )

    # The request body used for BOTH legs — identical down to the clientToken, so the only thing
    # that differs between the refusal and the success is the application's state.
    request = dict(
        applicationId=app_id,
        clientToken=ctx.unique_name("tok-"),
        executionRoleArn=role_arn,
        name="sim2real-behav-emr-srvauto-write-nonce",
        jobDriver={"sparkSubmit": {
            "entryPoint": f"s3://{bucket}/{script_key}",
            "entryPointArguments": [nonce, out_uri],
            "sparkSubmitParameters": _SPARK_SUBMIT_PARAMS}},
        tags=MANAGED_TAGS,
    )

    code, message = _error(lambda: emrs.start_job_run(**request))
    assert code == "ValidationException", (
        f"StartJobRun on a non-autostart application that is not STARTED must be refused with "
        f"ValidationException, got {code!r} (message {message!r})"
    )
    assert message == (
        "Job run cannot be started as Application is not in STARTED state and auto-start is disabled"
    ), message

    runs = [(jr["id"], jr["state"])
            for page in emrs.get_paginator("list_job_runs").paginate(applicationId=app_id)
            for jr in page.get("jobRuns", [])]
    assert runs == [], (
        f"a refused StartJobRun must record no job run at all; ListJobRuns returned {runs!r}"
    )
    state_after = _app()["state"]
    assert state_after == state_before, (
        f"a refused StartJobRun must not implicitly start the application — that is exactly what "
        f"autoStart disabled means; state went {state_before!r} -> {state_after!r}"
    )

    emrs.start_application(applicationId=app_id)
    started = _poll(lambda: _app()["state"], lambda s: s != "STARTING", timeout_s=300,
                    interval_s=10, description=f"application {app_id} leaves STARTING")
    assert started == "STARTED", (
        f"StartApplication must bring the application to STARTED, got {started!r}"
    )

    job_run_id = emrs.start_job_run(**request)["jobRunId"]

    def _job():
        return emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]

    final = _poll(lambda: _job()["state"], lambda s: s in TERMINAL_JOB_STATES,
                  timeout_s=900, interval_s=20,
                  description=f"control job run {job_run_id} reaches a terminal state")
    job = _job()
    assert final == "SUCCESS", (
        f"the byte-identical StartJobRun must succeed once the application is STARTED — "
        f"otherwise the refusal above proves nothing about the state gate — got {final!r} "
        f"(stateDetails: {job.get('stateDetails')!r})"
    )

    parts = _poll(
        lambda: sorted(o["Key"]
                       for page in s3.get_paginator("list_objects_v2").paginate(
                           Bucket=bucket, Prefix=f"{out_prefix}/part-")
                       for o in page.get("Contents", [])),
        lambda ks: bool(ks), timeout_s=180, interval_s=10,
        description=f"Spark output committed under s3://{bucket}/{out_prefix}/")
    assert len(parts) == 1, (
        f"a single-partition RDD must commit exactly one part file, got {parts!r}"
    )
    body = s3.get_object(Bucket=bucket, Key=parts[0])["Body"].read().decode("utf-8")
    assert body.strip() == nonce, (
        f"the control run's Spark writer must produce exactly the nonce it was given; expected "
        f"{nonce!r}, got {body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
