"""emr-serverless-failing-script-reports-failed-and-writes-no-output."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "emr-serverless-failing-script-reports-failed-and-writes-no-output"
GROUP = 'data-plane'
SERVICES = ['emr']

# ===== helpers =====
#
# NOTE ON SERVICE TOKEN: this file lives in behavioral/emr/ and declares SERVICES = ['emr'] per
# the directory convention, but drives the SEPARATE emr-serverless Smithy model
# (com.amazonaws.emrserverless#AwsToledoWebService) via ctx.client('emr-serverless').

RELEASE_LABEL = "emr-6.15.0"

MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav",
                "sim2real": "emr-serverless-failing-script"}

_EMR_SERVERLESS_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "emr-serverless.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}

TERMINAL_JOB_STATES = {"SUCCESS", "FAILED", "CANCELLED"}

# The failing entry point. It builds a real SparkSession first — so the driver genuinely starts,
# work genuinely happens, and the run's totalExecutionDurationSeconds is non-zero — and only THEN
# raises. That ordering is what separates "a Spark driver ran and died" from "the submission was
# rejected", and it is the distinction the assertions below rest on.
_FAIL_SOURCE = '''import sys


def main():
    from pyspark.sql import SparkSession

    out_uri = sys.argv[1]
    spark = SparkSession.builder.appName("sim2real-behav-emr-srvless-fail").getOrCreate()
    # Real distributed work, so the driver is provably up before the failure.
    n = spark.sparkContext.parallelize(range(1, 101), 2).sum()
    print("sim2real-driver-alive sum=%d out=%s" % (n, out_uri))
    raise RuntimeError("sim2real-deliberate-failure")


main()
'''

# The positive control's entry point: writes its argv nonce through Spark's own RDD writer, so the
# object in S3 can only exist if a real Spark driver + executor ran to completion.
_PASS_SOURCE = '''import sys


def main():
    from pyspark.sql import SparkSession

    nonce, out_uri = sys.argv[1], sys.argv[2]
    spark = SparkSession.builder.appName("sim2real-behav-emr-srvless-pass").getOrCreate()
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


def _make_bucket(ctx, s3):
    """Create the script/output bucket; teardown registered FIRST so LIFO drains it last."""
    bucket = ctx.unique_name("sim2real-behav-emr-srvfail-")

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
    role_name = ctx.unique_name("sim2real-behav-emr-srvfail-role-")
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


def _head_status(s3, bucket, key):
    """HeadObject's error code, or the sentinel 'EXISTS' when the object is really there.

    Never returns a falsy value: an object that exists where the check expects a 404 is the
    strongest possible signal, and a falsy sentinel would flatten it into a code mismatch.
    """
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "")
    return "EXISTS"


def _list_keys(s3, bucket, prefix):
    """Every key under `prefix`, paginated — the bucket prefix may hold more keys than one page."""
    return sorted(o["Key"]
                  for page in s3.get_paginator("list_objects_v2").paginate(
                      Bucket=bucket, Prefix=prefix)
                  for o in page.get("Contents", []))


# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A Spark driver that exits non-zero leaves its EMR Serverless job run FAILED with a non-zero
    execution duration and no S3 output, while a passing job on the same application reaches
    SUCCESS as the control that makes the absence meaningful."""
    emrs = ctx.client("emr-serverless")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = _make_bucket(ctx, s3)
    fail_key, pass_key = "job/fail.py", "job/pass.py"
    s3.put_object(Bucket=bucket, Key=fail_key, Body=_FAIL_SOURCE.encode("utf-8"))
    s3.put_object(Bucket=bucket, Key=pass_key, Body=_PASS_SOURCE.encode("utf-8"))
    role_arn = _make_execution_role(ctx, iam, bucket)

    fail_prefix, pass_prefix = "fail-output", "pass-output"
    nonce = ctx.unique_name("emr-srvless-nonce-")

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-behav-emr-srvfail-app-"),
        releaseLabel=RELEASE_LABEL, type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        maximumCapacity={"cpu": "8 vCPU", "memory": "32 GB"},
        autoStartConfiguration={"enabled": True},
        autoStopConfiguration={"enabled": True, "idleTimeoutMinutes": 1},
        tags=MANAGED_TAGS,
    )["applicationId"]

    def _app_state():
        return emrs.get_application(applicationId=app_id)["application"]["state"]

    def _cleanup_app() -> None:
        def _cancel_running() -> None:
            for page in emrs.get_paginator("list_job_runs").paginate(applicationId=app_id):
                for jr in page.get("jobRuns", []):
                    if jr["state"] not in TERMINAL_JOB_STATES:
                        _swallow(lambda jr=jr: emrs.cancel_job_run(
                            applicationId=app_id, jobRunId=jr["id"]))

        _swallow(_cancel_running)
        _swallow(lambda: emrs.stop_application(applicationId=app_id))
        _swallow(lambda: _poll(_app_state, lambda s: s in {"STOPPED", "TERMINATED"},
                               timeout_s=300, interval_s=10,
                               description=f"application {app_id} reaches STOPPED"))
        _swallow(lambda: emrs.delete_application(applicationId=app_id))

    ctx.on_cleanup(_cleanup_app)  # registered immediately after creation

    leftc = _poll(_app_state, lambda s: s != "CREATING", timeout_s=300, interval_s=10,
                  description=f"application {app_id} leaves CREATING")
    if leftc != "STARTED":
        emrs.start_application(applicationId=app_id)
    started = _poll(_app_state, lambda s: s != "STARTING", timeout_s=300, interval_s=10,
                    description=f"application {app_id} leaves STARTING")
    assert started == "STARTED", (
        f"the application must reach STARTED before any job run; got {started!r}"
    )

    def _job(job_run_id):
        return emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]

    def _submit(key, args, name):
        return emrs.start_job_run(
            applicationId=app_id, clientToken=ctx.unique_name("tok-"),
            executionRoleArn=role_arn, name=name,
            jobDriver={"sparkSubmit": {
                "entryPoint": f"s3://{bucket}/{key}",
                "entryPointArguments": args,
                "sparkSubmitParameters": _SPARK_SUBMIT_PARAMS}},
            tags=MANAGED_TAGS,
        )["jobRunId"]

    # ---- the failing run ----------------------------------------------------------------
    fail_uri = f"s3://{bucket}/{fail_prefix}"
    fail_id = _submit(fail_key, [fail_uri], "sim2real-behav-emr-srvless-failing")
    fail_state = _poll(lambda: _job(fail_id)["state"], lambda s: s in TERMINAL_JOB_STATES,
                       timeout_s=900, interval_s=20,
                       description=f"failing job run {fail_id} reaches a terminal state")
    fail_job = _job(fail_id)
    assert fail_state == "FAILED", (
        f"a Spark driver that raises must leave the job run FAILED, got {fail_state!r} "
        f"(stateDetails: {fail_job.get('stateDetails')!r})"
    )
    details = (fail_job.get("stateDetails") or "").strip()
    assert details, (
        f"a FAILED job run must carry non-empty stateDetails naming the failure; got "
        f"{fail_job.get('stateDetails')!r} on the whole run {fail_job!r}"
    )
    # The driver really ran before it died. A backend that reports FAILED for a submission it
    # never executed cannot produce a non-zero execution duration.
    assert fail_job.get("totalExecutionDurationSeconds", 0) > 0, (
        f"the FAILED run must report a non-zero totalExecutionDurationSeconds — a Spark driver "
        f"that started, worked and then raised — got "
        f"{fail_job.get('totalExecutionDurationSeconds')!r}"
    )

    # The effect-absent half: Spark's commit marker for the failing run is NOT in S3, and the
    # whole output prefix is empty.
    fail_marker = _head_status(s3, bucket, f"{fail_prefix}/_SUCCESS")
    assert fail_marker == "404", (
        f"a FAILED job run must not commit Spark's _SUCCESS marker to "
        f"s3://{bucket}/{fail_prefix}/; HeadObject answered {fail_marker!r}"
    )
    fail_keys = _list_keys(s3, bucket, f"{fail_prefix}/")
    assert fail_keys == [], (
        f"a FAILED job run must write nothing under s3://{bucket}/{fail_prefix}/, found "
        f"{fail_keys!r}"
    )

    # ---- the positive control, on the SAME application -------------------------------------
    pass_uri = f"s3://{bucket}/{pass_prefix}"
    pass_id = _submit(pass_key, [nonce, pass_uri], "sim2real-behav-emr-srvless-passing")
    pass_state = _poll(lambda: _job(pass_id)["state"], lambda s: s in TERMINAL_JOB_STATES,
                       timeout_s=900, interval_s=20,
                       description=f"passing job run {pass_id} reaches a terminal state")
    pass_job = _job(pass_id)
    assert pass_state == "SUCCESS", (
        f"the control run on the same application must reach SUCCESS — otherwise the failing "
        f"run's FAILED proves nothing about the script — got {pass_state!r} "
        f"(stateDetails: {pass_job.get('stateDetails')!r})"
    )
    parts = _poll(lambda: [k for k in _list_keys(s3, bucket, f"{pass_prefix}/") if "/part-" in k],
                  lambda ks: bool(ks), timeout_s=180, interval_s=10,
                  description=f"Spark output committed under s3://{bucket}/{pass_prefix}/")
    assert len(parts) == 1, (
        f"a single-partition RDD must commit exactly one part file, got {parts!r}"
    )
    body = s3.get_object(Bucket=bucket, Key=parts[0])["Body"].read().decode("utf-8")
    assert body.strip() == nonce, (
        f"the control run's Spark writer must produce exactly the nonce it was given; expected "
        f"{nonce!r}, got {body!r}"
    )

    # Both runs must be discoverable through the paginated listing with the states asserted above,
    # so a backend cannot report one thing by id and another in the list.
    listed = {jr["id"]: jr["state"]
              for page in emrs.get_paginator("list_job_runs").paginate(applicationId=app_id)
              for jr in page.get("jobRuns", [])}
    assert listed.get(fail_id) == "FAILED", (
        f"ListJobRuns must report the failing run {fail_id} as FAILED, got {listed!r}"
    )
    assert listed.get(pass_id) == "SUCCESS", (
        f"ListJobRuns must report the control run {pass_id} as SUCCESS, got {listed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
