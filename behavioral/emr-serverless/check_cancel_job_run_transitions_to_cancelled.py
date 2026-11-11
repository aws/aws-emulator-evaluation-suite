"""cancel-job-run-transitions-to-cancelled."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cancel-job-run-transitions-to-cancelled"
GROUP = "job-run-lifecycle"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CancelJobRun on a job run that is actively RUNNING (real Spark capacity executing a long script)
    drives it through CANCELLING to CANCELLED, releasing the resources before natural completion."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    emrs = ctx.client("emr-serverless")

    bucket = ctx.unique_name("sim2real-emrs-cxl-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    # a plain script that sleeps well past the time it takes us to observe RUNNING and cancel it.
    s3.put_object(Bucket=bucket, Key="sleep.py", Body=b"import time\ntime.sleep(240)\n")

    role_arn = _create_execution_role(ctx, iam, bucket)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        tags={"sim2real-check": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: _cleanup_application(emrs, app_id))

    job_run_id = _start_job_run_with_retry(
        emrs, app_id, role_arn, {"sparkSubmit": {"entryPoint": f"s3://{bucket}/sleep.py"}}, ctx
    )

    _poll_until(
        lambda: emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]["state"],
        lambda s: s in ("SCHEDULED", "RUNNING", "PENDING"),
        timeout_s=420.0,
        interval_s=10.0,
    )

    emrs.cancel_job_run(applicationId=app_id, jobRunId=job_run_id, shutdownGracePeriodInSeconds=0)

    final_state = _poll_until(
        lambda: emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]["state"],
        lambda s: s in ("CANCELLED", "SUCCESS", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final_state == "CANCELLED", f"expected job run to transition to CANCELLED, got {final_state!r}"


def _create_bucket(ctx, s3, bucket):
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # us-east-1 rejects an explicit LocationConstraint; every other region requires it
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
