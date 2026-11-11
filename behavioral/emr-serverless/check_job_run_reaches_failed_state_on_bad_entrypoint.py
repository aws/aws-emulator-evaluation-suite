"""job-run-reaches-failed-state-on-bad-entrypoint."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "job-run-reaches-failed-state-on-bad-entrypoint"
GROUP = "state"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A job whose Spark entry point can never be fetched actually executes and lands in FAILED."""
    emrs = ctx.client("emr-serverless")
    role_arn = _create_execution_role(ctx)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.0.0",
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        tags={"sim2real": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))
    ctx.on_cleanup(lambda: _wait_for_application_state(ctx, app_id, {"STOPPED"}, timeout_s=300.0))
    ctx.on_cleanup(lambda: emrs.stop_application(applicationId=app_id))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    # start the application explicitly so the job begins executing promptly
    emrs.start_application(applicationId=app_id)
    _wait_for_application_state(ctx, app_id, {"STARTED"}, timeout_s=300.0)

    job_run_id = _start_job_run_with_retry(
        emrs,
        app_id,
        role_arn,
        {
            "sparkSubmit": {
                "entryPoint": f"s3://{ctx.unique_name('sim2real-emrs-no-such-bucket-')}/no_such_script.py",
            }
        },
        ctx,
    )

    final_state = _wait_for_job_run_state(
        ctx, app_id, job_run_id, {"SUCCESS", "FAILED", "CANCELLED"}, timeout_s=600.0
    )
    assert final_state == "FAILED", f"expected FAILED for an unreachable entry point, got {final_state}"

    job_run = emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]
    assert job_run["stateDetails"], "FAILED job run reported no stateDetails explaining the failure"


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emrs-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "emr-serverless.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _start_job_run_with_retry(emrs, app_id, role_arn, job_driver, ctx):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = emrs.start_job_run(
                applicationId=app_id,
                clientToken=ctx.unique_name("tok-"),
                executionRoleArn=role_arn,
                jobDriver=job_driver,
                executionTimeoutMinutes=10,
            )
            return resp["jobRunId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"StartJobRun never succeeded after IAM propagation wait: {last_exc}")


def _wait_for_application_state(ctx, app_id, target_states, timeout_s=180.0, interval_s=5.0):
    emrs = ctx.client("emr-serverless")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_application(applicationId=app_id)["application"]["state"]
        if last in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"application never reached {target_states}, last state={last}")


def _wait_for_job_run_state(ctx, app_id, job_run_id, target_states, timeout_s=600.0, interval_s=10.0):
    emrs = ctx.client("emr-serverless")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]["state"]
        if last in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"job run never reached {target_states}, last state={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
