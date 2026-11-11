"""start-job-run-auto-starts-application."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-job-run-auto-starts-application"
GROUP = "state"
SERVICES = ["emr-serverless"]

MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-emrs"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartJobRun on a CREATED application with autoStart enabled brings the application to STARTED."""
    emrs = ctx.client("emr-serverless")
    role_arn = _create_execution_role(ctx)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.0.0",
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        autoStartConfiguration={"enabled": True},
        tags=MANAGED_TAGS,
    )["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    job_run_id = _start_job_run_with_role_propagation_retry(
        emrs,
        applicationId=app_id,
        clientToken=ctx.unique_name("tok-"),
        executionRoleArn=role_arn,
        jobDriver={"sparkSubmit": {"entryPoint": "s3://sim2real-does-not-exist/none.py"}},
    )

    # we never called StartApplication -- the job submission itself must trigger auto-start
    state = _wait_for_application_state(ctx, app_id, {"STARTING", "STARTED"}, timeout_s=300.0)
    assert state in ("STARTING", "STARTED"), f"expected STARTING or STARTED after StartJobRun, got {state}"

    final = _wait_for_application_state(ctx, app_id, {"STARTED"}, timeout_s=300.0)
    assert final == "STARTED", f"expected application STARTED, got {final}"

    ctx.on_cleanup(lambda: _wait_for_application_state(ctx, app_id, {"STOPPED"}, timeout_s=300.0))
    ctx.on_cleanup(lambda: emrs.stop_application(applicationId=app_id))
    ctx.on_cleanup(lambda: _safe_cancel(emrs, app_id, job_run_id))


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
        Tags=[{"Key": k, "Value": v} for k, v in MANAGED_TAGS.items()],
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


def _start_job_run_with_role_propagation_retry(emrs, *, timeout_s=60.0, interval_s=3.0, **kwargs):
    """StartJobRun, retrying only while emr-serverless has not yet observed the freshly
    created execution role as assumable -- IAM's own trust-policy propagation exposes no
    condition to poll, so this is a bounded retry on the specific rejection, never a sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return emrs.start_job_run(**kwargs)["jobRunId"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in {"ValidationException", "AccessDeniedException"} and "assum" in str(e).lower():
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"StartJobRun never resolved after {timeout_s}s of IAM role propagation retries: {last_err}")


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


def _safe_cancel(emrs, app_id, job_run_id):
    from botocore.exceptions import ClientError
    try:
        emrs.cancel_job_run(applicationId=app_id, jobRunId=job_run_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
