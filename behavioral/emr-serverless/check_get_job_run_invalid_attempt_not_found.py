"""get-job-run-invalid-attempt-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-job-run-invalid-attempt-not-found"
GROUP = "error-semantics"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetJobRun with an attempt number that was never created returns ResourceNotFoundException."""
    emrs = ctx.client("emr-serverless")
    role_arn = _create_execution_role(ctx)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.0.0",
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        autoStartConfiguration={"enabled": True},
        tags={"sim2real": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: _stop_and_delete_application(emrs, app_id))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    job_run_id = _start_job_run_with_retry(ctx, emrs, app_id, role_arn)
    ctx.on_cleanup(lambda: _safe_cancel(emrs, app_id, job_run_id))

    # sanity: attempt 1 (the only one that exists) is readable
    first = emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id, attempt=1)
    assert first["jobRun"]["jobRunId"] == job_run_id, (
        f"expected attempt=1 to return jobRunId={job_run_id!r}, got {first['jobRun'].get('jobRunId')!r}"
    )

    code, message = _error(lambda: emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id, attempt=999))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created attempt, got {code!r}"
    )
    assert message == "Job Run with given attempt doesn't exist", (
        f"unexpected GetJobRun not-found message: {message!r}"
    )


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


def _start_job_run_with_retry(ctx, emrs, app_id, role_arn, timeout_s=30.0, interval_s=3.0):
    """StartJobRun can reject a just-created role before IAM's trust-policy change has propagated
    to emr-serverless; retry (idempotently, same clientToken) up to a bounded deadline instead of
    guessing a fixed sleep."""
    from botocore.exceptions import ClientError

    token = ctx.unique_name("tok-")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return emrs.start_job_run(
                applicationId=app_id,
                clientToken=token,
                executionRoleArn=role_arn,
                jobDriver={"sparkSubmit": {"entryPoint": "s3://sim2real-does-not-exist/none.py"}},
            )["jobRunId"]
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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


def _stop_and_delete_application(emrs, app_id, timeout_s=600.0, interval_s=10.0):
    """StopApplication is refused while the application is still starting or a cancelled job run
    is still draining, so retry it until the application reaches STOPPED, then delete it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = emrs.get_application(applicationId=app_id)["application"]["state"]
        if state in ("CREATED", "STOPPED", "TERMINATED"):
            break
        if state == "STARTED":
            try:
                emrs.stop_application(applicationId=app_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        time.sleep(interval_s)
    else:
        raise AssertionError(f"application {app_id} never stopped for teardown, last state={state}")
    if state != "TERMINATED":
        emrs.delete_application(applicationId=app_id)


def _safe_cancel(emrs, app_id, job_run_id):
    from botocore.exceptions import ClientError
    try:
        emrs.cancel_job_run(applicationId=app_id, jobRunId=job_run_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
