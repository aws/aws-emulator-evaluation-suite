"""cancel-terminal-job-run-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cancel-terminal-job-run-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelJobRun on an already-terminal (CANCELLED) job run is an idempotent no-op,
    but CancelJobRun on a job run id that does not exist on the application is rejected
    with ResourceNotFoundException."""
    emrs = ctx.client("emr-serverless")
    role_arn = _create_execution_role(ctx)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.0.0",
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        autoStartConfiguration={"enabled": True},
        tags={"sim2real:managed": "true"},
    )["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))
    ctx.on_cleanup(lambda: _wait_for_application_state(ctx, app_id, {"STOPPED"}, timeout_s=300.0))
    ctx.on_cleanup(lambda: _safe_stop(emrs, app_id))
    ctx.on_cleanup(lambda: _wait_for_application_state(ctx, app_id, {"STARTED"}, timeout_s=300.0))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    job_driver = {"sparkSubmit": {"entryPoint": "s3://sim2real-does-not-exist/none.py"}}
    job_run_id = _start_job_run_with_retry(emrs, app_id, role_arn, job_driver, ctx)

    # positive control: the first cancel on a live (non-terminal) job run succeeds
    emrs.cancel_job_run(applicationId=app_id, jobRunId=job_run_id)
    cancelled_state = _wait_for_job_run_state(ctx, app_id, job_run_id, {"CANCELLED"}, timeout_s=300.0)
    assert cancelled_state == "CANCELLED", (
        f"expected the live job run to reach CANCELLED after cancel, got {cancelled_state!r}"
    )

    # empirically, a repeat cancel on an already-terminal job run is accepted as an
    # idempotent no-op (echoes back the same ids) rather than raising an error
    repeat_resp = emrs.cancel_job_run(applicationId=app_id, jobRunId=job_run_id)
    assert repeat_resp["jobRunId"] == job_run_id, (
        f"expected repeat cancel to echo back jobRunId {job_run_id!r}, got {repeat_resp['jobRunId']!r}"
    )

    # effect absent: the job run's state is unchanged
    still_state = emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]["state"]
    assert still_state == "CANCELLED", (
        f"expected repeat cancel to leave state unchanged at CANCELLED, got {still_state!r}"
    )

    # break exactly one thing: cancel a job run id that does not exist on this application
    bogus_job_run_id = "00" + job_run_id[2:] if job_run_id[:2] != "00" else "11" + job_run_id[2:]
    code, message = _error(lambda: emrs.cancel_job_run(applicationId=app_id, jobRunId=bogus_job_run_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException cancelling nonexistent job run id "
        f"{bogus_job_run_id!r}, got {code!r}"
    )
    assert message == "Job Run with given ID doesn't exist", (
        f"unexpected CancelJobRun not-found message: {message!r}"
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


def _start_job_run_with_retry(emrs, app_id, role_arn, job_driver, ctx, timeout_s=90.0, interval_s=5.0):
    """StartJobRun can fail until IAM's assume-role trust for the freshly-created execution role
    has propagated; retry on that transient error instead of guessing a fixed delay."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = emrs.start_job_run(
                applicationId=app_id,
                clientToken=ctx.unique_name("tok-"),
                executionRoleArn=role_arn,
                jobDriver=job_driver,
            )
            return resp["jobRunId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"StartJobRun never succeeded within {timeout_s}s of IAM propagation wait: {last_exc}")


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


def _wait_for_job_run_state(ctx, app_id, job_run_id, target_states, timeout_s=300.0, interval_s=5.0):
    emrs = ctx.client("emr-serverless")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]["state"]
        if last in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"job run never reached {target_states}, last state={last}")


def _safe_stop(emrs, app_id):
    from botocore.exceptions import ClientError
    try:
        emrs.stop_application(applicationId=app_id)
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
