"""cancel-job-run-on-terminal-state-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cancel-job-run-on-terminal-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelJobRun on a job run already in a terminal state (FAILED) is rejected with ValidationException
    and the job run's state is left unchanged, while cancelling a freshly-submitted, still-pending job
    run on the same application succeeds and drives it to CANCELLED."""
    iam = ctx.client("iam")
    emrs = ctx.client("emr-serverless")

    # a role emr-serverless cannot assume -> any job run against it reliably fails.
    role_name = ctx.unique_name("sim2real-emrs-badrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        tags={"sim2real": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: _cleanup_application(emrs, app_id))

    job_driver = {"sparkSubmit": {"entryPoint": "s3://sim2real-emrs-check-nonexistent/job.py"}}

    # Part A: run a job to FAILED, then try to cancel the already-terminal run.
    run1_id = emrs.start_job_run(
        applicationId=app_id,
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        executionRoleArn=role_arn,
        jobDriver=job_driver,
    )["jobRunId"]

    failed_run = _poll_until(
        lambda: emrs.get_job_run(applicationId=app_id, jobRunId=run1_id)["jobRun"],
        lambda jr: jr["state"] in ("SUCCESS", "FAILED", "CANCELLED"),
        timeout_s=420.0,
        interval_s=10.0,
    )
    assert failed_run["state"] == "FAILED", f"expected job run to reach FAILED, got {failed_run['state']!r}"

    code, message = _error(lambda: emrs.cancel_job_run(applicationId=app_id, jobRunId=run1_id))
    assert code == "ValidationException", f"expected ValidationException cancelling a FAILED job run, got {code!r}"
    assert message == "Job run is not in a cancellable state", (
        f"unexpected CancelJobRun message for a FAILED job run: {message!r}"
    )

    unchanged = emrs.get_job_run(applicationId=app_id, jobRunId=run1_id)["jobRun"]
    assert unchanged["state"] == "FAILED", (
        f"expected the rejected cancel to leave state unchanged at FAILED, got {unchanged['state']!r}"
    )

    # Part B (positive control): a *fresh* job run cancelled immediately, before it can fail, succeeds.
    run2_id = emrs.start_job_run(
        applicationId=app_id,
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        executionRoleArn=role_arn,
        jobDriver=job_driver,
    )["jobRunId"]
    emrs.cancel_job_run(applicationId=app_id, jobRunId=run2_id, shutdownGracePeriodInSeconds=0)

    final_state = _poll_until(
        lambda: emrs.get_job_run(applicationId=app_id, jobRunId=run2_id)["jobRun"]["state"],
        lambda s: s in ("CANCELLED", "SUCCESS", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final_state == "CANCELLED", (
        f"expected the fresh, immediately-cancelled job run to reach CANCELLED, got {final_state!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
