"""list-job-runs-filters-by-state."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-job-runs-filters-by-state"
GROUP = "list-filtering"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListJobRuns with a states filter separates a CANCELLED run from one still in flight."""
    emrs = ctx.client("emr-serverless")
    role_arn = _create_execution_role(ctx)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.0.0",
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        autoStartConfiguration={"enabled": True},
    )["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))
    ctx.on_cleanup(lambda: _wait_for_application_state(ctx, app_id, {"STOPPED"}, timeout_s=300.0))
    ctx.on_cleanup(lambda: _safe_stop(emrs, app_id))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    job_a = _start_job_run_with_retry(
        emrs,
        applicationId=app_id,
        clientToken=ctx.unique_name("tok-"),
        executionRoleArn=role_arn,
        jobDriver={"sparkSubmit": {"entryPoint": "s3://sim2real-does-not-exist/a.py"}},
    )["jobRunId"]
    job_b = _start_job_run_with_retry(
        emrs,
        applicationId=app_id,
        clientToken=ctx.unique_name("tok-"),
        executionRoleArn=role_arn,
        jobDriver={"sparkSubmit": {"entryPoint": "s3://sim2real-does-not-exist/b.py"}},
    )["jobRunId"]
    ctx.on_cleanup(lambda: _safe_cancel(emrs, app_id, job_b))

    # cancel A right away; leave B running so it's still non-terminal when we list
    emrs.cancel_job_run(applicationId=app_id, jobRunId=job_a)
    _wait_for_job_run_state(ctx, app_id, job_a, {"CANCELLED"}, timeout_s=300.0)

    cancelled_ids = {j["id"] for j in _list_all(emrs, applicationId=app_id, states=["CANCELLED"])}
    assert job_a in cancelled_ids, f"expected cancelled job {job_a} in states=[CANCELLED] listing, got {cancelled_ids}"
    assert job_b not in cancelled_ids, f"expected non-terminal job {job_b} absent from states=[CANCELLED] listing, got {cancelled_ids}"

    non_terminal_ids = {
        j["id"]
        for j in _list_all(
            emrs, applicationId=app_id, states=["SUBMITTED", "PENDING", "SCHEDULED", "QUEUED", "RUNNING"]
        )
    }
    assert job_b in non_terminal_ids, f"expected non-terminal job {job_b} in the non-terminal-states listing, got {non_terminal_ids}"
    assert job_a not in non_terminal_ids, f"expected cancelled job {job_a} absent from the non-terminal-states listing, got {non_terminal_ids}"


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
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


def _start_job_run_with_retry(emrs, timeout_s: float = 60.0, interval_s: float = 3.0, **kwargs):
    """The execution role was just created; emr-serverless may not yet be able to assume
    it. Poll the observable condition we actually care about -- start_job_run itself --
    rather than sleeping blindly."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return emrs.start_job_run(**kwargs)
        except Exception as exc:  # noqa: BLE001 - broad on purpose, retried below
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"start_job_run kept failing within {timeout_s}s: {last_exc}")


def _list_all(emrs, **kwargs):
    out = []
    token = None
    while True:
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = emrs.list_job_runs(**params)
        out.extend(resp.get("jobRuns", []))
        token = resp.get("nextToken")
        if not token:
            return out


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
