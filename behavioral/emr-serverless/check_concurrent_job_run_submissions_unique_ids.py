"""concurrent-job-run-submissions-unique-ids."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-job-run-submissions-unique-ids"
GROUP = "concurrency"
SERVICES = ["emr-serverless"]

MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-emrs"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent StartJobRun calls (distinct clientTokens) each get a distinct jobRunId, and
    all N show up in ListJobRuns -- no id collisions or lost writes under concurrent submission."""
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
    ctx.on_cleanup(lambda: _wait_for_application_state(ctx, app_id, {"STOPPED"}, timeout_s=300.0))
    ctx.on_cleanup(lambda: _safe_stop(emrs, app_id))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    n = 6

    def _submit(i):
        return _start_job_run_with_role_propagation_retry(
            emrs,
            applicationId=app_id,
            clientToken=ctx.unique_name(f"tok-{i}-"),
            executionRoleArn=role_arn,
            jobDriver={"sparkSubmit": {"entryPoint": f"s3://sim2real-does-not-exist/racer-{i}.py"}},
        )

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_submit, i) for i in range(n)]
        job_run_ids = [f.result() for f in as_completed(futures)]

    ctx.on_cleanup(lambda: [_safe_cancel(emrs, app_id, jid) for jid in job_run_ids])

    assert len(job_run_ids) == n, f"expected {n} StartJobRun results, got {len(job_run_ids)}"
    assert len(set(job_run_ids)) == n, "concurrent StartJobRun calls collided on jobRunId"

    listed_ids = {j["id"] for j in _list_all(emrs, applicationId=app_id)}
    for jid in job_run_ids:
        assert jid in listed_ids, f"jobRunId {jid} missing from ListJobRuns after concurrent submission"


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
