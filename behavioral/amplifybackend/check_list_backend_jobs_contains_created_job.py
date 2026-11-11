"""list-backend-jobs-contains-created-job."""
from __future__ import annotations

import secrets
import string
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-backend-jobs-contains-created-job"
GROUP = "lifecycle"
SERVICES = ["amplifybackend"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListBackendJobs surfaces the job created by CreateBackend with the same JobId/Operation."""
    app_id, app_name = _create_amplify_app(ctx)
    ab = ctx.client("amplifybackend")
    # BackendEnvironmentName is restricted on AWS to 2-10 lowercase LETTERS ONLY (AWS rejects
    # digits), so it cannot use ctx.unique_name's "sim2real-..." prefix.
    env_name = "".join(secrets.choice(string.ascii_lowercase) for _ in range(8))

    created = ab.create_backend(AppId=app_id, AppName=app_name, BackendEnvironmentName=env_name)
    job_id = created["JobId"]
    ctx.on_cleanup(lambda: _best_effort_delete_backend(ab, app_id, env_name))

    # Status terminal values are COMPLETED/FAILED on real AWS, not Succeeded/Failed; the Smithy
    # model carries no enum for this field.
    job = _poll_until(
        lambda: ab.get_backend_job(AppId=app_id, BackendEnvironmentName=env_name, JobId=job_id),
        lambda j: j["Status"] in ("COMPLETED", "FAILED"),
        timeout_s=600,
        interval_s=10,
    )
    assert job["Status"] == "COMPLETED", f"backend job did not complete: {job}"
    # CreateBackend's own response does not carry "Operation" on AWS, even though the Smithy
    # model lists it as optional output, so the expected value
    # must come from an independent read -- GetBackendJob, itself distinct from the mutating call --
    # not from echoing the create response.
    job_operation = job.get("Operation")
    assert job_operation, f"GetBackendJob did not report an Operation: {job!r}"

    listed = ab.list_backend_jobs(AppId=app_id, BackendEnvironmentName=env_name)
    matches = [j for j in listed.get("Jobs", []) if j.get("JobId") == job_id]
    assert len(matches) == 1, f"expected exactly one job with id {job_id}, got {matches}"
    assert matches[0]["Operation"] == job_operation, (
        f"expected Operation {job_operation!r}, got {matches[0].get('Operation')!r} in {matches[0]!r}"
    )
    assert matches[0]["Status"] == "COMPLETED", f"expected Status COMPLETED, got {matches[0]!r}"


def _create_amplify_app(ctx):
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-ab-app-")
    resp = amplify.create_app(name=name, tags={"sim2real": CHECK})
    app_id = resp["app"]["appId"]
    ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
    return app_id, name


def _best_effort_delete_backend(ab, app_id, env_name):
    try:
        ab.delete_backend(AppId=app_id, BackendEnvironmentName=env_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
