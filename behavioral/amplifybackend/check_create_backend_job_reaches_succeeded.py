"""create-backend-job-reaches-succeeded."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-backend-job-reaches-succeeded"
GROUP = "lifecycle"
SERVICES = ["amplifybackend"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBackend's returned job reaches a terminal COMPLETED status, and the environment it
    provisioned becomes visible through GetBackend -- an independent read at a different
    operation than either CreateBackend or GetBackendJob."""
    app_id, app_name = _create_amplify_app(ctx)
    ab = ctx.client("amplifybackend")
    # BackendEnvironmentName is undocumented in the Smithy model but real AWS rejects anything
    # outside 2-10 lowercase LETTERS (ValidationException; digits and hyphens are rejected too),
    # so the generated name maps the hex unique_name onto a-z rather than using it raw.
    env_name = "e" + ctx.unique_name("")[:9].translate(str.maketrans("0123456789", "qrstuvwxyz"))

    created = ab.create_backend(AppId=app_id, AppName=app_name, BackendEnvironmentName=env_name)
    job_id = created["JobId"]
    ctx.on_cleanup(lambda: _best_effort_delete_backend(ab, app_id, env_name))

    # GetBackendJob reports the terminal state as "COMPLETED" (or "FAILED"), not
    # "Succeeded"/"Failed".
    job = _poll_until(
        lambda: ab.get_backend_job(AppId=app_id, BackendEnvironmentName=env_name, JobId=job_id),
        lambda j: j["Status"] in ("COMPLETED", "FAILED"),
        timeout_s=600,
        interval_s=10,
    )
    assert job["Status"] == "COMPLETED", f"backend job did not complete: {job}"
    assert not job.get("Error"), f"completed job carried an error payload: {job.get('Error')}"

    backend = ab.get_backend(AppId=app_id)
    assert env_name in backend.get("BackendEnvironmentList", []), (
        f"{env_name!r} missing from GetBackend's environment list: "
        f"{backend.get('BackendEnvironmentList')}"
    )


# ===== helpers (self-contained) =====
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
