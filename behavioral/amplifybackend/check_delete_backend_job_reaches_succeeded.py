"""delete-backend-job-reaches-succeeded."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-backend-job-reaches-succeeded"
GROUP = "lifecycle"
SERVICES = ["amplifybackend"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteBackend's job for an existing environment reaches COMPLETED, GetBackend no longer lists
    the environment, and a second DeleteBackend is refused with NotFoundException and the exact
    message."""
    app_id, app_name = _create_amplify_app(ctx)
    ab = ctx.client("amplifybackend")
    # BackendEnvironmentName must be 2-10 lowercase letters (stricter than the model).
    env_name = "".join(chr(97 + int(c, 16)) for c in uuid.uuid4().hex[:8])

    created = ab.create_backend(AppId=app_id, AppName=app_name, BackendEnvironmentName=env_name)
    create_job_id = created["JobId"]

    create_job = _poll_until(
        lambda: ab.get_backend_job(AppId=app_id, BackendEnvironmentName=env_name, JobId=create_job_id),
        lambda j: j["Status"] in ("COMPLETED", "FAILED"),
        timeout_s=600,
        interval_s=10,
    )
    assert create_job["Status"] == "COMPLETED", f"backend env job did not succeed: {create_job}"

    deleted = ab.delete_backend(AppId=app_id, BackendEnvironmentName=env_name)
    delete_job_id = deleted["JobId"]

    delete_job = _poll_until(
        lambda: ab.get_backend_job(AppId=app_id, BackendEnvironmentName=env_name, JobId=delete_job_id),
        lambda j: j["Status"] in ("COMPLETED", "FAILED"),
        timeout_s=600,
        interval_s=10,
    )
    assert delete_job["Status"] == "COMPLETED", f"delete job did not succeed: {delete_job}"

    backend = ab.get_backend(AppId=app_id)
    assert env_name not in backend.get("BackendEnvironmentList", []), (
        f"{env_name} still listed after DeleteBackend succeeded: {backend}"
    )

    error = _client_error(lambda: ab.delete_backend(AppId=app_id, BackendEnvironmentName=env_name))
    assert error["Code"] == "NotFoundException", repr(error)
    assert error.get("Message") == (
        f"An error occurred while processing your request: BackendEnvironment {env_name} does not exist."
    ), repr(error)


def _create_amplify_app(ctx):
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-ab-app-")
    resp = amplify.create_app(name=name, tags={"sim2real": CHECK})
    app_id = resp["app"]["appId"]
    ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
    return app_id, name


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError; call succeeded unexpectedly with {result!r}")


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
