"""get-backend-lists-created-environment."""
from __future__ import annotations

import random
import string
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-backend-lists-created-environment"
GROUP = "lifecycle"
SERVICES = ["amplifybackend"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once CreateBackend's job reaches COMPLETED, GetBackend lists the new environment in
    BackendEnvironmentList."""
    app_id, app_name = _create_amplify_app(ctx)
    ab = ctx.client("amplifybackend")
    # BackendEnvironmentName must be 2-10 lowercase letters (stricter than the model), which
    # ctx.unique_name's output never satisfies.
    env_name = "".join(random.choices(string.ascii_lowercase, k=8))

    created = ab.create_backend(AppId=app_id, AppName=app_name, BackendEnvironmentName=env_name)
    job_id = created["JobId"]
    ctx.on_cleanup(lambda: _best_effort_delete_backend(ab, app_id, env_name))

    # A job reads PENDING or RUNNING while in flight and COMPLETED on success.
    job = _poll_until(
        lambda: ab.get_backend_job(AppId=app_id, BackendEnvironmentName=env_name, JobId=job_id),
        lambda j: j["Status"] not in ("PENDING", "RUNNING"),
        timeout_s=600,
        interval_s=10,
    )
    assert job["Status"] == "COMPLETED", f"backend job did not complete: {job}"

    backend = ab.get_backend(AppId=app_id)
    env_list = backend["BackendEnvironmentList"]
    assert env_name in env_list, f"expected {env_name!r} in BackendEnvironmentList, got {env_list!r}"


def _create_amplify_app(ctx):
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-ab-app-")
    resp = amplify.create_app(name=name, tags={"sim2real": "true"})
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
