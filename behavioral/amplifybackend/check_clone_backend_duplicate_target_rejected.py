"""clone-backend-duplicate-target-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "clone-backend-duplicate-target-rejected"
GROUP = "overly-permissive"
SERVICES = ["amplifybackend"]
CLONE_REFUSAL = (
    "An error occurred while processing your request: Operation not supported through SDK/AWS CLI. "
    'Please use "amplify pull --appId <appId> --envName staging && amplify add env && amplify push" '
    "from Amplify CLI"
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CloneBackend through the SDK is refused with the same ValidationException directing the
    caller to the Amplify CLI for both a fresh and an in-use target environment name, and neither
    call adds an environment."""
    app_id, app_name = _create_amplify_app(ctx)
    ab = ctx.client("amplifybackend")
    # BackendEnvironmentName must be 2-10 lowercase characters; it is scoped to the unique
    # app_id, so a short fixed literal is unique enough.
    env_a = "enva"

    created = ab.create_backend(AppId=app_id, AppName=app_name, BackendEnvironmentName=env_a)
    job_id = created["JobId"]
    ctx.on_cleanup(lambda: _best_effort_delete_backend(ab, app_id, env_a))

    # GetBackendJob's terminal-success Status is "COMPLETED"; the model leaves Status untyped.
    job = _poll_until(
        lambda: ab.get_backend_job(AppId=app_id, BackendEnvironmentName=env_a, JobId=job_id),
        lambda j: j["Status"] == "COMPLETED",
        timeout_s=600,
        interval_s=10,
    )
    assert job["Status"] == "COMPLETED", f"backend job did not complete: {job}"

    # A fresh target name is refused like a duplicate one: AWS blocks SDK clones before any
    # target-name validation.
    env_b = "envb"
    error_fresh = _client_error(
        lambda: ab.clone_backend(AppId=app_id, BackendEnvironmentName=env_a, TargetEnvironmentName=env_b)
    )
    assert error_fresh.get("Code") == "ValidationException", (
        f"CloneBackend into a fresh target name was rejected with {error_fresh.get('Code')!r}, "
        f"expected 'ValidationException'"
    )
    assert error_fresh.get("Message") == CLONE_REFUSAL, (
        f"CloneBackend into a fresh target name was rejected with message "
        f"{error_fresh.get('Message')!r}, expected {CLONE_REFUSAL!r}"
    )

    # Negative: cloning into the SAME environment name that is already in use gets the identical
    # SDK-level refusal, not a distinct duplicate-name error.
    error_dup = _client_error(
        lambda: ab.clone_backend(
            AppId=app_id, BackendEnvironmentName=env_a, TargetEnvironmentName=env_a
        )
    )
    assert error_dup.get("Code") == "ValidationException", (
        f"CloneBackend with TargetEnvironmentName equal to an already-in-use environment name "
        f"was rejected with {error_dup.get('Code')!r}, expected 'ValidationException'"
    )
    assert error_dup.get("Message") == CLONE_REFUSAL, (
        f"CloneBackend into an already-in-use target name was rejected with message "
        f"{error_dup.get('Message')!r}, expected {CLONE_REFUSAL!r}"
    )

    # Effect absent: neither the fresh nor the duplicate clone attempt created env_b, and env_a
    # still appears exactly once.
    backend = ab.get_backend(AppId=app_id)
    env_list = backend.get("BackendEnvironmentList", [])
    assert env_list.count(env_a) == 1, (
        f"env_a={env_a!r} appears {env_list.count(env_a)} times in {env_list!r} after the "
        f"refused CloneBackend calls, expected exactly 1"
    )
    assert env_b not in env_list, (
        f"env_b={env_b!r} appears in {env_list!r} even though every CloneBackend call into it "
        f"was refused"
    )


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


def _client_error(fn):
    """Call fn(); return its botocore Error dict. A success raises: accepting a call AWS refuses is a
    mismatch of its own, not a wrong error code."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected CloneBackend to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
