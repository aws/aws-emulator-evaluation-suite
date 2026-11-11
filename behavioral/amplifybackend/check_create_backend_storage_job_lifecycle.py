"""create-backend-storage-job-lifecycle."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-backend-storage-job-lifecycle"
GROUP = "lifecycle"
SERVICES = ["amplifybackend"]
STUDIO_REFUSAL = (
    "An error occurred while processing your request: Operation not supported through SDK/AWS CLI. "
    "Please use Amplify Studio"
)
STORAGE_NOT_FOUND = (
    "An error occurred while processing your request: Given Storage resource not found in amplify-meta.json"
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBackendStorage through the SDK is refused with a fixed ValidationException directing the
    caller to Amplify Studio, and GetBackendStorage and ListBackendJobs show no resource or job from
    it, while CreateBackend for the same app completes."""
    app_id, app_name = _create_amplify_app(ctx)
    ab = ctx.client("amplifybackend")
    # BackendEnvironmentName is capped at 10 lowercase letters server-side (stricter than the model).
    env_name = "".join(secrets.choice(string.ascii_lowercase) for _ in range(10))

    created = ab.create_backend(AppId=app_id, AppName=app_name, BackendEnvironmentName=env_name)
    env_job_id = created["JobId"]
    ctx.on_cleanup(lambda: _best_effort_delete_backend(ab, app_id, env_name))

    env_job = _poll_until(
        lambda: ab.get_backend_job(AppId=app_id, BackendEnvironmentName=env_name, JobId=env_job_id),
        lambda j: j["Status"] == "COMPLETED" or bool(j.get("Error")),
        timeout_s=600,
        interval_s=10,
    )
    assert env_job["Status"] == "COMPLETED" and not env_job.get("Error"), (
        f"positive control failed: backend env job did not complete cleanly: {env_job}"
    )

    resource_name = "s3storage"
    bucket_name = ctx.unique_name("sim2real-ab-storage-").lower().replace("_", "-")
    before_job_ids = _job_ids(ab, app_id, env_name)

    try:
        ab.create_backend_storage(
            AppId=app_id,
            BackendEnvironmentName=env_name,
            ResourceName=resource_name,
            ResourceConfig={
                "BucketName": bucket_name,
                "Permissions": {"Authenticated": ["READ"]},
                "ServiceName": "S3",
            },
        )
        raise AssertionError(
            "expected CreateBackendStorage to be rejected on real AWS (SDK/CLI unsupported); it succeeded"
        )
    except ClientError as e:
        error = e.response["Error"]
        assert error["Code"] == "ValidationException", (
            f"expected ValidationException rejecting CreateBackendStorage via SDK/CLI, "
            f"got {error['Code']}: {error['Message']}"
        )
        assert error.get("Message") == STUDIO_REFUSAL, (
            f"expected the SDK/CLI-unsupported refusal {STUDIO_REFUSAL!r}, got: {error.get('Message')!r}"
        )

    try:
        ab.get_backend_storage(AppId=app_id, BackendEnvironmentName=env_name, ResourceName=resource_name)
        raise AssertionError("expected GetBackendStorage to find nothing after the rejected create")
    except ClientError as e:
        error = e.response["Error"]
        assert error["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for the never-created storage resource, got {error}"
        )
        assert error.get("Message") == STORAGE_NOT_FOUND, (
            f"expected GetBackendStorage message {STORAGE_NOT_FOUND!r}, got: {error.get('Message')!r}"
        )

    after_job_ids = _job_ids(ab, app_id, env_name)
    assert after_job_ids == before_job_ids, (
        f"expected no new backend job from the rejected CreateBackendStorage call, "
        f"before={before_job_ids} after={after_job_ids}"
    )


def _create_amplify_app(ctx):
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-ab-app-")
    resp = amplify.create_app(name=name)
    app_id = resp["app"]["appId"]
    ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
    return app_id, name


def _job_ids(ab, app_id, env_name):
    jobs = ab.list_backend_jobs(AppId=app_id, BackendEnvironmentName=env_name).get("Jobs", [])
    return {j["JobId"] for j in jobs}


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
