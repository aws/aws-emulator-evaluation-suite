"""create-backend-auth-job-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-backend-auth-job-lifecycle"
GROUP = "lifecycle"
SERVICES = ["amplifybackend"]
STUDIO_REFUSAL = (
    "An error occurred while processing your request: Operation not supported through SDK/AWS CLI. "
    "Please use Amplify Studio"
)
AUTH_NOT_FOUND = "An error occurred while processing your request: Amplify auth parameters file not found."


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBackendAuth through the SDK is refused with a fixed ValidationException directing the
    caller to Amplify Studio and creates no auth resource, while CreateBackend for the same app
    completes."""
    app_id, app_name = _create_amplify_app(ctx)
    ab = ctx.client("amplifybackend")
    # BackendEnvironmentName must be 2-10 lowercase letters (stricter than the model), so
    # unique_name's digits are mapped to letters.
    env_name = ("e" + ctx.unique_name("")[:9]).translate(
        str.maketrans("0123456789", "ghijklmnop")
    )

    created = ab.create_backend(AppId=app_id, AppName=app_name, BackendEnvironmentName=env_name)
    env_job_id = created["JobId"]
    ctx.on_cleanup(lambda: _best_effort_delete_backend(ab, app_id, env_name))

    env_job = _poll_until(
        lambda: ab.get_backend_job(AppId=app_id, BackendEnvironmentName=env_name, JobId=env_job_id),
        lambda j: j["Status"] in ("COMPLETED", "FAILED"),
        timeout_s=600,
        interval_s=10,
    )
    # Positive control: the account and credentials are healthy for amplifybackend --
    # CreateBackend (the environment itself) succeeds through the SDK.
    assert env_job["Status"] == "COMPLETED", f"backend env job did not complete: {env_job}"

    resource_name = "cognitoauth"
    user_pool_name = ctx.unique_name("sim2real-ab-pool-")
    resource_config = {
        "AuthResources": "USER_POOL_ONLY",
        "Service": "COGNITO",
        "UserPoolConfigs": {
            "RequiredSignUpAttributes": ["EMAIL"],
            "SignInMethod": "EMAIL",
            "UserPoolName": user_pool_name,
        },
    }

    # CreateBackendAuth is refused for every SDK caller with a ValidationException naming
    # Amplify Studio as the supported path.
    try:
        ab.create_backend_auth(
            AppId=app_id,
            BackendEnvironmentName=env_name,
            ResourceName=resource_name,
            ResourceConfig=resource_config,
        )
    except ClientError as e:
        error = e.response["Error"]
        assert error["Code"] == "ValidationException", (
            f"expected the SDK/CLI-withdrawal ValidationException, got {error['Code']}: "
            f"{error.get('Message')}"
        )
        assert error.get("Message") == STUDIO_REFUSAL, (
            f"expected the withdrawal message {STUDIO_REFUSAL!r}, got: {error.get('Message')!r}"
        )
    else:
        raise AssertionError(
            "CreateBackendAuth succeeded through the SDK; AWS has apparently restored "
            "SDK/CLI support and this withdrawal check needs re-auditing"
        )

    # Effect-absent, at an independent read: GetBackendAuth finds nothing for this
    # environment, because the create above never took effect.
    try:
        auth = ab.get_backend_auth(
            AppId=app_id, BackendEnvironmentName=env_name, ResourceName=resource_name
        )
    except ClientError as e:
        error = e.response["Error"]
        assert error["Code"] == "ResourceNotFoundException", (
            f"expected GetBackendAuth to report no resource, got {error['Code']}: "
            f"{error.get('Message')}"
        )
        assert error.get("Message") == AUTH_NOT_FOUND, (
            f"expected GetBackendAuth message {AUTH_NOT_FOUND!r}, got: {error.get('Message')!r}"
        )
    else:
        raise AssertionError(
            f"GetBackendAuth found a resource after the rejected create: {auth}"
        )


def _create_amplify_app(ctx):
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-ab-app-")
    resp = amplify.create_app(
        name=name, tags={"sim2real": "create-backend-auth-job-lifecycle"}
    )
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
