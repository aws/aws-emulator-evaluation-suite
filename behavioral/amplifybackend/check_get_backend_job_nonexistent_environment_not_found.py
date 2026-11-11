"""get-backend-job-nonexistent-environment-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-backend-job-nonexistent-environment-not-found"
GROUP = "error-semantics"
SERVICES = ["amplifybackend"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetBackendJob on a live app for an environment and job that were never created is refused
    with ResourceNotFoundException and the exact message; the real app isolates a missing job from
    a missing app."""
    app_id = _create_amplify_app(ctx)
    ab = ctx.client("amplifybackend")

    error = _client_error(
        lambda: ab.get_backend_job(
            AppId=app_id,
            BackendEnvironmentName="never-created-env",
            JobId="never-created-job",
        )
    )
    assert error["Code"] == "ResourceNotFoundException", repr(error)
    assert error.get("Message") == (
        "An error occurred while processing your request: "
        "Unable to find matching job with provided parameters."
    ), repr(error)


def _create_amplify_app(ctx):
    amplify = ctx.client("amplify")
    resp = amplify.create_app(name=ctx.unique_name("sim2real-ab-app-"), tags={"sim2real": CHECK})
    app_id = resp["app"]["appId"]
    ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
    return app_id


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError; call succeeded unexpectedly with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
