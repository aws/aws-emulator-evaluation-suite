"""list-experiment-definitions-invalid-application-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-experiment-definitions-invalid-application-id-rejected"
GROUP = "error-semantics"
SERVICES = ["appconfig"]
_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListExperimentDefinitions with a malformed application_identifier filter (exceeding
    the 2048-char length constraint) returns BadRequestException instead of silently
    treating the filter as a non-match and returning an empty list."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)

    malformed_id = "x" * 2049  # exceeds Identifier max length of 2048
    err = _error(
        lambda: appconfig.list_experiment_definitions(ApplicationIdentifier=malformed_id)
    )
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err['Code']}"
    assert err["Message"] == (
        f"1 validation error detected: Value '{malformed_id}' at 'applicationIdentifier' failed to "
        f"satisfy constraint: Member must have length less than or equal to 2048"
    ), f"unexpected message: {err['Message'][:200]!r}"

    # Positive control: a well-formed, real application identifier is accepted and lists fine.
    resp = appconfig.list_experiment_definitions(ApplicationIdentifier=app_id)
    assert "Items" in resp and isinstance(resp["Items"], list), (
        f"expected a well-formed application id to list successfully, got {resp!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS
    )
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
