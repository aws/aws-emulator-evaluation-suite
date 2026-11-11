"""create-backend-nonexistent-app-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-backend-nonexistent-app-not-found"
GROUP = "error-semantics"
SERVICES = ["amplifybackend"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBackend for a nonexistent AppId is refused with NotFoundException and the exact
    message, while the same call on a real app clears app lookup and fails only on the malformed
    environment name, with its exact ValidationException."""
    amplify = ctx.client("amplify")
    ab = ctx.client("amplifybackend")

    app_resp = amplify.create_app(
        name=ctx.unique_name("sim2real-ab-app-"), tags={"sim2real": CHECK}
    )
    app_id = app_resp["app"]["appId"]
    ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))

    positive = _client_error(
        lambda: ab.create_backend(
            AppId=app_id,
            AppName=ctx.unique_name("sim2real-ab-noapp-"),
            BackendEnvironmentName="env-name-too-long-to-be-valid",
        )
    )
    assert positive["Code"] == "ValidationException", repr(positive)
    assert positive.get("Message") == (
        "An error occurred while processing your request: "
        "Environment name must be between 2 and 10 characters, and lowercase only."
    ), repr(positive)

    bogus_app_id = "d" + uuid.uuid4().hex[:12]
    negative = _client_error(
        lambda: ab.create_backend(
            AppId=bogus_app_id,
            AppName=ctx.unique_name("sim2real-ab-noapp-"),
            BackendEnvironmentName="dev",
        )
    )
    assert negative["Code"] == "NotFoundException", repr(negative)
    assert negative.get("Message") == (
        f"An error occurred while processing your request: App {bogus_app_id} not found."
    ), repr(negative)


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError; call succeeded unexpectedly with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
