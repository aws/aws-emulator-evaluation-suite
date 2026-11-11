"""complete-resource-token-auth-server-validated-issuance."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-resource-token-auth-server-validated-issuance"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetResourceApiKey returns exactly the registered key for a valid workload token and refuses a
    bogus one ('Invalid workload access token'); CompleteResourceTokenAuth refuses a never-issued
    sessionUri ('Invalid or expired session'), both AccessDeniedException.
    """
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    workload_name = ctx.unique_name("sim2real-wi").replace("-", "")[:40]
    control.create_workload_identity(name=workload_name, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: control.delete_workload_identity(name=workload_name))

    provider_name = ctx.unique_name("sim2real-apikey").replace("-", "")[:40]
    secret_value = f"sim2real-secret-{uuid.uuid4().hex}"
    control.create_api_key_credential_provider(
        name=provider_name, apiKey=secret_value, tags={"sim2real:managed": "true"}
    )
    ctx.on_cleanup(lambda: control.delete_api_key_credential_provider(name=provider_name))

    token = data.get_workload_access_token(workloadName=workload_name)["workloadAccessToken"]

    # Positive: a genuinely valid workload identity token unlocks the real stored secret.
    fetched = data.get_resource_api_key(
        workloadIdentityToken=token,
        resourceCredentialProviderName=provider_name,
    )
    assert fetched["apiKey"] == secret_value, (
        "GetResourceApiKey did not return the exact secret registered with the credential "
        "provider -- the service must be looking it up, not fabricating a value"
    )

    # Negative: GetResourceApiKey rejects a syntactically-valid but bogus workload token.
    bad_token_code, bad_token_message = _error(lambda: data.get_resource_api_key(
        workloadIdentityToken="not-a-real-workload-identity-token." + uuid.uuid4().hex,
        resourceCredentialProviderName=provider_name,
    ))
    assert bad_token_code == "AccessDeniedException", (
        f"expected AccessDeniedException for a bogus workload identity token, got {bad_token_code!r}"
    )
    assert bad_token_message == "Invalid workload access token", (
        f"expected message 'Invalid workload access token', got {bad_token_message!r}"
    )

    # Negative: CompleteResourceTokenAuth rejects a well-formed but never-issued sessionUri.
    # This session was never created by any InitiateResourceTokenAuth-style flow tied to our
    # caller identity, so the service must refuse to complete it -- it must NOT silently treat
    # an unrecognized/foreign session URI as a completed authorization.
    bogus_session_uri = "urn:ietf:params:oauth:request_uri:" + uuid.uuid4().hex
    complete_code, complete_message = _error(lambda: data.complete_resource_token_auth(
        userIdentifier={"userId": "sim2real-test"},
        sessionUri=bogus_session_uri,
    ))
    assert complete_code == "AccessDeniedException", (
        f"expected AccessDeniedException for a never-issued sessionUri, got {complete_code!r}"
    )
    assert complete_message == "Invalid or expired session", (
        f"expected message 'Invalid or expired session', got {complete_message!r}"
    )

    # Confirm the earlier, genuinely valid secret retrieval still works (real effect present).
    still_fetched = data.get_resource_api_key(
        workloadIdentityToken=token,
        resourceCredentialProviderName=provider_name,
    )
    assert still_fetched["apiKey"] == secret_value, (
        f"expected the still-valid token to keep returning {secret_value!r}, got "
        f"{still_fetched['apiKey']!r} -- the earlier negatives must not have corrupted state"
    )


def _error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
