"""delete-api-key-credential-provider-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-api-key-credential-provider-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """For a never-created name GetApiKeyCredentialProvider answers ResourceNotFoundException with its exact message
    while DeleteApiKeyCredentialProvider succeeds twice and leaves a real provider intact; once the real one is
    deleted, Get and Update answer ResourceNotFoundException with their exact messages."""
    client = ctx.client("bedrock-agentcore-control")

    real_name = ctx.unique_name("sim2real-apikeycred-")
    client.create_api_key_credential_provider(
        name=real_name,
        apiKey="dummy-api-key-value-123",
        tags={"env": "sim2real-test", "purpose": "delete-nonexistent-not-found"},
    )
    ctx.on_cleanup(lambda: _best_effort_delete(client, real_name))

    fake_name = ctx.unique_name("sim2real-apikeycred-missing-")

    # The provider genuinely does not exist: Get correctly reports not-found.
    get_code, get_message = _error_detail(lambda: client.get_api_key_credential_provider(name=fake_name))
    assert get_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {get_code}"
    expected_get_message = f"ApiKeyCredentialProvider not found for {fake_name}"
    assert get_message == expected_get_message, f"expected message {expected_get_message!r}, got {get_message!r}"

    # But Delete on that same nonexistent name is idempotent -- it does not raise.
    client.delete_api_key_credential_provider(name=fake_name)

    # Idempotency: calling delete again on the still-nonexistent name is also a no-op.
    client.delete_api_key_credential_provider(name=fake_name)

    # Effect absent / unaffected: the real provider is still present.
    got = client.get_api_key_credential_provider(name=real_name)
    assert got["name"] == real_name, f"expected {real_name}, got {got['name']}"

    # Positive control: deleting the real provider succeeds.
    client.delete_api_key_credential_provider(name=real_name)
    code2, message2 = _error_detail(lambda: client.get_api_key_credential_provider(name=real_name))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected_message2 = f"ApiKeyCredentialProvider not found for {real_name}"
    assert message2 == expected_message2, f"expected message {expected_message2!r}, got {message2!r}"

    # Gone-and-unusable: a mutation on the now-deleted id also fails, not just the read.
    update_code, update_message = _error_detail(
        lambda: client.update_api_key_credential_provider(name=real_name, apiKey="post-delete-value")
    )
    assert update_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {update_code}"
    expected_update_message = "ApiKey CredentialProvider not found"
    assert update_message == expected_update_message, f"expected message {expected_update_message!r}, got {update_message!r}"


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _best_effort_delete(client, name: str) -> None:
    try:
        client.delete_api_key_credential_provider(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
