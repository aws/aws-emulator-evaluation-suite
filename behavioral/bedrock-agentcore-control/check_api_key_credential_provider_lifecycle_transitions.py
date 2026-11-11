"""api-key-credential-provider-lifecycle-transitions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "api-key-credential-provider-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ApiKeyCredentialProvider create->update->delete; the provider is both unresolvable
    and no longer mutable after delete."""
    client = ctx.client("bedrock-agentcore-control")
    name = _alnum_name(ctx, "sim2reals3akcp")

    created = client.create_api_key_credential_provider(
        name=name,
        apiKey="initial-api-key-value-0001",
    )
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, name))
    assert created["name"] == name, f"expected name {name!r}, got {created['name']!r}"
    provider_arn = created["credentialProviderArn"]
    assert provider_arn.endswith(f"/apikeycredentialprovider/{name}"), (
        f"expected ARN ending in /apikeycredentialprovider/{name}, got {provider_arn!r}"
    )

    got = client.get_api_key_credential_provider(name=name)
    assert got["credentialProviderArn"] == provider_arn, (
        f"expected credentialProviderArn {provider_arn!r}, got {got['credentialProviderArn']!r}"
    )
    created_time = got["createdTime"]

    updated = client.update_api_key_credential_provider(
        name=name,
        apiKey="rotated-api-key-value-0002",
    )
    assert updated["credentialProviderArn"] == provider_arn, (
        f"expected credentialProviderArn {provider_arn!r}, got {updated['credentialProviderArn']!r}"
    )
    got_after_update = client.get_api_key_credential_provider(name=name)
    assert got_after_update["lastUpdatedTime"] >= created_time, (
        f"expected lastUpdatedTime >= {created_time!r}, got {got_after_update['lastUpdatedTime']!r}"
    )

    client.delete_api_key_credential_provider(name=name)

    get_code, get_message = _error_detail(lambda: client.get_api_key_credential_provider(name=name))
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from Get after delete, got {get_code!r}"
    )
    expected_get_message = f"ApiKeyCredentialProvider not found for {name}"
    assert get_message == expected_get_message, (
        f"expected message {expected_get_message!r}, got {get_message!r}"
    )

    update_code, update_message = _error_detail(
        lambda: client.update_api_key_credential_provider(
            name=name, apiKey="post-delete-api-key-value-0003"
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from Update on a deleted provider, got {update_code!r}"
    )
    expected_update_message = "ApiKey CredentialProvider not found"
    assert update_message == expected_update_message, (
        f"expected message {expected_update_message!r}, got {update_message!r}"
    )


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch in "-_")


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_ignore_not_found(client, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        client.delete_api_key_credential_provider(name=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
