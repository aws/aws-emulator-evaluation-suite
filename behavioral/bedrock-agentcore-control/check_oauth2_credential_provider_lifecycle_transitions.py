"""oauth2-credential-provider-lifecycle-transitions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "oauth2-credential-provider-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Oauth2CredentialProvider create->update->delete; provider unresolvable after delete."""
    client = ctx.client("bedrock-agentcore-control")
    name = _alnum_name(ctx, "sim2reals3ocp")

    created = client.create_oauth2_credential_provider(
        name=name,
        credentialProviderVendor="GoogleOauth2",
        oauth2ProviderConfigInput={
            "googleOauth2ProviderConfig": {
                "clientId": "sim2real-test-client-id-0001",
                "clientSecret": "sim2real-test-client-secret-0001",
            }
        },
        tags={"sim2real": "oauth2-credential-provider-lifecycle-transitions"},
    )
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, name))
    provider_arn = created["credentialProviderArn"]
    assert provider_arn.endswith(f"/oauth2credentialprovider/{name}"), (
        f"expected ARN ending in /oauth2credentialprovider/{name}, got {provider_arn!r}"
    )
    assert created["name"] == name, f"expected name {name!r}, got {created['name']!r}"

    got = client.get_oauth2_credential_provider(name=name)
    assert got["credentialProviderVendor"] == "GoogleOauth2", (
        f"expected vendor GoogleOauth2, got {got['credentialProviderVendor']!r}"
    )
    created_time = got["createdTime"]

    updated = client.update_oauth2_credential_provider(
        name=name,
        credentialProviderVendor="GoogleOauth2",
        oauth2ProviderConfigInput={
            "googleOauth2ProviderConfig": {
                "clientId": "sim2real-test-client-id-0002-rotated",
                "clientSecret": "sim2real-test-client-secret-0002",
            }
        },
    )
    assert updated["credentialProviderArn"] == provider_arn, (
        f"expected update to keep ARN {provider_arn!r}, got {updated['credentialProviderArn']!r}"
    )
    got_after_update = client.get_oauth2_credential_provider(name=name)
    assert got_after_update["lastUpdatedTime"] > created_time, (
        f"expected lastUpdatedTime {got_after_update['lastUpdatedTime']} strictly after "
        f"createdTime {created_time} following an update"
    )

    client.delete_oauth2_credential_provider(name=name)

    code, message = _error(lambda: client.get_oauth2_credential_provider(name=name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted provider {name!r}, got {code!r}"
    )
    expected = "CredentialProvider not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    update_code, update_message = _error(
        lambda: client.update_oauth2_credential_provider(
            name=name,
            credentialProviderVendor="GoogleOauth2",
            oauth2ProviderConfigInput={
                "googleOauth2ProviderConfig": {
                    "clientId": "sim2real-test-client-id-post-delete",
                    "clientSecret": "sim2real-test-client-secret-post-delete",
                }
            },
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected update on deleted provider {name!r} to fail with ResourceNotFoundException, "
        f"got {update_code!r}"
    )
    expected = f"CredentialProvider not found for name: {name}"
    assert update_message == expected, f"expected message {expected!r}, got {update_message!r}"


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch in "-_")


def _error(fn):
    """Return (code, message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_ignore_not_found(client, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        client.delete_oauth2_credential_provider(name=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
