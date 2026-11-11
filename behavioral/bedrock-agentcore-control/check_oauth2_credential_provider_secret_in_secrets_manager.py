"""oauth2-credential-provider-secret-in-secrets-manager."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "oauth2-credential-provider-secret-in-secrets-manager"
GROUP = "cross-service"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateOauth2CredentialProvider stores the supplied client secret in a
    real Secrets Manager secret, retrievable via GetSecretValue on the
    returned ARN."""
    control = ctx.client("bedrock-agentcore-control")
    secrets = ctx.client("secretsmanager")

    name = ctx.unique_name("sim2real-oauth2cp-")
    client_secret_value = f"cs-sim2real-{ctx.unique_name('secret')}"

    create_resp = control.create_oauth2_credential_provider(
        name=name,
        credentialProviderVendor="CustomOauth2",
        oauth2ProviderConfigInput={
            "customOauth2ProviderConfig": {
                "oauthDiscovery": {
                    "discoveryUrl": "https://example.com/.well-known/openid-configuration"
                },
                "clientId": "sim2real-test-client-id",
                "clientSecret": client_secret_value,
            }
        },
        tags={"env": "sim2real-test", "purpose": CHECK},
    )
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: control.delete_oauth2_credential_provider(name=name))
    )

    secret_arn = create_resp["clientSecretArn"]["secretArn"]
    json_key = create_resp.get("clientSecretJsonKey")

    fetched = control.get_oauth2_credential_provider(name=name)
    assert fetched["clientSecretArn"]["secretArn"] == secret_arn, (
        f"get_oauth2_credential_provider secretArn {fetched['clientSecretArn']['secretArn']!r} "
        f"!= create response secretArn {secret_arn!r}"
    )
    assert fetched["credentialProviderVendor"] == "CustomOauth2", (
        f"expected credentialProviderVendor 'CustomOauth2', got "
        f"{fetched['credentialProviderVendor']!r}"
    )

    # Terminal read: the consumer (Secrets Manager), not the producer, must
    # independently confirm the secret bytes CreateOauth2CredentialProvider
    # claims it stored.
    secret_resp = secrets.get_secret_value(SecretId=secret_arn)
    secret_data = json.loads(secret_resp["SecretString"])
    if json_key:
        assert secret_data[json_key] == client_secret_value, (
            f"secret JSON key {json_key!r} holds {secret_data.get(json_key)!r}, "
            f"expected {client_secret_value!r}"
        )
    else:
        assert client_secret_value in secret_data.values(), (
            f"expected {client_secret_value!r} among secret values {list(secret_data.values())!r}"
        )


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
