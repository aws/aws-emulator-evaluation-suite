"""api-key-credential-provider-secret-in-secrets-manager."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-key-credential-provider-secret-in-secrets-manager"
GROUP = "cross-service"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateApiKeyCredentialProvider stores the supplied API key in a real
    Secrets Manager secret, and a Secrets Manager GetSecretValue on the
    returned ARN yields that exact value."""
    control = ctx.client("bedrock-agentcore-control")
    secrets = ctx.client("secretsmanager")

    name = ctx.unique_name("sim2real-apikeycp-")
    api_key_value = f"sk-sim2real-{ctx.unique_name('secret')}"

    create_resp = control.create_api_key_credential_provider(
        name=name, apiKey=api_key_value, tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: control.delete_api_key_credential_provider(name=name))
    )

    secret_arn = create_resp["apiKeySecretArn"]["secretArn"]
    json_key = create_resp.get("apiKeySecretJsonKey")
    assert create_resp["apiKeySecretSource"] == "MANAGED", (
        f"expected a MANAGED secret source, got {create_resp['apiKeySecretSource']!r}"
    )

    # the control-plane Get should also confirm the same secret reference --
    # but the terminal assertion belongs at the consumer (Secrets Manager),
    # not back at the producer that issued it.
    fetched = control.get_api_key_credential_provider(name=name)
    assert fetched["apiKeySecretArn"]["secretArn"] == secret_arn, (
        f"GetApiKeyCredentialProvider secretArn {fetched['apiKeySecretArn']['secretArn']!r} "
        f"does not match the ARN returned by Create {secret_arn!r}"
    )

    secret_resp = secrets.get_secret_value(SecretId=secret_arn)
    secret_data = json.loads(secret_resp["SecretString"])
    if json_key:
        assert secret_data[json_key] == api_key_value, (
            f"Secrets Manager value at key {json_key!r} was {secret_data.get(json_key)!r}, "
            f"expected the created apiKey {api_key_value!r}"
        )
    else:
        assert api_key_value in secret_data.values(), (
            f"created apiKey {api_key_value!r} not found among Secrets Manager values "
            f"{list(secret_data.values())!r}"
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
