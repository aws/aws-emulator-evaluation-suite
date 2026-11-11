"""payment-credential-provider-lifecycle-transitions."""
from __future__ import annotations

import base64
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "payment-credential-provider-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PaymentCredentialProvider create->update->delete; both a read and a mutation on the
    deleted name come back ResourceNotFoundException."""
    client = ctx.client("bedrock-agentcore-control")
    name = _alnum_name(ctx, "sim2reals3pcp")

    created = client.create_payment_credential_provider(
        name=name,
        credentialProviderVendor="CoinbaseCDP",
        providerConfigurationInput={
            "coinbaseCdpConfiguration": {
                "apiKeyId": "sim2real-coinbase-api-key-id-0001",
                "apiKeySecret": _ed25519_key(),
                "walletSecret": _p256_key(),
            }
        },
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, name))
    provider_arn = created["credentialProviderArn"]
    assert provider_arn.endswith(f"/paymentcredentialprovider/{name}"), (
        f"expected ARN ending in /paymentcredentialprovider/{name}, got {provider_arn!r}"
    )
    assert created["credentialProviderVendor"] == "CoinbaseCDP", (
        f"expected vendor CoinbaseCDP, got {created['credentialProviderVendor']!r}"
    )

    got = client.get_payment_credential_provider(name=name)
    created_time = got["createdTime"]

    updated = client.update_payment_credential_provider(
        name=name,
        credentialProviderVendor="CoinbaseCDP",
        providerConfigurationInput={
            "coinbaseCdpConfiguration": {
                "apiKeyId": "sim2real-coinbase-api-key-id-0002-rotated",
                "apiKeySecret": _ed25519_key(),
                "walletSecret": _p256_key(),
            }
        },
    )
    assert updated["credentialProviderArn"] == provider_arn, (
        f"expected update to keep ARN {provider_arn!r}, got {updated['credentialProviderArn']!r}"
    )
    got_after_update = client.get_payment_credential_provider(name=name)
    assert got_after_update["lastUpdatedTime"] >= created_time, (
        f"expected lastUpdatedTime >= createdTime {created_time!r}, got {got_after_update['lastUpdatedTime']!r}"
    )

    client.delete_payment_credential_provider(name=name)

    code, message = _error(lambda: client.get_payment_credential_provider(name=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException on get, got {code!r}"
    expected = "PaymentCredentialProvider not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    update_code, update_message = _error(
        lambda: client.update_payment_credential_provider(
            name=name,
            credentialProviderVendor="CoinbaseCDP",
            providerConfigurationInput={
                "coinbaseCdpConfiguration": {
                    "apiKeyId": "sim2real-coinbase-api-key-id-0003-post-delete",
                    "apiKeySecret": _ed25519_key(),
                    "walletSecret": _p256_key(),
                }
            },
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected update on a deleted provider to fail ResourceNotFoundException, got {update_code!r}"
    )
    expected = f"PaymentCredentialProvider not found for name: {name}"
    assert update_message == expected, f"expected message {expected!r}, got {update_message!r}"


def _ed25519_key() -> str:
    return base64.b64encode(os.urandom(64)).decode("ascii")


def _p256_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return base64.b64encode(der).decode("ascii")


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch in "-_")


def _error(fn):
    """Return (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_ignore_not_found(client, name: str) -> None:
    try:
        client.delete_payment_credential_provider(name=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
