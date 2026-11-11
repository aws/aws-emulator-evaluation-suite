"""delete-payment-credential-provider-nonexistent-not-found."""
from __future__ import annotations

import base64
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-payment-credential-provider-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For a never-created name GetPaymentCredentialProvider answers ResourceNotFoundException while two
    DeletePaymentCredentialProvider calls succeed; creates with an unknown vendor or a non-genuine CoinbaseCDP key
    are refused with their exact ValidationException messages and leave no provider."""
    client = ctx.client("bedrock-agentcore-control")

    fake_name = ctx.unique_name("sim2real-paycred-missing-")

    # The provider genuinely does not exist: Get correctly reports not-found.
    get_code, get_message = _error_detail(lambda: client.get_payment_credential_provider(name=fake_name))
    assert get_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {get_code}"
    expected_get_message = "PaymentCredentialProvider not found"
    assert get_message == expected_get_message, f"expected message {expected_get_message!r}, got {get_message!r}"

    # Delete on that same nonexistent name is idempotent -- it does not raise.
    client.delete_payment_credential_provider(name=fake_name)

    # Repeating it stays a no-op: this is true idempotency, not a one-shot fluke.
    client.delete_payment_credential_provider(name=fake_name)

    # Boundary control: an out-of-enum vendor is rejected too, but with a distinct,
    # generic ValidationException -- proving the operation is reachable and doing real
    # request validation, not failing for an unrelated reason (auth, region, etc).
    bad_vendor_name = ctx.unique_name("sim2real-paycred-badvendor-")
    bad_vendor_code, bad_vendor_message = _error_detail(
        lambda: client.create_payment_credential_provider(
            name=bad_vendor_name,
            credentialProviderVendor="NotARealPaymentVendor",
            providerConfigurationInput={
                "coinbaseCdpConfiguration": {
                    "apiKeyId": "dummy-coinbase-key-id",
                    "apiKeySecret": _b64_key(),
                    "walletSecret": _b64_key(),
                }
            },
        )
    )
    assert bad_vendor_code == "ValidationException", f"expected ValidationException, got {bad_vendor_code}"
    expected_bad_vendor_message = "1 validation error detected: Value at 'credentialProviderVendor' failed to satisfy constraint: Member must satisfy enum value set: [Stripe, CoinbaseCDP, StripePrivy]"
    assert bad_vendor_message == expected_bad_vendor_message, f"expected message {expected_bad_vendor_message!r}, got {bad_vendor_message!r}"

    # The actual contract: a well-formed CoinbaseCDP request with a correctly-shaped but
    # non-genuine key is rejected with the specific key-authenticity ValidationException.
    fake_key_name = ctx.unique_name("sim2real-paycred-fakekey-")
    fake_key_code, fake_key_message = _error_detail(
        lambda: client.create_payment_credential_provider(
            name=fake_key_name,
            credentialProviderVendor="CoinbaseCDP",
            providerConfigurationInput={
                "coinbaseCdpConfiguration": {
                    "apiKeyId": "dummy-coinbase-key-id",
                    "apiKeySecret": _b64_key(),
                    "walletSecret": _b64_key(),
                }
            },
        )
    )
    assert fake_key_code == "ValidationException", f"expected ValidationException, got {fake_key_code}"
    expected_fake_key_message = "Invalid apiKeySecret format: Expected base64-encoded Ed25519 private key"
    assert fake_key_message == expected_fake_key_message, f"expected message {expected_fake_key_message!r}, got {fake_key_message!r}"

    # Effect absent: neither rejected create left a provider behind.
    for name in (bad_vendor_name, fake_key_name):
        code, message = _error_detail(lambda: client.get_payment_credential_provider(name=name))
        assert code == "ResourceNotFoundException", f"{name}: expected ResourceNotFoundException, got {code}"
        expected_message = "PaymentCredentialProvider not found"
        assert message == expected_message, f"{name}: expected message {expected_message!r}, got {message!r}"


def _b64_key(nbytes: int = 32) -> str:
    """Base64-encoded random bytes, matching the raw Ed25519 private-key-seed shape
    CreatePaymentCredentialProvider expects for apiKeySecret/walletSecret -- correctly
    shaped, but not authentic Coinbase-issued material."""
    return base64.b64encode(os.urandom(nbytes)).decode("ascii")


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
