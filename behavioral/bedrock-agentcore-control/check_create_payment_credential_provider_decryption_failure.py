"""create-payment-credential-provider-decryption-failure."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from behavioral_harness import tags

CHECK = "create-payment-credential-provider-decryption-failure"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]

_RESTORE_BUDGET_S = 60.0
_POLL_S = 3.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePaymentCredentialProvider (StripePrivy, EXTERNAL secret) succeeds with its KMS key enabled, fails with
    DecryptionFailure and its exact message leaving no provider once the key is disabled, and the identical call
    succeeds again after the key is re-enabled."""
    control = ctx.client("bedrock-agentcore-control")
    kms = ctx.client("kms")
    secretsmanager = ctx.client("secretsmanager")

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-paycred-kms-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: _retire_key(kms, key_id))

    secret = secretsmanager.create_secret(
        Name=ctx.unique_name("sim2real-paycred-secret-"),
        KmsKeyId=key_id,
        SecretString=json.dumps({"appSecret": "real-privy-app-secret-value"}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    def _create_kwargs(name: str) -> dict:
        return dict(
            name=name,
            credentialProviderVendor="StripePrivy",
            providerConfigurationInput={
                "stripePrivyConfiguration": {
                    "appId": "dummy-privy-app-id",
                    "authorizationId": "dummy-authz-id",
                    "appSecretSource": "EXTERNAL",
                    "appSecretConfig": {"secretId": secret_arn, "jsonKey": "appSecret"},
                    # MANAGED and required whenever unspecified; irrelevant to the KMS/appSecret
                    # decrypt path under test, but the call is rejected up front without it.
                    "authorizationPrivateKey": _p256_key(),
                }
            },
            tags={"sim2real": CHECK},
        )

    # --- POSITIVE CONTROL: this exact wiring (EXTERNAL secret, enabled key) succeeds.
    ctrl_name = ctx.unique_name("sim2real-paycred-ctrl-")
    ctrl_created = control.create_payment_credential_provider(**_create_kwargs(ctrl_name))
    ctx.on_cleanup(lambda: _best_effort_delete(control, ctrl_name))
    assert ctrl_created["name"] == ctrl_name, (
        f"positive control: expected name {ctrl_name!r}, got {ctrl_created.get('name')!r}"
    )
    ctrl_got = control.get_payment_credential_provider(name=ctrl_name)
    assert ctrl_got["name"] == ctrl_name, (
        f"positive control: GetPaymentCredentialProvider returned {ctrl_got.get('name')!r}, "
        f"want {ctrl_name!r}"
    )

    # --- Break exactly one thing: disable the CMK protecting the EXTERNAL secret.
    kms.disable_key(KeyId=key_id)
    key_state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert key_state == "Disabled", f"DisableKey returned but DescribeKey reports {key_state!r}"

    bad_name = ctx.unique_name("sim2real-paycred-bad-")
    bad_kwargs = _create_kwargs(bad_name)
    code, message = _error_detail(lambda: control.create_payment_credential_provider(**bad_kwargs))
    assert code == "DecryptionFailure", f"expected DecryptionFailure, got {code}"
    expected_message = "Unable to decrypt the provided secret. Verify KMS key permissions."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no provider was created under that name.
    code2, message2 = _error_detail(lambda: control.get_payment_credential_provider(name=bad_name))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected_message2 = "PaymentCredentialProvider not found"
    assert message2 == expected_message2, f"expected message {expected_message2!r}, got {message2!r}"

    # --- Restore, and prove the IDENTICAL call (same dict, not a re-derived one) now
    # succeeds. Key-state propagation on the decrypt path is not instantaneous and exposes no
    # "is this effective yet" API, so this is a bounded retry of the identical call, not a
    # fixed sleep.
    kms.enable_key(KeyId=key_id)
    ctx.on_cleanup(lambda: _best_effort_delete(control, bad_name))
    deadline = time.monotonic() + _RESTORE_BUDGET_S
    restored = None
    last_code = None
    while time.monotonic() < deadline:
        try:
            restored = control.create_payment_credential_provider(**bad_kwargs)
            break
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code != "DecryptionFailure":
                raise
            time.sleep(_POLL_S)
    assert restored is not None, (
        f"the identical create call still fails ({last_code}) {_RESTORE_BUDGET_S:.0f}s after "
        "re-enabling the CMK -- the earlier failure was not actually tied to the key's state"
    )
    assert restored["name"] == bad_name, f"expected name {bad_name!r}, got {restored.get('name')!r}"

    got = control.get_payment_credential_provider(name=bad_name)
    assert got["name"] == bad_name, (
        f"GetPaymentCredentialProvider returned name {got.get('name')!r}, want {bad_name!r}"
    )


def _p256_key() -> str:
    """Base64-encoded DER/PKCS8 EC P-256 private key -- the shape StripePrivy's
    authorizationPrivateKey validates against regardless of source, once decryption of the
    EXTERNAL secret it gates has already succeeded."""
    key = ec.generate_private_key(ec.SECP256R1())
    der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(der).decode("ascii")


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _retire_key(kms, key_id: str) -> None:
    """Re-enable then schedule deletion, so a mid-check failure never leaves a disabled key
    behind."""
    try:
        kms.enable_key(KeyId=key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _best_effort_delete(control, name: str) -> None:
    try:
        control.delete_payment_credential_provider(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
