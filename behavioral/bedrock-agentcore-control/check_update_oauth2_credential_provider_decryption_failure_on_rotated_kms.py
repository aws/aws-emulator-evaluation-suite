"""update-oauth2-credential-provider-decryption-failure-on-rotated-kms."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-oauth2-credential-provider-decryption-failure-on-rotated-kms"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Rotating an EXTERNAL OAuth2 credential provider onto a new secret whose KMS key is disabled
    fails and leaves the provider unchanged; re-enabling the key makes the identical rotation
    succeed, and an unrelated provider can still be created throughout (positive control)."""
    control = ctx.client("bedrock-agentcore-control")
    kms = ctx.client("kms")
    secretsmanager = ctx.client("secretsmanager")

    initial_key = kms.create_key(Description=ctx.unique_name("sim2real-oauth2cred-kms-init-"))["KeyMetadata"]
    initial_key_id = initial_key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=initial_key_id, PendingWindowInDays=7))

    initial_secret = secretsmanager.create_secret(
        Name=ctx.unique_name("sim2real-oauth2cred-secret-init-"),
        KmsKeyId=initial_key_id,
        SecretString=json.dumps({"clientSecret": "real-oauth-client-secret"}),
    )
    initial_secret_arn = initial_secret["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=initial_secret_arn, ForceDeleteWithoutRecovery=True))

    name = ctx.unique_name("sim2real-oauth2cred-")
    control.create_oauth2_credential_provider(
        name=name,
        credentialProviderVendor="GoogleOauth2",
        oauth2ProviderConfigInput={
            "googleOauth2ProviderConfig": {
                "clientId": "initial-client-id",
                "clientSecretSource": "EXTERNAL",
                "clientSecretConfig": {"secretId": initial_secret_arn, "jsonKey": "clientSecret"},
            }
        },
    )
    ctx.on_cleanup(lambda: _best_effort_delete(control, name))

    rotated_key = kms.create_key(Description=ctx.unique_name("sim2real-oauth2cred-kms-rot-"))["KeyMetadata"]
    rotated_key_id = rotated_key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=rotated_key_id, PendingWindowInDays=7))

    rotated_secret = secretsmanager.create_secret(
        Name=ctx.unique_name("sim2real-oauth2cred-secret-rot-"),
        KmsKeyId=rotated_key_id,
        SecretString=json.dumps({"clientSecret": "real-rotated-oauth-client-secret"}),
    )
    rotated_secret_arn = rotated_secret["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=rotated_secret_arn, ForceDeleteWithoutRecovery=True))

    kms.disable_key(KeyId=rotated_key_id)

    def _rotate():
        return control.update_oauth2_credential_provider(
            name=name,
            credentialProviderVendor="GoogleOauth2",
            oauth2ProviderConfigInput={
                "googleOauth2ProviderConfig": {
                    "clientId": "rotated-client-id",
                    "clientSecretSource": "EXTERNAL",
                    "clientSecretConfig": {"secretId": rotated_secret_arn, "jsonKey": "clientSecret"},
                }
            },
        )

    code, message = _client_error(_rotate)
    assert code == "DecryptionFailure", f"expected DecryptionFailure, got {code}"
    expected_message = "Unable to decrypt the provided secret. Verify KMS key permissions."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the provider's stored clientId is unchanged by the failed update.
    got = control.get_oauth2_credential_provider(name=name)
    stored_client_id = got["oauth2ProviderConfigOutput"]["googleOauth2ProviderConfig"]["clientId"]
    assert stored_client_id == "initial-client-id", f"update should not have applied, got {stored_client_id}"

    # Restore: re-enabling the key makes the identical rotation succeed, proving the
    # earlier rejection was specifically about the key being unusable, not the EXTERNAL path itself.
    kms.enable_key(KeyId=rotated_key_id)
    _rotate()
    got_restored = control.get_oauth2_credential_provider(name=name)
    restored_client_id = got_restored["oauth2ProviderConfigOutput"]["googleOauth2ProviderConfig"]["clientId"]
    assert restored_client_id == "rotated-client-id", (
        f"expected rotated-client-id after re-enabling the key, got {restored_client_id}"
    )

    # Positive control: a fresh, unrelated MANAGED-secret provider still creates fine --
    # proves CreateOauth2CredentialProvider itself is healthy in this account/run.
    good_name = ctx.unique_name("sim2real-oauth2cred-good-")
    control.create_oauth2_credential_provider(
        name=good_name,
        credentialProviderVendor="GoogleOauth2",
        oauth2ProviderConfigInput={
            "googleOauth2ProviderConfig": {
                "clientId": "good-client-id",
                "clientSecretSource": "MANAGED",
                "clientSecret": "good-managed-secret-value",
            }
        },
    )
    ctx.on_cleanup(lambda: _best_effort_delete(control, good_name))
    got2 = control.get_oauth2_credential_provider(name=good_name)
    good_client_id = got2["oauth2ProviderConfigOutput"]["googleOauth2ProviderConfig"]["clientId"]
    assert good_client_id == "good-client-id", f"expected good-client-id, got {good_client_id}"


# ===== helpers =====
def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises: a target
    accepting a call real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _best_effort_delete(control, name: str) -> None:
    try:
        control.delete_oauth2_credential_provider(name=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
