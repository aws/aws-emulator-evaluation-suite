"""create-api-key-credential-provider-decryption-failure-on-bad-secret."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-api-key-credential-provider-decryption-failure-on-bad-secret"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]

_TAGS = {"sim2real": "apikeycred-decryption-failure"}
_KMS_TAGS = [{"TagKey": "sim2real", "TagValue": "apikeycred-decryption-failure"}]
_SM_TAGS = [{"Key": "sim2real", "Value": "apikeycred-decryption-failure"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiKeyCredentialProvider on an EXTERNAL secret whose KMS key is disabled fails with DecryptionFailure
    and its exact message and leaves no provider; the identical call succeeds once the key is re-enabled, and a
    MANAGED key provider is created too."""
    control = ctx.client("bedrock-agentcore-control")
    kms = ctx.client("kms")
    secretsmanager = ctx.client("secretsmanager")

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-apikeycred-kms-"), Tags=_KMS_TAGS
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    secret = secretsmanager.create_secret(
        Name=ctx.unique_name("sim2real-apikeycred-secret-"),
        KmsKeyId=key_id,
        SecretString=json.dumps({"apiKey": "real-secret-api-key-value"}),
        Tags=_SM_TAGS,
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    kms.disable_key(KeyId=key_id)

    bad_name = ctx.unique_name("sim2real-apikeycred-bad-")

    def _create_bad():
        return control.create_api_key_credential_provider(
            name=bad_name,
            apiKeySecretSource="EXTERNAL",
            apiKeySecretConfig={"secretId": secret_arn, "jsonKey": "apiKey"},
            tags=_TAGS,
        )

    code, message = _error_detail(_create_bad)
    assert code == "DecryptionFailure", f"expected DecryptionFailure, got {code}"
    expected_message = "Unable to decrypt the provided secret. Verify KMS key permissions."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no provider was created under that name.
    code2, message2 = _error_detail(lambda: control.get_api_key_credential_provider(name=bad_name))
    assert code2 == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the never-created provider, got {code2}"
    )
    expected_message2 = f"ApiKeyCredentialProvider not found for {bad_name}"
    assert message2 == expected_message2, f"expected message {expected_message2!r}, got {message2!r}"

    # Restore: re-enable the SAME key and retry the IDENTICAL EXTERNAL/KMS-backed call.
    # Without this, "the disabled key caused DecryptionFailure" is indistinguishable from
    # "EXTERNAL secrets never work" -- the MANAGED positive control below never touches
    # KMS or Secrets Manager at all, so it cannot isolate which one made the difference.
    kms.enable_key(KeyId=key_id)
    restored = _poll_until_success(
        _create_bad, timeout_s=60.0, description="the identical EXTERNAL create to succeed once the key is re-enabled"
    )
    ctx.on_cleanup(lambda: _best_effort_delete(control, bad_name))
    assert restored["name"] == bad_name, f"restored create did not echo the name: {restored!r}"
    got_restored = control.get_api_key_credential_provider(name=bad_name)
    assert got_restored["name"] == bad_name, (
        f"the identical EXTERNAL/KMS-backed call did not become visible after the key was "
        f"re-enabled: {got_restored!r}"
    )

    # Positive control: a MANAGED secret (no external KMS/Secrets Manager dependency)
    # still succeeds, proving CreateApiKeyCredentialProvider itself works.
    good_name = ctx.unique_name("sim2real-apikeycred-good-")
    control.create_api_key_credential_provider(
        name=good_name, apiKey="a-plain-managed-api-key", tags=_TAGS
    )
    ctx.on_cleanup(lambda: _best_effort_delete(control, good_name))
    got = control.get_api_key_credential_provider(name=good_name)
    assert got["name"] == good_name


def _error_detail(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts input AWS refuses fails as an acceptance, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"the call was expected to be refused but it SUCCEEDED and returned {result!r}")


def _poll_until_success(fn, *, timeout_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while True:
        try:
            return fn()
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"waited {timeout_s}s for {description}; last error was {last_code!r}"
                ) from err
            time.sleep(3.0)


def _best_effort_delete(control, name: str) -> None:
    try:
        control.delete_api_key_credential_provider(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
