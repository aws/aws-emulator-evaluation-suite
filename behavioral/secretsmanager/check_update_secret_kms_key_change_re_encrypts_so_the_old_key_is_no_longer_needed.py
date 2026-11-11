"""update-secret-kms-key-change-re-encrypts-so-the-old-key-is-no-longer-needed."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-secret-kms-key-change-re-encrypts-so-the-old-key-is-no-longer-needed"
GROUP = "server-side"
SERVICES = ["secretsmanager"]


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _key(ctx, kms):
    """A fresh symmetric CMK, scheduled for deletion at teardown."""
    arn = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-smkey-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _secret(ctx, sm, **kwargs):
    name = ctx.unique_name("sim2real-behav-secret-")
    arn = sm.create_secret(Name=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}], **kwargs)["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    return arn


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateSecret changing only KmsKeyId re-encrypts under the new key: with the old key disabled
    the value still decrypts, and with the new key disabled GetSecretValue fails DecryptionFailure.
    """
    kms = ctx.client("kms")
    sm = ctx.client("secretsmanager")
    old_key, new_key = _key(ctx, kms), _key(ctx, kms)
    arn = _secret(ctx, sm, KmsKeyId=old_key, SecretString="value-under-the-first-key")

    sm.update_secret(SecretId=arn, KmsKeyId=new_key)
    described = sm.describe_secret(SecretId=arn)
    assert described.get("KmsKeyId") == new_key, (
        f"DescribeSecret must name the new key {new_key!r}, got {described.get('KmsKeyId')!r}"
    )
    kms.disable_key(KeyId=old_key)
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=old_key))
    _await_disabled(kms, old_key)
    value = sm.get_secret_value(SecretId=arn)["SecretString"]
    assert value == "value-under-the-first-key", (
        f"with the old key disabled the secret must still decrypt to its value, got {value!r}"
    )
    code, message = _error(lambda: sm.get_secret_value(SecretId=arn, VersionStage="AWSPENDING"))
    assert code == "ResourceNotFoundException", f"the key change left an AWSPENDING version: {code!r}"
    assert message == (
        "Secrets Manager can't find the specified secret value for staging label: AWSPENDING"
    ), f"unexpected message {message!r}"

    kms.disable_key(KeyId=new_key)
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=new_key))
    _await_disabled(kms, new_key)
    deadline = time.monotonic() + 180
    while True:  # the service may serve a cached data key briefly after the disable
        try:
            sm.get_secret_value(SecretId=arn)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            break
        assert time.monotonic() < deadline, "the secret still decrypts 180s after its key was disabled"
        time.sleep(3.0)
    assert code == "DecryptionFailure", (
        f"with the NEW key disabled GetSecretValue must fail DecryptionFailure, got {code!r}"
    )
    # message varies: it embeds the downstream KMS call's request id.



def _await_disabled(kms, key, timeout_s=120.0):
    """Poll Encrypt under the key until KMS refuses it: disabling a key propagates, it is not instant."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kms.encrypt(KeyId=key, Plaintext=b"probe")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DisabledException":
                return
            raise
        assert time.monotonic() < deadline, f"key {key} still encrypts {timeout_s}s after disable"
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

