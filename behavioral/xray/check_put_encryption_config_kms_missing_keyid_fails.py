"""put-encryption-config-kms-missing-keyid-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-encryption-config-kms-missing-keyid-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


EXPECTED_MESSAGE = "Key ID is required for type KMS"


def _error(fn):
    """-> (code, message) of the ClientError `fn` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:xray-encryption")
def run(ctx) -> None:
    """PutEncryptionConfig with Type KMS and no KeyId fails with InvalidRequestException "Key ID
    is required for type KMS" and leaves the encryption Type and KeyId as they were."""
    xr = ctx.client("xray")
    original = xr.get_encryption_config()["EncryptionConfig"]

    code, message = _error(lambda: xr.put_encryption_config(Type="KMS"))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException, got {code} ({message!r})"
    )
    assert message == EXPECTED_MESSAGE, f"MESSAGE={message!r}"

    # The rejected change must not have taken effect.
    unchanged = xr.get_encryption_config()["EncryptionConfig"]
    assert unchanged.get("Type") == original.get("Type"), (
        f"encryption type unexpectedly changed from {original.get('Type')} to {unchanged.get('Type')}"
    )
    assert unchanged.get("KeyId") == original.get("KeyId"), (
        f"encryption KeyId unexpectedly changed from {original.get('KeyId')} to {unchanged.get('KeyId')}"
    )

    # Positive control (read-only, so it can't race with a concurrently running check that
    # mutates this same singleton): GetEncryptionConfig itself still succeeds and reports a
    # settled status in the same run, so the rejection is attributable to the missing KeyId and
    # not to the account/service being generally unreachable.
    assert unchanged.get("Status") in ("ACTIVE", "UPDATING"), unchanged


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
