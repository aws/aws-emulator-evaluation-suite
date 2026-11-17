"""encapsulate-decapsulate-dry-run-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "encapsulate-decapsulate-dry-run-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]

MSG_DRY_RUN = "The request would have succeeded, but the DryRun option is set."


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Encapsulate and Decapsulate with DryRun=True fail with DryRunOperationException and the
    exact message, without returning a shared secret; the identical calls without DryRun succeed."""
    kms = ctx.client("kms")
    key_meta = kms.create_key(
        Description=ctx.unique_name("kms-ml-kem-"),
        KeyUsage="ENCAPSULATE_DECAPSULATE",
        KeySpec="ML_KEM_768",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-encapsulate-decapsulate-dry-run-rejected"}],
    )["KeyMetadata"]
    key_id = key_meta["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    code, message = _error(
        lambda: kms.encapsulate(KeyId=key_id, EncapsulationAlgorithm="ML_KEM", DryRun=True)
    )
    assert code == "DryRunOperationException", f"Expected DryRunOperationException, got {code!r}"
    assert message == MSG_DRY_RUN, f"unexpected message: {message!r}"

    encapsulated = kms.encapsulate(KeyId=key_id, EncapsulationAlgorithm="ML_KEM")
    ciphertext = encapsulated["SharedSecretCiphertextBlob"]

    code, message = _error(
        lambda: kms.decapsulate(
            KeyId=key_id,
            SharedSecretCiphertextBlob=ciphertext,
            EncapsulationAlgorithm="ML_KEM",
            DryRun=True,
        )
    )
    assert code == "DryRunOperationException", f"Expected DryRunOperationException, got {code!r}"
    assert message == MSG_DRY_RUN, f"unexpected message: {message!r}"

    decapsulated = kms.decapsulate(
        KeyId=key_id, SharedSecretCiphertextBlob=ciphertext, EncapsulationAlgorithm="ML_KEM"
    )
    assert decapsulated["SharedSecret"] == encapsulated["SharedSecret"], (
        "the identical call without DryRun must succeed and recover the shared secret"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
