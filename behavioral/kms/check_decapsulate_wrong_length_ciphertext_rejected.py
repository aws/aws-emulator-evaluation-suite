"""decapsulate-wrong-length-ciphertext-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "decapsulate-wrong-length-ciphertext-rejected"
GROUP = "key_agreement"
SERVICES = ["kms"]


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success fails too."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Decapsulate rejects a SharedSecretCiphertextBlob whose length does not match the ML-KEM
    key spec, and the same key still decapsulates a correctly sized ciphertext afterward.
    """
    kms = ctx.client("kms")

    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-mlkemneg-"),
        KeyUsage="ENCAPSULATE_DECAPSULATE",
        KeySpec="ML_KEM_512",
        Tags=[{"TagKey": "sim2real-behav", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    good_ciphertext = kms.encapsulate(KeyId=key_id, EncapsulationAlgorithm="ML_KEM")[
        "SharedSecretCiphertextBlob"
    ]
    truncated = good_ciphertext[:-1]
    _WRONG_LENGTH = (
        "InvalidCiphertextException",
        f"SharedSecretCiphertextBlob length mismatch for ML_KEM_512 KeySpec: expected "
        f"{len(good_ciphertext)} bytes, got {len(truncated)} bytes.",
    )

    expect_error(
        lambda: kms.decapsulate(
            KeyId=key_id,
            SharedSecretCiphertextBlob=truncated,
            EncapsulationAlgorithm="ML_KEM",
        ),
        *_WRONG_LENGTH,
    )

    control = kms.decapsulate(
        KeyId=key_id,
        SharedSecretCiphertextBlob=good_ciphertext,
        EncapsulationAlgorithm="ML_KEM",
    )
    assert len(control["SharedSecret"]) == 32, (
        f"control Decapsulate SharedSecret length: {len(control['SharedSecret'])}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
