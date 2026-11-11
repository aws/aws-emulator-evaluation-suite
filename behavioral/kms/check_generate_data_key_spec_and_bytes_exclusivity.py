"""generate-data-key-spec-and-bytes-exclusivity."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "generate-data-key-spec-and-bytes-exclusivity"
GROUP = 'data_keys'
SERVICES = ['kms']

ERR_VALIDATION = "ValidationException"
EXCLUSIVE_MESSAGE = "Please specify either number of bytes or key spec."
TOO_BIG_MESSAGE = (
    "1 validation error detected: Value '1025' at 'numberOfBytes' failed to satisfy constraint: "
    "Member must have value less than or equal to 1024"
)


def _client_error(fn):
    """Return the botocore Error if fn() raises ClientError; raise if fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7-day minimum window).

    The ARN guard keeps this teardown off AWS-managed keys and aliases.
    """
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateDataKey's KeySpec and NumberOfBytes are mutually exclusive and jointly required,
    and the returned Plaintext has the requested length and is what CiphertextBlob decrypts to.

    Reference: https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-dkspec-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))

    ok = kms.generate_data_key(KeyId=key_arn, KeySpec="AES_256")
    assert len(ok["Plaintext"]) == 32, len(ok["Plaintext"])
    assert ok["KeyId"] == key_arn, ok["KeyId"]
    # The pair must be genuinely related, not two independent random blobs.
    assert (
        kms.decrypt(CiphertextBlob=ok["CiphertextBlob"], KeyId=key_arn)["Plaintext"]
        == ok["Plaintext"]
    ), "GenerateDataKey's CiphertextBlob must decrypt to exactly its Plaintext"

    # KeySpec/NumberOfBytes are not `required` in the model, so botocore forwards these to KMS.
    # ValidationException is not a modelled KMS error shape, yet KMS returns it.
    both = _client_error(
        lambda: kms.generate_data_key(KeyId=key_arn, KeySpec="AES_256", NumberOfBytes=32)
    )
    assert both["Code"] == ERR_VALIDATION, (
        f"KeySpec and NumberOfBytes together must raise {ERR_VALIDATION}, got {both!r}"
    )
    assert both["Message"] == EXCLUSIVE_MESSAGE, (
        f"expected message {EXCLUSIVE_MESSAGE!r}, got {both['Message']!r}"
    )

    neither = _client_error(lambda: kms.generate_data_key(KeyId=key_arn))
    assert neither["Code"] == ERR_VALIDATION, (
        f"neither KeySpec nor NumberOfBytes must raise {ERR_VALIDATION}, got {neither!r}"
    )
    assert neither["Message"] == EXCLUSIVE_MESSAGE, (
        f"expected message {EXCLUSIVE_MESSAGE!r}, got {neither['Message']!r}"
    )

    # NumberOfBytesType is range 1..1024, so 1025 is above the modelled max and reaches the
    # server; 0 is below the min and botocore rejects it client-side.
    too_big = _client_error(lambda: kms.generate_data_key(KeyId=key_arn, NumberOfBytes=1025))
    assert too_big["Code"] == ERR_VALIDATION, (
        f"NumberOfBytes=1025 (max is 1024) must raise {ERR_VALIDATION}, got {too_big!r}"
    )
    assert too_big["Message"] == TOO_BIG_MESSAGE, (
        f"expected message {TOO_BIG_MESSAGE!r}, got {too_big['Message']!r}"
    )

    # The same rules hold on the WithoutPlaintext variant.
    both_wp = _client_error(
        lambda: kms.generate_data_key_without_plaintext(
            KeyId=key_arn, KeySpec="AES_256", NumberOfBytes=32
        )
    )
    assert both_wp["Code"] == ERR_VALIDATION, (
        f"GenerateDataKeyWithoutPlaintext with both must raise {ERR_VALIDATION}, "
        f"got {both_wp!r}"
    )
    assert both_wp["Message"] == EXCLUSIVE_MESSAGE, (
        f"expected message {EXCLUSIVE_MESSAGE!r}, got {both_wp['Message']!r}"
    )
    neither_wp = _client_error(lambda: kms.generate_data_key_without_plaintext(KeyId=key_arn))
    assert neither_wp["Code"] == ERR_VALIDATION, (
        f"GenerateDataKeyWithoutPlaintext with neither must raise {ERR_VALIDATION}, "
        f"got {neither_wp!r}"
    )
    assert neither_wp["Message"] == EXCLUSIVE_MESSAGE, (
        f"expected message {EXCLUSIVE_MESSAGE!r}, got {neither_wp['Message']!r}"
    )

    # The refusals left the key fully functional.
    exact = kms.generate_data_key(KeyId=key_arn, NumberOfBytes=64)
    assert len(exact["Plaintext"]) == 64, len(exact["Plaintext"])
    round_trip = kms.decrypt(CiphertextBlob=exact["CiphertextBlob"], KeyId=key_arn)["Plaintext"]
    assert round_trip == exact["Plaintext"], (
        "GenerateDataKey(NumberOfBytes=64)'s CiphertextBlob must decrypt to exactly its Plaintext"
    )

    # AES_128 must be exactly 16 bytes.
    small = kms.generate_data_key(KeyId=key_arn, KeySpec="AES_128")
    assert len(small["Plaintext"]) == 16, len(small["Plaintext"])
    assert small["Plaintext"] != exact["Plaintext"], "data keys must be freshly random"

    # WithoutPlaintext must omit Plaintext entirely — not return it empty.
    wp = kms.generate_data_key_without_plaintext(KeyId=key_arn, KeySpec="AES_256")
    assert "Plaintext" not in wp, sorted(wp)
    wp_decrypted_len = len(kms.decrypt(CiphertextBlob=wp["CiphertextBlob"], KeyId=key_arn)["Plaintext"])
    assert wp_decrypted_len == 32, wp_decrypted_len

    after = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    assert after["KeyState"] == "Enabled", after["KeyState"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
