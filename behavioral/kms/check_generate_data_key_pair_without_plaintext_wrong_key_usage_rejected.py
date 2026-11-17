"""generate-data-key-pair-without-plaintext-wrong-key-usage-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generate-data-key-pair-without-plaintext-wrong-key-usage-rejected"
GROUP = "data_keys"
SERVICES = ["kms"]


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateDataKeyPairWithoutPlaintext on a SIGN_VERIFY key fails InvalidKeyUsageException
    without producing a key pair; the identical call on an ENCRYPT_DECRYPT key succeeds."""
    kms = ctx.client("kms")

    sign_key = kms.create_key(
        Description=ctx.unique_name("kms-gdkpwp-wrongusage-sign-"),
        KeyUsage="SIGN_VERIFY",
        KeySpec="RSA_2048",
    )["KeyMetadata"]
    sign_key_id, sign_key_arn = sign_key["KeyId"], sign_key["Arn"]
    ctx.on_cleanup(lambda _k=sign_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    code, message = _error(
        lambda: kms.generate_data_key_pair_without_plaintext(KeyId=sign_key_id, KeyPairSpec="ECC_NIST_P256")
    )
    assert code == "InvalidKeyUsageException", f"expected InvalidKeyUsageException, got {code}"
    expected_message = (
        f"{sign_key_arn} key usage is SIGN_VERIFY which is not valid for "
        "GenerateDataKeyPairWithoutPlaintext."
    )
    assert message == expected_message, f"unexpected message {message!r}"

    # positive control: the identical call succeeds on an ENCRYPT_DECRYPT key
    encrypt_key_id = kms.create_key(
        Description=ctx.unique_name("kms-gdkpwp-wrongusage-enc-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=encrypt_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    resp = kms.generate_data_key_pair_without_plaintext(KeyId=encrypt_key_id, KeyPairSpec="ECC_NIST_P256")
    assert resp["KeyPairSpec"] == "ECC_NIST_P256", (
        f"positive control: expected KeyPairSpec ECC_NIST_P256, got {resp['KeyPairSpec']!r}"
    )
    assert "PrivateKeyCiphertextBlob" in resp, (
        f"positive control: expected PrivateKeyCiphertextBlob in response, got keys {list(resp)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
