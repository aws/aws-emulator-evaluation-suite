"""derive-shared-secret-wrong-key-usage-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "derive-shared-secret-wrong-key-usage-rejected"
GROUP = "sign_verify"
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
    """DeriveSharedSecret against a SIGN_VERIFY key fails InvalidKeyUsageException given a
    correctly-shaped peer public key; the identical algorithm and peer key succeed against a
    KEY_AGREEMENT key of the same curve."""
    kms = ctx.client("kms")

    sign_key = kms.create_key(
        Description=ctx.unique_name("kms-dss-wrongusage-sign-"),
        KeyUsage="SIGN_VERIFY",
        KeySpec="ECC_NIST_P256",
    )["KeyMetadata"]
    sign_key_id, sign_key_arn = sign_key["KeyId"], sign_key["Arn"]
    ctx.on_cleanup(lambda _k=sign_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    peer_key_id = kms.create_key(
        Description=ctx.unique_name("kms-dss-wrongusage-peer-"),
        KeyUsage="KEY_AGREEMENT",
        KeySpec="ECC_NIST_P256",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=peer_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    peer_public_key = kms.get_public_key(KeyId=peer_key_id)["PublicKey"]

    code, message = _error(
        lambda: kms.derive_shared_secret(
            KeyId=sign_key_id, KeyAgreementAlgorithm="ECDH", PublicKey=peer_public_key
        )
    )
    assert code == "InvalidKeyUsageException", f"expected InvalidKeyUsageException, got {code}"
    expected_message = f"{sign_key_arn} key usage is SIGN_VERIFY which is not valid for DeriveSharedSecret."
    assert message == expected_message, f"unexpected message {message!r}"

    # positive control: the identical algorithm and peer key succeed against a KEY_AGREEMENT key
    agreement_key_id = kms.create_key(
        Description=ctx.unique_name("kms-dss-wrongusage-agree-"),
        KeyUsage="KEY_AGREEMENT",
        KeySpec="ECC_NIST_P256",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=agreement_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    resp = kms.derive_shared_secret(
        KeyId=agreement_key_id, KeyAgreementAlgorithm="ECDH", PublicKey=peer_public_key
    )
    assert resp["KeyAgreementAlgorithm"] == "ECDH", (
        f"positive control: expected KeyAgreementAlgorithm ECDH, got {resp['KeyAgreementAlgorithm']!r}"
    )
    assert len(resp["SharedSecret"]) == 32, (
        f"positive control: expected a 32-byte shared secret, got {len(resp['SharedSecret'])}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
