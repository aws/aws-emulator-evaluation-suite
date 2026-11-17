"""get-public-key-symmetric-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-public-key-symmetric-key-rejected"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPublicKey on a symmetric ENCRYPT_DECRYPT key fails UnsupportedOperationException; the
    identical call on an asymmetric SIGN_VERIFY key succeeds and returns its public key."""
    kms = ctx.client("kms")

    sym_key_id = kms.create_key(
        Description=ctx.unique_name("kms-getpubkey-sym-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=sym_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    code, message = _error(lambda: kms.get_public_key(KeyId=sym_key_id))
    assert code == "UnsupportedOperationException", f"expected UnsupportedOperationException, got {code}"
    assert message == "", f"unexpected message {message!r}"

    # positive control: the identical call succeeds on an asymmetric key
    asym_key_id = kms.create_key(
        Description=ctx.unique_name("kms-getpubkey-asym-"),
        KeyUsage="SIGN_VERIFY",
        KeySpec="ECC_NIST_P256",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=asym_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    resp = kms.get_public_key(KeyId=asym_key_id)
    assert resp["KeyUsage"] == "SIGN_VERIFY", (
        f"positive control: expected KeyUsage SIGN_VERIFY, got {resp['KeyUsage']!r}"
    )
    assert resp["PublicKey"][:1] == b"\x30", "positive control: public key must be DER encoded"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
