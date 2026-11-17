"""create-key-edwards25519-encrypt-decrypt-leaves-no-key."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-key-edwards25519-encrypt-decrypt-leaves-no-key"
GROUP = "errors"
SERVICES = ["kms"]

_REJECTED = (
    "ValidationException",
    "KeyUsage ENCRYPT_DECRYPT is not compatible with KeySpec ECC_NIST_EDWARDS25519",
)


def expect_error(fn, code: str, message: str) -> None:
    """Assert fn() raises a ClientError with exactly this (code, message); raise on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message", ""))
        assert got == (code, message), f"expected ({code!r}, {message!r}), got {got!r}"
        return
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _list_key_ids(kms) -> set:
    ids = set()
    for page in kms.get_paginator("list_keys").paginate():
        ids.update(k["KeyId"] for k in page["Keys"])
    return ids


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateKey refuses KeySpec=ECC_NIST_EDWARDS25519 with KeyUsage=ENCRYPT_DECRYPT and creates
    no key; the same KeySpec with SIGN_VERIFY, and RSA_2048 with ENCRYPT_DECRYPT, both succeed."""
    kms = ctx.client("kms")

    # Edwards25519 is accepted with SIGN_VERIFY.
    sign_key = kms.create_key(
        KeySpec="ECC_NIST_EDWARDS25519",
        KeyUsage="SIGN_VERIFY",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(
        lambda _k=sign_key["KeyId"]: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7)
    )
    sign_described = kms.describe_key(KeyId=sign_key["KeyId"])["KeyMetadata"]
    assert sign_described["KeyUsage"] == "SIGN_VERIFY", (
        f"DescribeKey on an Edwards25519+SIGN_VERIFY key reported KeyUsage="
        f"{sign_described['KeyUsage']!r}"
    )
    assert set(sign_described["SigningAlgorithms"]) == {"ED25519_SHA_512", "ED25519_PH_SHA_512"}, (
        f"an Ed25519 SIGN_VERIFY key must advertise exactly these two signing algorithms, got "
        f"{sign_described['SigningAlgorithms']!r}"
    )
    assert "EncryptionAlgorithms" not in sign_described, (
        f"a SIGN_VERIFY-only key must report no EncryptionAlgorithms, got "
        f"{sign_described.get('EncryptionAlgorithms')!r}"
    )

    # ENCRYPT_DECRYPT is accepted on RSA_2048.
    rsa_key = kms.create_key(
        KeySpec="RSA_2048",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(
        lambda _k=rsa_key["KeyId"]: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7)
    )
    rsa_described = kms.describe_key(KeyId=rsa_key["KeyId"])["KeyMetadata"]
    assert rsa_described["KeyUsage"] == "ENCRYPT_DECRYPT", (
        f"DescribeKey on an RSA_2048+ENCRYPT_DECRYPT key reported KeyUsage="
        f"{rsa_described['KeyUsage']!r}"
    )

    # Edwards25519 with ENCRYPT_DECRYPT is refused, and no listed key carries the refused
    # call's Description.
    refused_description = ctx.unique_name("sim2real-kms-rejected-")
    before_ids = _list_key_ids(kms)
    expect_error(
        lambda: kms.create_key(
            KeySpec="ECC_NIST_EDWARDS25519",
            KeyUsage="ENCRYPT_DECRYPT",
            Description=refused_description,
        ),
        *_REJECTED,
    )
    after_ids = _list_key_ids(kms)
    new_ids = after_ids - before_ids
    matches = [
        key_id for key_id in new_ids
        if kms.describe_key(KeyId=key_id)["KeyMetadata"].get("Description") == refused_description
    ]
    assert matches == [], (
        f"the refused CreateKey's Description {refused_description!r} must match no key, but "
        f"ListKeys/DescribeKey found it on {matches!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
