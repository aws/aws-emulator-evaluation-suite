"""kms-reencrypt-with-a-mismatched-source-encryption-context-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "kms-reencrypt-with-a-mismatched-source-encryption-context-rejected"
GROUP = 're_encrypt'
SERVICES = ['kms']

ERR_INVALID_CIPHERTEXT = "InvalidCiphertextException"



def _err(fn):
    """Return the botocore (Error.Code, Error.Message) fn() raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call was expected to fail and it succeeded")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7-day minimum window).

    The ARN guard keeps this teardown off AWS-managed keys and aliases.
    """
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    for attempt in range(4):
        try:
            kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "KMSInvalidStateException":
                return  # already PendingDeletion
            if code not in ("ThrottlingException", "KMSInternalException") or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """ReEncrypt with a wrong SourceEncryptionContext is refused (InvalidCiphertextException) and
    leaves the source blob usable; the correct rewrap opens only under the destination key+context.
    """
    kms = ctx.client("kms")

    src_meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-reencsrc-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-reencrypt-source-context"}],
    )["KeyMetadata"]
    src_arn = src_meta["Arn"]
    ctx.on_cleanup(lambda _a=src_arn: _teardown_key(kms, _a))

    dst_meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-reencdst-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-reencrypt-source-context"}],
    )["KeyMetadata"]
    dst_arn = dst_meta["Arn"]
    ctx.on_cleanup(lambda _a=dst_arn: _teardown_key(kms, _a))

    plaintext = b"rewrap-me-across-two-aad-domains"
    ctx_src = {"stage": "source", "tenant": "acme"}
    ctx_dst = {"stage": "destination", "tenant": "acme"}
    ctx_wrong = {"stage": "source", "tenant": "evil"}  # one value differs from ctx_src

    ct_src = kms.encrypt(
        KeyId=src_arn, Plaintext=plaintext, EncryptionContext=ctx_src
    )["CiphertextBlob"]

    # One wrong value in the SOURCE context; every other argument matches the later success.
    code_wrong, message_wrong = _err(
        lambda: kms.re_encrypt(
            CiphertextBlob=ct_src,
            SourceKeyId=src_arn,
            DestinationKeyId=dst_arn,
            SourceEncryptionContext=ctx_wrong,
            DestinationEncryptionContext=ctx_dst,
        )
    )
    assert code_wrong == ERR_INVALID_CIPHERTEXT, (
        f"ReEncrypt with SourceEncryptionContext {ctx_wrong!r} instead of {ctx_src!r} must raise "
        f"{ERR_INVALID_CIPHERTEXT}, got {code_wrong!r}"
    )
    assert message_wrong == "", f"expected an empty {ERR_INVALID_CIPHERTEXT} message, got {message_wrong!r}"

    assert kms.decrypt(
        CiphertextBlob=ct_src, KeyId=src_arn, EncryptionContext=ctx_src
    )["Plaintext"] == plaintext, (
        "the refused ReEncrypt must leave the source ciphertext usable"
    )
    assert kms.describe_key(KeyId=src_arn)["KeyMetadata"]["KeyState"] == "Enabled", (
        "the refused ReEncrypt must not disturb the source key"
    )
    dst_after_refusal = kms.describe_key(KeyId=dst_arn)["KeyMetadata"]
    assert dst_after_refusal["KeyState"] == "Enabled" and dst_after_refusal["Enabled"] is True, (
        f"the refused ReEncrypt must not disturb the destination key: {dst_after_refusal!r}"
    )

    rewrap = kms.re_encrypt(
        CiphertextBlob=ct_src,
        SourceKeyId=src_arn,
        DestinationKeyId=dst_arn,
        SourceEncryptionContext=ctx_src,
        DestinationEncryptionContext=ctx_dst,
    )
    assert rewrap["SourceKeyId"] == src_arn, rewrap["SourceKeyId"]
    assert rewrap["KeyId"] == dst_arn, rewrap["KeyId"]
    assert rewrap["CiphertextBlob"] != ct_src, "ReEncrypt must actually rewrap the blob"

    # The destination AAD replaced the source AAD.
    assert kms.decrypt(
        CiphertextBlob=rewrap["CiphertextBlob"], KeyId=dst_arn, EncryptionContext=ctx_dst
    )["Plaintext"] == plaintext, (
        "positive control: the destination context must open the rewrapped blob"
    )
    code_src_on_rewrapped, message_src_on_rewrapped = _err(
        lambda: kms.decrypt(
            CiphertextBlob=rewrap["CiphertextBlob"], KeyId=dst_arn, EncryptionContext=ctx_src
        )
    )
    assert code_src_on_rewrapped == ERR_INVALID_CIPHERTEXT, (
        f"the SOURCE context {ctx_src!r} must not open the rewrapped blob — the destination AAD "
        f"replaced it; got {code_src_on_rewrapped!r}"
    )
    assert message_src_on_rewrapped == "", message_src_on_rewrapped

    code_wrong_key, message_wrong_key = _err(
        lambda: kms.decrypt(
            CiphertextBlob=rewrap["CiphertextBlob"], KeyId=src_arn, EncryptionContext=ctx_dst
        )
    )
    assert code_wrong_key == "IncorrectKeyException", (
        f"the rewrapped blob must not open under the SOURCE key, got {code_wrong_key!r}"
    )
    assert message_wrong_key == (
        "The key ID in the request does not identify a CMK that can perform this operation."
    ), message_wrong_key

    code_dst_on_source, message_dst_on_source = _err(
        lambda: kms.decrypt(
            CiphertextBlob=ct_src, KeyId=src_arn, EncryptionContext=ctx_dst
        )
    )
    assert code_dst_on_source == ERR_INVALID_CIPHERTEXT, (
        f"the destination context must not open the SOURCE blob, got {code_dst_on_source!r}"
    )
    assert message_dst_on_source == "", message_dst_on_source


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
