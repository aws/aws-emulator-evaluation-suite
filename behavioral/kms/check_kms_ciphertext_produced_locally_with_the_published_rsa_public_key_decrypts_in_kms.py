"""kms-ciphertext-produced-locally-with-the-published-rsa-public-key-decrypts-in-kms."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from behavioral_harness import tags

CHECK = "kms-ciphertext-produced-locally-with-the-published-rsa-public-key-decrypts-in-kms"
GROUP = 'encrypt_decrypt'
SERVICES = ['kms']

ERR_INVALID_CIPHERTEXT = "InvalidCiphertextException"

def _err_code(fn):
    """Return the botocore Error.Code if fn() raises ClientError; raise if fn() succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("the call was expected to fail and it succeeded")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check created (KMS's minimum window is 7 days).

    The ARN guard keeps this from targeting an AWS-managed key or an alias.
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


def _poll_until(fn, predicate, *, timeout_s: float, interval_s: float = 3.0, what: str = ""):
    """Poll fn() until predicate(value) is true. Returns the value, or raises AssertionError."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last saw {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A plaintext encrypted locally with RSAES_OAEP_SHA_256 against the GetPublicKey DER key
    decrypts in KMS to the same bytes, and a SHA-1 OAEP ciphertext declared as SHA-256 is refused.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/offline-operations.html
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-localoaep-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="RSA_3072",  # keeps the OAEP plaintext ceiling far from binding
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-local-rsa-oaep-decrypts-in-kms"}],
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))

    # Asymmetric CMK creation is asynchronous: the key pair is generated server-side.
    _poll_until(
        lambda: kms.describe_key(KeyId=key_arn)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=120,
        what=f"{key_arn} to reach Enabled",
    )

    pub = kms.get_public_key(KeyId=key_arn)
    assert pub["KeySpec"] == "RSA_3072", pub["KeySpec"]
    assert pub["KeyUsage"] == "ENCRYPT_DECRYPT", pub["KeyUsage"]
    assert set(pub["EncryptionAlgorithms"]) == {"RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256"}, (
        f"an RSA ENCRYPT_DECRYPT key must advertise exactly the two OAEP algorithms, got "
        f"{pub['EncryptionAlgorithms']!r}"
    )

    loaded = serialization.load_der_public_key(pub["PublicKey"])
    assert loaded.key_size == 3072, (
        f"the published modulus is {loaded.key_size} bits but the KeySpec says "
        f"{pub['KeySpec']!r} — the published key is not the key that was created"
    )

    plaintext = b"encrypted-entirely-on-the-client-side"

    # --- The claim: KMS holds the private half of the key it published. Nothing here touches
    # a KMS Encrypt; the ciphertext is built locally from the DER public key.
    ct_sha256 = loaded.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    dec = kms.decrypt(
        CiphertextBlob=ct_sha256, KeyId=key_arn, EncryptionAlgorithm="RSAES_OAEP_SHA_256"
    )
    assert dec["Plaintext"] == plaintext, (
        "KMS could not decrypt a ciphertext built from the public key it published — the "
        "published public key is not the counterpart of the private key KMS holds"
    )
    assert dec["KeyId"] == key_arn, dec["KeyId"]
    assert dec["EncryptionAlgorithm"] == "RSAES_OAEP_SHA_256", dec["EncryptionAlgorithm"]

    # --- The OAEP digest is a real cryptographic parameter, not a label. The SAME bytes, the
    # SAME key, only the declared digest is wrong.
    ct_sha1 = loaded.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
    )
    code = _err_code(
        lambda: kms.decrypt(
            CiphertextBlob=ct_sha1, KeyId=key_arn, EncryptionAlgorithm="RSAES_OAEP_SHA_256"
        )
    )
    assert code == ERR_INVALID_CIPHERTEXT, (
        f"a SHA-1 OAEP ciphertext presented as RSAES_OAEP_SHA_256 must be refused with "
        f"{ERR_INVALID_CIPHERTEXT}, got {code!r}"
    )
    assert kms.decrypt(
        CiphertextBlob=ct_sha1, KeyId=key_arn, EncryptionAlgorithm="RSAES_OAEP_SHA_1"
    )["Plaintext"] == plaintext, (
        "the identical bytes must open under the OAEP digest they were built with — otherwise "
        "the refusal above was not about the digest"
    )

    # --- Effect absent / integrity: the refusal did not consume the SHA-256 ciphertext either.
    assert kms.decrypt(
        CiphertextBlob=ct_sha256, KeyId=key_arn, EncryptionAlgorithm="RSAES_OAEP_SHA_256"
    )["Plaintext"] == plaintext, "the locally built ciphertext must survive the failed attempt"

    # --- Control: the key was never mutated.
    after = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    assert after["KeyState"] == "Enabled", after["KeyState"]
    assert after["KeySpec"] == "RSA_3072", after["KeySpec"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
