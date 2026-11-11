"""external-origin-pending-import-lifecycle."""
from __future__ import annotations

import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "external-origin-pending-import-lifecycle"
GROUP = 'key_lifecycle'
SERVICES = ['kms']


def _error(fn):
    """Return the botocore (Error.Code, Error.Message) if fn() raises ClientError; an
    unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Origin=EXTERNAL keys start in PendingImport, issue fresh import parameters, reject crypto
    while pending, and become genuinely usable -- not just relabeled -- once material is imported."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("kms-external-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Origin="EXTERNAL",
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    assert meta["Origin"] == "EXTERNAL", meta["Origin"]
    assert meta["KeyState"] == "PendingImport", meta["KeyState"]
    assert meta.get("Enabled") is False, meta.get("Enabled")

    params = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    assert params["KeyId"] == meta["Arn"], f"expected GetParametersForImport KeyId {meta['Arn']!r}, got {params['KeyId']!r}"
    assert params["ImportToken"], "an import token must be issued"
    assert params["PublicKey"][:1] == b"\x30", "wrapping public key must be DER encoded"
    assert params["ParametersValidTo"] is not None, "ParametersValidTo must be populated on a fresh grant"

    # no key material yet => cryptographic operations are blocked on key state
    code, message = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=b"no-material-yet"))
    assert code == "KMSInvalidStateException", f"expected KMSInvalidStateException, got {code}"
    assert message == f"{meta['Arn']} is pending import.", f"unexpected message {message!r}"

    # each GetParametersForImport call issues a distinct token / wrapping key
    params2 = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    assert params2["ImportToken"] != params["ImportToken"], "import tokens must not be reused"
    assert params2["PublicKey"] != params["PublicKey"], "wrapping key must be freshly generated"

    # restore: import real key material and prove the earlier refusal was tied to key state,
    # not a blanket denial of crypto on EXTERNAL-origin keys
    public_key = serialization.load_der_public_key(params["PublicKey"])
    key_material = os.urandom(32)  # AES-256, matches SYMMETRIC_DEFAULT
    wrapped = public_key.encrypt(
        key_material,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=wrapped,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )

    enabled = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=60,
    )
    assert enabled["KeyState"] == "Enabled", f"expected Enabled after import, got {enabled['KeyState']}"
    assert enabled["Enabled"] is True, f"expected Enabled=True after import, got {enabled['Enabled']}"

    # the identical call that was refused above now succeeds against real, usable material
    plaintext = b"sim2real-external-origin-import-roundtrip"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, f"expected round-trip plaintext {plaintext!r}, got {decrypted!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
