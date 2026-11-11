"""concurrent-import-key-material-race."""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-import-key-material-race"
GROUP = "concurrency"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent ImportKeyMaterial calls with the same underlying material don't corrupt key state."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")
    resp = kms.create_key(
        Origin="EXTERNAL",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Description=ctx.unique_name("sim2real-kms-import-"),
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    assert resp["KeyMetadata"]["KeyState"] == "PendingImport", (
        f"expected a freshly created EXTERNAL-origin key to start PendingImport, "
        f"got {resp['KeyMetadata']['KeyState']!r}"
    )
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    params = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    import_token = params["ImportToken"]
    public_key = serialization.load_der_public_key(params["PublicKey"])

    key_material = os.urandom(32)  # AES-256 backing material, identical for both concurrent imports
    oaep = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    # two independent OAEP wraps of the SAME plaintext material (OAEP padding is randomized,
    # so the wire bytes differ even though they decrypt to identical material)
    wrapped_a = public_key.encrypt(key_material, oaep)
    wrapped_b = public_key.encrypt(key_material, oaep)

    def do_import(wrapped: bytes) -> str:
        for _ in range(5):
            try:
                kms.import_key_material(
                    KeyId=key_id,
                    ImportToken=import_token,
                    EncryptedKeyMaterial=wrapped,
                    ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
                )
                return "ok"
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code != "KMSInvalidStateException":
                    return code
                time.sleep(1.0)
        return "KMSInvalidStateException"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(do_import, w) for w in (wrapped_a, wrapped_b)]
        outcomes = [f.result(timeout=60) for f in futures]

    # both concurrent imports carry IDENTICAL underlying key material, so AWS KMS must treat
    # the second one as a benign reimport rather than corrupting the key: neither call may be
    # rejected as a material mismatch, and the key must land cleanly in Enabled state
    for code in outcomes:
        assert code == "ok", f"concurrent import of identical key material was rejected: {outcomes}"

    state = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda s: s == "Enabled",
        timeout_s=30.0,
    )
    assert state == "Enabled", f"expected key to land Enabled after the race, got {state!r}"

    # the key must be genuinely usable afterwards -- not just reporting Enabled while broken
    plaintext = b"import-race-roundtrip-payload"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, (
        f"encrypt/decrypt roundtrip on the post-race key did not return the original "
        f"plaintext: expected {plaintext!r}, got {decrypted!r}"
    )


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
