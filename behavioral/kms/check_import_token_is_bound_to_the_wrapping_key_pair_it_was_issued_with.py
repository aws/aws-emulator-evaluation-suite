"""import-token-is-bound-to-the-wrapping-key-pair-it-was-issued-with."""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from behavioral_harness import tags

CHECK = "import-token-is-bound-to-the-wrapping-key-pair-it-was-issued-with"
GROUP = "key_material_import"
SERVICES = ["kms"]

ERR_MISMATCH = "InvalidCiphertextException"
ERR_INVALID_STATE = "KMSInvalidStateException"


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7 days is the AWS minimum window)."""
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    for attempt in range(4):
        try:
            kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "KMSInvalidStateException":
                return
            if code not in ("ThrottlingException", "KMSInternalException") or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def _poll_until(fn, predicate, *, timeout_s: float, interval_s: float = 2.0, what: str = ""):
    """Poll fn() until predicate(value) is true. Returns the value, or RAISES on timeout."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last saw {last!r}")


def _wrap_for_import(public_key_der: bytes, material: bytes) -> bytes:
    """RSAES_OAEP_SHA_256-wrap `material` under the DER wrapping key GetParametersForImport gave."""
    pub = serialization.load_der_public_key(public_key_der)
    assert pub.key_size == 2048, f"WrappingKeySpec RSA_2048 must be 2048-bit, got {pub.key_size}"
    return pub.encrypt(
        material,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def _client_error(fn):
    """Return the botocore Error if fn() raises ClientError; raise if fn() succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("the call was expected to be refused but it succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Each GetParametersForImport mints a new wrapping key pair and token; material wrapped under
    one pair's public key with the other's token is refused both ways and the key stays unusable,
    while the matched pair imports and the key round-trips.

    Reference: https://docs.aws.amazon.com/kms/latest/APIReference/API_GetParametersForImport.html
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-tokenbind-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Origin="EXTERNAL",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-import-token-wrapping-key-binding"}],
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))
    assert meta["KeyState"] == "PendingImport", (
        f"a key with no material yet must be PendingImport, got {meta['KeyState']!r}"
    )

    def parameters():
        return kms.get_parameters_for_import(
            KeyId=key_arn, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
        )

    before = datetime.now(timezone.utc)
    first = parameters()
    second = parameters()
    after = datetime.now(timezone.utc)

    # Each call mints a fresh wrapping key pair and a fresh token.
    assert first["PublicKey"] != second["PublicKey"], (
        f"each GetParametersForImport must mint a NEW ephemeral wrapping key pair; both calls "
        f"returned the same {len(first['PublicKey'])}-byte public key "
        f"{first['PublicKey'].hex()[:48]}..."
    )
    assert first["ImportToken"] != second["ImportToken"], (
        "each GetParametersForImport must return a distinct ImportToken; both calls returned the "
        f"same {len(first['ImportToken'])}-byte token"
    )
    assert first["KeyId"] == key_arn and second["KeyId"] == key_arn, (
        f"both parameter sets must name {key_arn!r}, got {first['KeyId']!r} and "
        f"{second['KeyId']!r}"
    )

    # Each parameter set is valid for 24 hours from issuance.
    for label, params in (("first", first), ("second", second)):
        delta = params["ParametersValidTo"] - before
        assert timedelta(hours=23, minutes=30) <= delta <= timedelta(hours=24, minutes=30), (
            f"the {label} parameter set's ParametersValidTo must be ~24h after the live clock "
            f"reading taken just before the call ({before.isoformat()}); measured delta {delta}"
        )
    assert second["ParametersValidTo"] >= first["ParametersValidTo"], (
        f"the later call's window must not expire before the earlier one's: "
        f"{second['ParametersValidTo']} < {first['ParametersValidTo']}"
    )
    assert after >= before, (after, before)

    material = os.urandom(32)
    wrapped_under_first = _wrap_for_import(first["PublicKey"], material)
    wrapped_under_second = _wrap_for_import(second["PublicKey"], material)
    assert wrapped_under_first != wrapped_under_second, (
        "the same 32 bytes wrapped under two different RSA public keys must give different blobs"
    )

    # Only the token and the public key are crossed; key, material and algorithm are the same.
    for label, token, blob in (
        ("token #1 with material wrapped under public key #2", first["ImportToken"],
         wrapped_under_second),
        ("token #2 with material wrapped under public key #1", second["ImportToken"],
         wrapped_under_first),
    ):
        err = _client_error(
            lambda _t=token, _b=blob: kms.import_key_material(
                KeyId=key_arn,
                ImportToken=_t,
                EncryptedKeyMaterial=_b,
                ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
            )
        )
        assert err["Code"] == ERR_MISMATCH, (
            f"{label} must be refused with {ERR_MISMATCH} — the token names a wrapping private "
            f"key that cannot unwrap that blob; got {err!r}"
        )
        # AWS sends this refusal with an empty message.
        assert err["Message"] == "", f"{label}: expected an empty message, got {err['Message']!r}"

    # The refused imports left the key without material.
    state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
    assert state == "PendingImport", (
        f"two refused imports must leave the key in PendingImport, got {state!r}"
    )
    err = _client_error(
        lambda: kms.encrypt(KeyId=key_arn, Plaintext=b"should-not-be-encryptable-yet")
    )
    assert err["Code"] == ERR_INVALID_STATE, (
        f"a key with no imported material must refuse Encrypt with {ERR_INVALID_STATE}, got "
        f"{err!r}"
    )
    expected = f"{key_arn} is pending import."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # Fix only the pairing: same key and material, matched token and public key.
    kms.import_key_material(
        KeyId=key_arn,
        ImportToken=second["ImportToken"],
        EncryptedKeyMaterial=wrapped_under_second,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )
    imported = _poll_until(
        lambda: kms.describe_key(KeyId=key_arn)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=60,
        what=f"{key_arn} to reach Enabled after the correctly paired import",
    )
    assert imported["Origin"] == "EXTERNAL", (
        f"the key must still report Origin EXTERNAL after import, got {imported['Origin']!r}"
    )
    assert imported["ExpirationModel"] == "KEY_MATERIAL_DOES_NOT_EXPIRE", (
        f"expected ExpirationModel KEY_MATERIAL_DOES_NOT_EXPIRE, got "
        f"{imported.get('ExpirationModel')!r}"
    )

    # The previously unusable key now performs a real round trip.
    plaintext = b"usable-only-after-the-correct-pairing-" + os.urandom(16)
    blob = kms.encrypt(KeyId=key_arn, Plaintext=plaintext)["CiphertextBlob"]
    recovered = kms.decrypt(CiphertextBlob=blob)
    assert recovered["Plaintext"] == plaintext, (
        f"the imported key must round-trip exactly; expected {plaintext.hex()[:32]}..., got "
        f"{recovered['Plaintext'].hex()[:32]}..."
    )
    assert recovered["KeyId"] == key_arn, (
        f"the blob must resolve to {key_arn!r}, got {recovered['KeyId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
