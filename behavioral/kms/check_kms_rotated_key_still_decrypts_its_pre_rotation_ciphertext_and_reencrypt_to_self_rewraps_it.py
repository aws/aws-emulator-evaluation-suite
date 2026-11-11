"""kms-rotated-key-still-decrypts-its-pre-rotation-ciphertext-and-reencrypt-to-self-rewraps-it."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "kms-rotated-key-still-decrypts-its-pre-rotation-ciphertext-and-reencrypt-to-self-rewraps-it"
GROUP = 'key_rotation'
SERVICES = ['kms']


def _client_error(fn):
    """Return the botocore Error if fn() raises ClientError; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("the call was expected to fail and it succeeded")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (KMS minimum pending window is 7 days).

    The ARN guard keeps this teardown from targeting an AWS-managed key or an alias.
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


def _all_rotations(kms, key_arn: str) -> list:
    """Every ListKeyRotations entry, following Marker/NextMarker pagination.

    There is no botocore paginator for ListKeyRotations, hence the hand-rolled loop.
    """
    out, marker = [], None
    while True:
        kwargs = {"KeyId": key_arn, "Limit": 10}
        if marker:
            kwargs["Marker"] = marker
        page = kms.list_key_rotations(**kwargs)
        out.extend(page.get("Rotations", []))
        marker = page.get("NextMarker")
        if not page.get("Truncated") or not marker:
            return out


def _poll_until(fn, predicate, *, timeout_s: float, interval_s: float = 3.0, what: str = ""):
    """Poll fn() until predicate(value) is true; return the value or raise AssertionError.

    ListKeyRotations lags the RotateKeyOnDemand return by an undocumented, variable delay.
    """
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last saw {last!r}")


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RotateKeyOnDemand creates new key material yet a pre-rotation ciphertext still decrypts under
    its original KeyMaterialId, and ReEncrypt to the same key rewraps it onto the new material.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/rotating-keys-on-demand.html
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-rotmat-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-rotated-key-material-binding"}],
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))

    plaintext = b"pre-rotation-payload-that-must-survive"
    enc_ctx = {"tenant": "acme", "purpose": "rotation"}

    # Decrypt returns KeyMaterialId (Encrypt does not); it identifies which material served it.
    ct_old = kms.encrypt(
        KeyId=key_arn, Plaintext=plaintext, EncryptionContext=enc_ctx
    )["CiphertextBlob"]
    dec_before = kms.decrypt(CiphertextBlob=ct_old, KeyId=key_arn, EncryptionContext=enc_ctx)
    assert dec_before["Plaintext"] == plaintext, "baseline: the fresh ciphertext must open"
    material_old = dec_before.get("KeyMaterialId")
    assert isinstance(material_old, str) and material_old, (
        f"Decrypt must report the KeyMaterialId that served the ciphertext, got "
        f"{material_old!r} — without it rotation is unobservable on the data plane"
    )

    meta_before = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    assert meta_before["CurrentKeyMaterialId"] == material_old, (
        f"before any rotation the key's CurrentKeyMaterialId must be the material serving its "
        f"ciphertext: DescribeKey says {meta_before['CurrentKeyMaterialId']!r}, Decrypt says "
        f"{material_old!r}"
    )

    status_before = kms.get_key_rotation_status(KeyId=key_arn)
    assert status_before["KeyRotationEnabled"] is False, (
        f"a new CMK must not have automatic rotation enabled, got {status_before!r}"
    )
    assert _all_rotations(kms, key_arn) == [], (
        f"a never-rotated key must report no rotations, got "
        f"{_all_rotations(kms, key_arn)!r}"
    )

    # Automatic rotation runs on a ~365-day period, so only on-demand rotation is observable.
    rotated = kms.rotate_key_on_demand(KeyId=key_arn)
    assert rotated["KeyId"] == key_arn, rotated["KeyId"]

    # The ON_DEMAND entry can take well over 150s to appear in ListKeyRotations; 200s covers it.
    rotations = _poll_until(
        lambda: _all_rotations(kms, key_arn),
        lambda rs: any(r.get("RotationType") == "ON_DEMAND" for r in rs),
        timeout_s=200,
        what="an ON_DEMAND entry in ListKeyRotations",
    )
    on_demand = [r for r in rotations if r.get("RotationType") == "ON_DEMAND"]
    assert len(on_demand) == 1, (
        f"exactly one on-demand rotation was requested, ListKeyRotations reports "
        f"{len(on_demand)}: {rotations!r}"
    )
    assert on_demand[0].get("KeyMaterialState") == "CURRENT", (
        f"the material the rotation produced must be reported CURRENT, got "
        f"{on_demand[0]!r}"
    )
    material_new = on_demand[0].get("KeyMaterialId")
    assert isinstance(material_new, str) and material_new, on_demand[0]

    # The rotation claim: new material, distinct from the material the old ciphertext uses.
    assert material_new != material_old, (
        f"RotateKeyOnDemand reported material {material_new!r}, which is the SAME material the "
        f"pre-rotation ciphertext is bound to — no new key material was created"
    )
    # The data plane keeps using the old material until DescribeKey's CurrentKeyMaterialId
    # advances, so wait for that before asserting anything about new ciphertexts.
    meta_rotated = _poll_until(
        lambda: kms.describe_key(KeyId=key_arn)["KeyMetadata"],
        lambda m: m["CurrentKeyMaterialId"] == material_new,
        timeout_s=120,
        what=f"DescribeKey to report CurrentKeyMaterialId {material_new!r}",
    )
    assert meta_rotated["CurrentKeyMaterialId"] != material_old, (
        f"after rotation the current material must not still be {material_old!r}"
    )

    # Rotation adds material; it does not replace what exists.
    dec_old = kms.decrypt(CiphertextBlob=ct_old, KeyId=key_arn, EncryptionContext=enc_ctx)
    assert dec_old["Plaintext"] == plaintext, (
        "rotation broke a ciphertext minted before it — the pre-rotation material was not "
        "retained"
    )
    assert dec_old["KeyId"] == key_arn, dec_old["KeyId"]
    assert dec_old.get("KeyMaterialId") == material_old, (
        f"the pre-rotation ciphertext must still be served by material {material_old!r}, "
        f"Decrypt now reports {dec_old.get('KeyMaterialId')!r}"
    )

    # ct_new != ct_old only proves a fresh IV; KeyMaterialId carries the material claim.
    ct_new = kms.encrypt(
        KeyId=key_arn, Plaintext=plaintext, EncryptionContext=enc_ctx
    )["CiphertextBlob"]
    assert ct_new != ct_old, (
        "two Encrypts of the identical plaintext under the identical context returned "
        "byte-identical ciphertext — Encrypt must be non-deterministic (fresh IV)"
    )
    dec_new = kms.decrypt(CiphertextBlob=ct_new, KeyId=key_arn, EncryptionContext=enc_ctx)
    assert dec_new["Plaintext"] == plaintext, "the post-rotation ciphertext must open too"
    assert dec_new.get("KeyMaterialId") == material_new, (
        f"a ciphertext minted after the rotation propagated must be served by the NEW material "
        f"{material_new!r}, Decrypt reports {dec_new.get('KeyMaterialId')!r}"
    )

    rewrap = kms.re_encrypt(
        CiphertextBlob=ct_old,
        SourceKeyId=key_arn,
        DestinationKeyId=key_arn,
        SourceEncryptionContext=enc_ctx,
        DestinationEncryptionContext=enc_ctx,
    )
    assert rewrap["SourceKeyId"] == key_arn and rewrap["KeyId"] == key_arn, rewrap
    assert rewrap["CiphertextBlob"] != ct_old, (
        "ReEncrypt to the same key returned the source bytes unchanged — it must rewrap"
    )
    assert rewrap["SourceKeyMaterialId"] == material_old, (
        f"the rewrap must read the source blob under its own material {material_old!r}, got "
        f"{rewrap['SourceKeyMaterialId']!r}"
    )
    assert rewrap["DestinationKeyMaterialId"] == material_new, (
        f"a same-key ReEncrypt must rewrap onto the CURRENT material {material_new!r} — that is "
        f"the whole point of rewrapping after a rotation; got "
        f"{rewrap['DestinationKeyMaterialId']!r}"
    )
    assert rewrap["SourceEncryptionAlgorithm"] == "SYMMETRIC_DEFAULT", rewrap
    assert rewrap["DestinationEncryptionAlgorithm"] == "SYMMETRIC_DEFAULT", rewrap

    dec_rewrapped = kms.decrypt(
        CiphertextBlob=rewrap["CiphertextBlob"], KeyId=key_arn, EncryptionContext=enc_ctx
    )
    assert dec_rewrapped["Plaintext"] == plaintext, "the rewrapped blob no longer opens"
    assert dec_rewrapped.get("KeyMaterialId") == material_new, (
        f"the rewrapped blob must now be served by {material_new!r}, Decrypt reports "
        f"{dec_rewrapped.get('KeyMaterialId')!r}"
    )
    # ReEncrypt produces a new blob; it does not migrate the one it was given.
    assert kms.decrypt(
        CiphertextBlob=ct_old, KeyId=key_arn, EncryptionContext=enc_ctx
    ).get("KeyMaterialId") == material_old, (
        "the source ciphertext must still be served by the pre-rotation material after the rewrap"
    )

    err = _client_error(
        lambda: kms.decrypt(CiphertextBlob=rewrap["CiphertextBlob"], KeyId=key_arn)
    )
    assert err["Code"] == "InvalidCiphertextException", (
        f"the rewrapped blob must stay bound to its encryption context, got {err!r}"
    )
    # AWS sends this refusal with an empty message.
    assert err["Message"] == "", f"expected an empty message, got {err['Message']!r}"

    after = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    assert after["Arn"] == key_arn, (
        f"the key ARN changed across rotation: {key_arn!r} -> {after['Arn']!r}"
    )
    assert after["KeyState"] == "Enabled", after["KeyState"]
    assert kms.get_key_rotation_status(KeyId=key_arn)["KeyRotationEnabled"] is False, (
        "an on-demand rotation must not switch AUTOMATIC rotation on"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
