"""e2e-key-rotation-and-decrypt-old-ciphertext."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-key-rotation-and-decrypt-old-ciphertext"
GROUP = "e2e"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Ciphertexts encrypted before and after RotateKeyOnDemand both decrypt, and Decrypt's
    KeyMaterialId shows the old blob served by the old material and the new blob by the new one.
    """
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-rotate-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    plaintext_pre = b"pre-rotation-secret-payload"
    ct_pre = kms.encrypt(KeyId=key_id, Plaintext=plaintext_pre)["CiphertextBlob"]
    dec_baseline = kms.decrypt(KeyId=key_id, CiphertextBlob=ct_pre)
    assert dec_baseline["Plaintext"] == plaintext_pre, (
        f"baseline decrypt must return the plaintext just encrypted, got "
        f"{dec_baseline['Plaintext']!r} instead of {plaintext_pre!r}"
    )
    material_old = dec_baseline.get("KeyMaterialId")
    assert isinstance(material_old, str) and material_old, (
        f"Decrypt must report the KeyMaterialId serving the ciphertext, got {material_old!r} "
        "-- without it a rotation that mints no new material is unobservable"
    )

    kms.rotate_key_on_demand(KeyId=key_id)
    _poll_until(
        lambda: kms.get_key_rotation_status(KeyId=key_id).get("OnDemandRotationStartDate")
        is not None,
        timeout_s=30.0,
        interval_s=1.0,
        what="OnDemandRotationStartDate to be recorded",
    )

    # RotateKeyOnDemand recording the *request* is not the same as the data plane
    # actually serving new material -- an Encrypt issued right after the call can still
    # land on the pre-rotation material for tens of seconds. Poll the key's own
    # CurrentKeyMaterialId (an independent read, not the rotate call's own response)
    # until it moves, then -- and only then -- mint the post-rotation ciphertext, so it
    # is guaranteed to exercise the NEW material rather than racing its propagation.
    material_new = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["CurrentKeyMaterialId"],
        timeout_s=200.0,
        interval_s=5.0,
        what="CurrentKeyMaterialId to advance past the pre-rotation material",
        predicate=lambda m: m != material_old,
    )
    assert material_new != material_old, (
        f"RotateKeyOnDemand reported success but CurrentKeyMaterialId is still "
        f"{material_new!r}, the pre-rotation material -- no new key material was created"
    )

    plaintext_post = b"post-rotation-secret-payload"
    ct_post = kms.encrypt(KeyId=key_id, Plaintext=plaintext_post)["CiphertextBlob"]

    assert ct_pre != ct_post, (
        "two Encrypt calls with different plaintext returned byte-identical ciphertext"
    )

    dec_pre = kms.decrypt(KeyId=key_id, CiphertextBlob=ct_pre)
    dec_post = kms.decrypt(KeyId=key_id, CiphertextBlob=ct_post)

    assert dec_pre["Plaintext"] == plaintext_pre, (
        f"the pre-rotation ciphertext must still open after rotation, got "
        f"{dec_pre['Plaintext']!r} instead of {plaintext_pre!r}"
    )
    assert dec_post["Plaintext"] == plaintext_post, (
        f"the post-rotation ciphertext must decrypt to what was encrypted, got "
        f"{dec_post['Plaintext']!r} instead of {plaintext_post!r}"
    )

    # The material-identity proof rotation actually promises: the pre-rotation blob is
    # still served by the OLD material (rotation retains it, it never replaces it in
    # place), and the post-rotation blob is served by the NEW material -- byte
    # inequality alone cannot distinguish this from "rotation never happened".
    assert dec_pre.get("KeyMaterialId") == material_old, (
        f"the pre-rotation ciphertext must still be served by material {material_old!r}, "
        f"Decrypt now reports {dec_pre.get('KeyMaterialId')!r}"
    )
    assert dec_post.get("KeyMaterialId") == material_new, (
        f"the post-rotation ciphertext must be served by the new material {material_new!r}, "
        f"Decrypt reports {dec_post.get('KeyMaterialId')!r}"
    )

    # OnDemandRotationStartDate marks a rotation IN FLIGHT, not the most recent one: once
    # CurrentKeyMaterialId has advanced (polled for above), it goes back to None.
    rotation_status = kms.get_key_rotation_status(KeyId=key_id)
    assert rotation_status.get("OnDemandRotationStartDate") is None, (
        f"once the on-demand rotation has completed (material already advanced to "
        f"{material_new!r}), GetKeyRotationStatus must stop reporting an in-flight "
        f"OnDemandRotationStartDate, got {rotation_status.get('OnDemandRotationStartDate')!r}"
    )


def _poll_until(probe, *, timeout_s: float, interval_s: float, what: str = "condition", predicate=None):
    """Poll probe() until predicate(value) (default: truthy value) holds; return that value.

    Raises on timeout rather than returning the last (failing) value, so a target that
    never satisfies the condition fails loudly instead of silently grading as passing.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        ok = last if predicate is None else predicate(last)
        if ok:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} not met within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
