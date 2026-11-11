"""rotate-key-on-demand-unsupported-key-type-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "rotate-key-on-demand-unsupported-key-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RotateKeyOnDemand rejects an asymmetric signing key (UnsupportedOperationException) and
    leaves no rotation history; a symmetric key still rotates, as seen via ListKeyRotations."""
    kms = ctx.client("kms")

    asym_key_id = _create_asymmetric_signing_key(ctx)

    code, message = _error(lambda: kms.rotate_key_on_demand(KeyId=asym_key_id))
    assert code == "UnsupportedOperationException", f"unexpected error code: {code!r}"
    assert message == "", f"expected the empty message AWS returns, got {message!r}"

    # GetKeyRotationStatus/ListKeyRotations accept asymmetric keys and report no rotation.
    status = kms.get_key_rotation_status(KeyId=asym_key_id)
    assert status["KeyRotationEnabled"] is False, (
        f"expected KeyRotationEnabled=False for a never-rotated asymmetric key, got {status!r}"
    )

    listing = kms.list_key_rotations(KeyId=asym_key_id)
    assert listing["Rotations"] == [], (
        f"expected no rotation history for the rejected asymmetric key, got {listing['Rotations']!r}"
    )

    # Positive control: poll ListKeyRotations until the rotation is recorded.
    sym_key_id = _create_symmetric_key(ctx)
    kms.rotate_key_on_demand(KeyId=sym_key_id)
    sym_rotations = _poll_until(
        lambda: kms.list_key_rotations(KeyId=sym_key_id)["Rotations"],
        lambda rots: len(rots) >= 1,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert sym_rotations, (
        f"expected the on-demand rotation to show up in ListKeyRotations for {sym_key_id}, "
        f"got {sym_rotations!r}"
    )
    assert any(r.get("RotationType") == "ON_DEMAND" for r in sym_rotations), (
        f"expected an ON_DEMAND rotation record for {sym_key_id}, got {sym_rotations!r}"
    )



def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s; last result: {result!r}"
            )
        time.sleep(interval_s)
        result = probe()
    return result


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_symmetric_key(ctx) -> str:
    kms = ctx.client("kms")
    resp = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-rotate-ctrl-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )
    return key_id


def _create_asymmetric_signing_key(ctx) -> str:
    kms = ctx.client("kms")
    resp = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-rotate-asym-"),
        KeyUsage="SIGN_VERIFY",
        KeySpec="RSA_2048",
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )
    return key_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
