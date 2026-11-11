"""rotate-key-on-demand-asymmetric-key-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rotate-key-on-demand-asymmetric-key-rejected"
GROUP = "ordering"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RotateKeyOnDemand rejects an asymmetric key (UnsupportedOperationException) and records
    no rotation; the same call on a symmetric key succeeds and is listed as ON_DEMAND."""
    kms = ctx.client("kms")

    # Positive control: on-demand rotation on a symmetric encryption key succeeds
    # and is tracked by ListKeyRotations.
    sym = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsrotctl-"),
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-rotate-on-demand-asym-rejected"}],
    )
    sym_key_id = sym["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=sym_key_id, PendingWindowInDays=7))

    kms.rotate_key_on_demand(KeyId=sym_key_id)
    sym_rotations = _poll_until(
        lambda: kms.list_key_rotations(KeyId=sym_key_id, IncludeKeyMaterial="ROTATIONS_ONLY")[
            "Rotations"
        ],
        lambda rots: len(rots) >= 1,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert len(sym_rotations) == 1, f"expected exactly 1 rotation record, got {sym_rotations}"
    assert sym_rotations[0]["RotationType"] == "ON_DEMAND", (
        f"expected ON_DEMAND rotation type, got {sym_rotations[0]!r}"
    )

    # Same operation on an asymmetric (SIGN_VERIFY) key.
    asym = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsrotasym-"),
        KeySpec="RSA_2048",
        KeyUsage="SIGN_VERIFY",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-rotate-on-demand-asym-rejected"}],
    )
    asym_key_id = asym["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=asym_key_id, PendingWindowInDays=7))

    code, message = _error(lambda: kms.rotate_key_on_demand(KeyId=asym_key_id))
    assert code == "UnsupportedOperationException", f"unexpected error code: {code}"
    assert message == "", f"expected the empty message AWS returns, got {message!r}"

    # ListKeyRotations still accepts an asymmetric key; it just reports no rotations.
    asym_rotations = [
        r
        for r in kms.list_key_rotations(KeyId=asym_key_id)["Rotations"]
        if r.get("RotationType") == "ON_DEMAND"
    ]
    assert asym_rotations == [], (
        f"expected no ON_DEMAND rotation records for rejected asymmetric-key rotation, "
        f"got {asym_rotations}"
    )



def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
