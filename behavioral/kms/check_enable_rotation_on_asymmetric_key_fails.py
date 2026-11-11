"""enable-rotation-on-asymmetric-key-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enable-rotation-on-asymmetric-key-fails"
GROUP = 'key_rotation'
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


def _poll_until(probe, predicate, *, timeout_s=15.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableKeyRotation on an RSA SIGN_VERIFY key fails UnsupportedOperationException and leaves
    rotation off, while on a symmetric key it succeeds (rotation is symmetric-key only)."""
    kms = ctx.client("kms")

    # Positive control: rotation works for a symmetric key.
    sym_key_id = kms.create_key(
        Description=ctx.unique_name("kms-rotationsym-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=sym_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    kms.enable_key_rotation(KeyId=sym_key_id)
    sym_status = _poll_until(
        lambda: kms.get_key_rotation_status(KeyId=sym_key_id),
        lambda s: s["KeyRotationEnabled"] is True,
        description="EnableKeyRotation propagation on symmetric key",
    )
    assert sym_status["KeyRotationEnabled"] is True, (
        f"positive control: expected rotation enabled on symmetric key, got {sym_status}"
    )

    asym_key_id = kms.create_key(
        Description=ctx.unique_name("kms-rotationasym-"),
        KeyUsage="SIGN_VERIFY",
        KeySpec="RSA_2048",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=asym_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    code, message = _error(lambda: kms.enable_key_rotation(KeyId=asym_key_id))
    assert code == "UnsupportedOperationException", f"expected UnsupportedOperationException, got {code}"
    assert message == "", f"unexpected message {message!r}"

    asym_status = kms.get_key_rotation_status(KeyId=asym_key_id)
    assert asym_status["KeyRotationEnabled"] is False, (
        f"expected rotation to remain disabled after the rejected EnableKeyRotation, "
        f"got {asym_status}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
