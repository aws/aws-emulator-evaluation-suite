"""automatic-rotation-schedule-computed-server-side."""
from __future__ import annotations

import datetime as dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "automatic-rotation-schedule-computed-server-side"
GROUP = "server-side"
SERVICES = ["kms"]
MSG_DISABLED = "{key_arn} is disabled."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """KMS computes NextRotationDate as now + RotationPeriodInDays and recomputes it on a period
    change; DisableKeyRotation clears the flag. A disabled key rejects EnableKeyRotation with
    DisabledException, leaving rotation off, and the same call succeeds after EnableKey."""
    kms = ctx.client("kms")
    key_meta = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-rotation-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id, key_arn = key_meta["KeyId"], key_meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    before_enable = dt.datetime.now(dt.timezone.utc)
    kms.enable_key_rotation(KeyId=key_id, RotationPeriodInDays=100)
    status = _poll_until(
        lambda: kms.get_key_rotation_status(KeyId=key_id),
        lambda s: s["KeyRotationEnabled"] is True,
        timeout_s=60,
        interval_s=2,
    )
    assert status["KeyRotationEnabled"] is True, status
    assert status["RotationPeriodInDays"] == 100, status["RotationPeriodInDays"]
    _assert_next_rotation_near(status["NextRotationDate"], before_enable, days=100)

    # Changing the period recomputes NextRotationDate server-side from now, not from
    # the original enable time.
    before_update = dt.datetime.now(dt.timezone.utc)
    kms.enable_key_rotation(KeyId=key_id, RotationPeriodInDays=200)
    status2 = _poll_until(
        lambda: kms.get_key_rotation_status(KeyId=key_id),
        lambda s: s["RotationPeriodInDays"] == 200,
        timeout_s=60,
        interval_s=2,
    )
    assert status2["RotationPeriodInDays"] == 200, status2["RotationPeriodInDays"]
    _assert_next_rotation_near(status2["NextRotationDate"], before_update, days=200)

    kms.disable_key_rotation(KeyId=key_id)
    status3 = _poll_until(
        lambda: kms.get_key_rotation_status(KeyId=key_id),
        lambda s: s["KeyRotationEnabled"] is False,
        timeout_s=60,
        interval_s=2,
    )
    assert status3["KeyRotationEnabled"] is False, status3

    kms.disable_key(KeyId=key_id)
    got = _err(lambda: kms.enable_key_rotation(KeyId=key_id, RotationPeriodInDays=90))
    expected = ("DisabledException", MSG_DISABLED.format(key_arn=key_arn))
    assert got == expected, f"expected {expected!r}, got {got!r}"

    status4 = kms.get_key_rotation_status(KeyId=key_id)
    assert status4["KeyRotationEnabled"] is False, status4

    kms.enable_key(KeyId=key_id)
    before_control = dt.datetime.now(dt.timezone.utc)
    kms.enable_key_rotation(KeyId=key_id, RotationPeriodInDays=90)
    status5 = _poll_until(
        lambda: kms.get_key_rotation_status(KeyId=key_id),
        lambda s: s["KeyRotationEnabled"] is True,
        timeout_s=60,
        interval_s=2,
    )
    assert status5["KeyRotationEnabled"] is True, status5
    assert status5["RotationPeriodInDays"] == 90, status5["RotationPeriodInDays"]
    _assert_next_rotation_near(status5["NextRotationDate"], before_control, days=90)


def _err(fn):
    """Return (Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    import time

    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition never met within {timeout_s}s, last value: {value}")
        time.sleep(interval_s)
        value = probe()
    return value


def _assert_next_rotation_near(
    next_rotation_date: dt.datetime, reference: dt.datetime, *, days: int
) -> None:
    expected = reference + dt.timedelta(days=days)
    delta = abs((next_rotation_date - expected).total_seconds())
    assert delta < 6 * 3600, (
        f"NextRotationDate {next_rotation_date} is not within 6h of reference+{days}d "
        f"({expected}); delta={delta}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
