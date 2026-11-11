"""get-key-last-usage-monotonic-timestamps."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-key-last-usage-monotonic-timestamps"
GROUP = "ordering"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetKeyLastUsage's timestamp appears and strictly advances across successive Encrypt calls.
    Usage is recorded with a delay, so each update is polled for rather than assumed instant.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/monitoring-keys-determining-usage.html
    """
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Description=ctx.unique_name("sim2real-kms-lastusage-"),
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    kms.encrypt(KeyId=key_id, Plaintext=b"first-usage")
    first_ts = _poll_for_last_usage(ctx, key_id, newer_than=None)
    assert first_ts is not None, "GetKeyLastUsage never reported a timestamp after Encrypt"

    kms.encrypt(KeyId=key_id, Plaintext=b"second-usage")
    second_ts = _poll_for_last_usage(ctx, key_id, newer_than=first_ts)
    assert second_ts is not None, (
        f"KeyLastUsage.Timestamp never advanced past {first_ts!r} after a second Encrypt"
    )
    assert second_ts > first_ts, (
        f"KeyLastUsage.Timestamp went backwards or stalled: first={first_ts!r} second={second_ts!r}"
    )


def _poll_for_last_usage(ctx, key_id, newer_than, timeout_s: float = 1200.0, interval_s: float = 30.0):

    """Poll GetKeyLastUsage until a Timestamp is present (and newer than newer_than, if given).

    AWS documents up to an hour of recording delay; first usage can take over 10 minutes,
    so the 20-minute default bound is generous without waiting out the full hour.
    """
    kms = ctx.client("kms")
    deadline = time.monotonic() + timeout_s
    last_seen = None
    while time.monotonic() < deadline:
        resp = kms.get_key_last_usage(KeyId=key_id)
        usage = resp.get("KeyLastUsage") or {}
        ts = usage.get("Timestamp")
        if ts is not None:
            last_seen = ts
            if newer_than is None or ts > newer_than:
                return ts
        time.sleep(interval_s)
    return None if newer_than is None else last_seen


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
