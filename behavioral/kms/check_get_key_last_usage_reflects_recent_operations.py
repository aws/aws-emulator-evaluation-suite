"""get-key-last-usage-reflects-recent-operations."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "get-key-last-usage-reflects-recent-operations"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A new key reports a TrackingStartDate and no usage Timestamp; after one Encrypt, GetKeyLastUsage reports
    Operation Encrypt with a Timestamp within 120 s of the call, computed by KMS (tracking may lag up to an hour)."""
    kms = ctx.client("kms")
    if not hasattr(kms, "get_key_last_usage"):

        raise AssertionError(
            "installed botocore does not expose GetKeyLastUsage (too old) -- cannot exercise"
        )

    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-lastuse-"), KeyUsage="ENCRYPT_DECRYPT"
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # Freshly created, never-used key: no usage tracked yet, and no client-supplied usage
    # metadata was accepted anywhere in CreateKey's request shape.
    before = kms.get_key_last_usage(KeyId=key_id)
    before_usage = before.get("KeyLastUsage", {}) or {}
    assert "Timestamp" not in before_usage, f"unused key already has usage timestamp: {before_usage}"
    assert "TrackingStartDate" in before, f"server-computed TrackingStartDate missing: {before}"

    before_call = datetime.datetime.now(datetime.timezone.utc)
    kms.encrypt(KeyId=key_id, Plaintext=b"last-usage-probe")

    try:
        last_usage = _poll_until(
            lambda: kms.get_key_last_usage(KeyId=key_id).get("KeyLastUsage", {}) or {},
            lambda usage: "Timestamp" in usage,
            timeout_s=1500.0,
            interval_s=30.0,
        )
    except AssertionError:

        raise AssertionError(
            "KeyLastUsage did not populate within our bounded poll window; AWS documents up "
            "to a one-hour propagation delay for this telemetry, which is longer than any "
            "bounded CI check can wait -- the synchronously-verifiable parts of the contract "
            "(no usage before the Encrypt call, no client-supplied override) already passed"
        ) from None

    assert last_usage["Operation"] == "Encrypt", last_usage["Operation"]
    ts = last_usage["Timestamp"]
    assert isinstance(ts, datetime.datetime)
    # Server-computed timestamp must be close to when we actually called Encrypt -- not some
    # client-supplied or stale value.
    delta = abs((ts - before_call).total_seconds())
    assert delta < 120, f"KeyLastUsage.Timestamp {ts} not close to Encrypt call time {before_call}"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

