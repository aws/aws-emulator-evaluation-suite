"""list-key-rotations-chronological-order."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-key-rotations-chronological-order"
GROUP = "ordering"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After several RotateKeyOnDemand calls, ListKeyRotations returns one ON_DEMAND record
    per rotation with distinct RotationDates, in any order (AWS documents no list order).
    """
    kms = ctx.client("kms")

    created = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsrot-"),
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )
    key_id = created["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    num_rotations = 3
    for i in range(num_rotations):
        expected_count = i + 1
        kms.rotate_key_on_demand(KeyId=key_id)
        # Each on-demand rotation must be individually reflected (eventually
        # consistent) before the next is initiated, so timestamps are guaranteed
        # distinct and attributable to a specific call.
        # A RotateKeyOnDemand call's ON_DEMAND entry can take a few minutes to appear
        # in ListKeyRotations; 240s leaves margin.
        rotations = _poll_until(
            lambda: _list_on_demand_rotations(kms, key_id),
            lambda rots: len(rots) >= expected_count,
            timeout_s=240.0,
            interval_s=10.0,
        )
        assert len(rotations) >= expected_count, (
            f"expected at least {expected_count} rotation records after rotation "
            f"#{expected_count}, got {len(rotations)}"
        )

    final_rotations = _poll_until(
        lambda: _list_on_demand_rotations(kms, key_id),
        lambda rots: len(rots) >= num_rotations,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert len(final_rotations) == num_rotations, (
        f"expected exactly {num_rotations} ON_DEMAND rotation records, "
        f"got {len(final_rotations)}: {final_rotations}"
    )
    for rot in final_rotations:
        assert rot["RotationType"] == "ON_DEMAND"

    dates = [rot["RotationDate"] for rot in final_rotations]
    sorted_dates = sorted(dates)
    # Rotations were triggered sequentially with a real wait between each, so neighbouring
    # timestamps must differ (no ties); AWS documents no list order, so either direction.
    for earlier, later in zip(dates, dates[1:]):
        assert later > earlier or later < earlier, (
            f"expected distinct RotationDates, got {sorted_dates}"
        )


def _list_on_demand_rotations(kms, key_id: str) -> list:
    resp = kms.list_key_rotations(KeyId=key_id, IncludeKeyMaterial="ROTATIONS_ONLY")
    return [r for r in resp.get("Rotations", []) if r.get("RotationType") == "ON_DEMAND"]


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
