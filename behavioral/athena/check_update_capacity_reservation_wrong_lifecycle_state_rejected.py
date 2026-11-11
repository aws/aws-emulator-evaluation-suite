"""update-capacity-reservation-wrong-lifecycle-state-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-capacity-reservation-wrong-lifecycle-state-rejected"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityReservation on a PENDING reservation is rejected with InvalidRequestException and
    leaves TargetDpus unchanged; the same update succeeds once the reservation is ACTIVE."""
    athena = ctx.client("athena")

    # Confirm the precondition rather than assuming it: a freshly created reservation starts
    # PENDING with AllocatedDpus=0 until its DPUs are allocated. A reservation already ACTIVE at
    # the first read missed that window, so a fresh one is created, up to _ATTEMPTS, until one reads
    # PENDING.
    for _attempt in range(_ATTEMPTS):
        name = ctx.unique_name("sim2real-athena-cr-")
        athena.create_capacity_reservation(
            Name=name,
            TargetDpus=24,
            Tags=[{"Key": "sim2real", "Value": "update-capacity-reservation-wrong-lifecycle-state-rejected"}],
        )
        ctx.on_cleanup(lambda name=name: _safe_cancel(athena, name))
        initial = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
        if initial["Status"] != "ACTIVE":
            break
    assert initial["Status"] == "PENDING", (
        f"expected freshly created reservation to be PENDING, got {initial['Status']!r}"
    )

    # Break exactly one thing: update while still PENDING; the refusal message names the
    # state it met.
    code, message = _error(lambda: athena.update_capacity_reservation(Name=name, TargetDpus=48))
    assert code == "InvalidRequestException", (
        f"UpdateCapacityReservation while PENDING: expected InvalidRequestException, got {code!r}"
    )
    assert message == "Reservation cannot be modified when state is PENDING", message

    # Effect absent: TargetDpus is still the create-time value, not the rejected one.
    still = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert still["TargetDpus"] == 24, f"expected TargetDpus unchanged at 24, got {still['TargetDpus']}"
    assert still["Status"] != "ACTIVE", f"expected reservation not yet ACTIVE, got {still['Status']!r}"

    # Positive control: once the SAME reservation reaches ACTIVE, the identical
    # UpdateCapacityReservation call succeeds and is eventually reflected.
    active = _poll_until(
        lambda: athena.get_capacity_reservation(Name=name)["CapacityReservation"],
        lambda r: r["Status"] == "ACTIVE",
        timeout_s=600.0,
    )
    assert active["TargetDpus"] == 24, (
        f"expected the earlier rejected update to still be absent once ACTIVE, got {active['TargetDpus']}"
    )

    athena.update_capacity_reservation(Name=name, TargetDpus=48)
    updated = _poll_until(
        lambda: athena.get_capacity_reservation(Name=name)["CapacityReservation"],
        lambda r: r["Status"] == "ACTIVE" and r["TargetDpus"] == 48,
        timeout_s=600.0,
    )
    assert updated["TargetDpus"] == 48, (
        f"expected the identical update to succeed once ACTIVE, got {updated['TargetDpus']}"
    )


_ATTEMPTS = 3


def _safe_cancel(athena, name: str) -> None:
    def _status():
        return athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]

    # A PENDING or UPDATE_PENDING reservation refuses the cancel; wait for it to settle, then
    # cancel, wait for CANCELLED (the only state that accepts a delete) and delete.
    status = _poll_until(_status, lambda s: s not in ("PENDING", "UPDATE_PENDING"), timeout_s=600.0, interval_s=5.0)
    if status not in ("CANCELLED", "CANCELLING"):
        athena.cancel_capacity_reservation(Name=name)
    _poll_until(_status, lambda s: s == "CANCELLED", timeout_s=600.0, interval_s=5.0)
    athena.delete_capacity_reservation(Name=name)


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    instead: accepting a call AWS refuses is a distinct failure, not an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
