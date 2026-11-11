"""delete-capacity-reservation-while-active-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-capacity-reservation-while-active-fails"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCapacityReservation is rejected while the reservation has not yet
    reached CANCELLED status; cancellation must precede deletion."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-capres-")
    athena.create_capacity_reservation(
        Name=name,
        TargetDpus=4,
        Tags=[{"Key": "sim2real", "Value": "delete-capacity-reservation-while-active-fails"}],
    )

    def _status():
        return athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]

    def _cleanup():
        try:
            _status()
        except ClientError as exc:
            # Already deleted by the positive control ("Reservation with name ... not found.").
            if "not found" in exc.response["Error"].get("Message", ""):
                return
            raise
        # A PENDING or UPDATE_PENDING reservation refuses the cancel; wait for it to settle.
        status = _poll_until(
            lambda: _status(), lambda s: s not in ("PENDING", "UPDATE_PENDING"), timeout_s=600, interval_s=5
        )
        if status not in ("CANCELLED", "CANCELLING"):
            athena.cancel_capacity_reservation(Name=name)
        _poll_until(lambda: _status(), lambda s: s == "CANCELLED", timeout_s=600, interval_s=5)
        athena.delete_capacity_reservation(Name=name)

    ctx.on_cleanup(_cleanup)

    # Hold the ACTIVE window the claim is about: a freshly created reservation is PENDING.
    status_before = _poll_until(
        lambda: _status(), lambda s: s in ("ACTIVE", "FAILED"), timeout_s=600, interval_s=5
    )
    assert status_before == "ACTIVE", f"reservation never became ACTIVE, ended at {status_before!r}"

    # Negative: delete while ACTIVE (not CANCELLED) must be rejected, naming the state it met.
    code, message = _error(lambda: athena.delete_capacity_reservation(Name=name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == (
        "Reservation state is ACTIVE. Reservation can only be deleted when state is CANCELLED"
    ), message

    # the reservation still exists, untouched by the rejected delete
    status_after_reject = _status()
    assert status_after_reject == "ACTIVE", (
        f"rejected delete must leave the reservation intact, got status={status_after_reject}"
    )

    # Positive control: cancel first, then delete succeeds.
    athena.cancel_capacity_reservation(Name=name)
    cancelled = _poll_until(lambda: _status(), lambda s: s == "CANCELLED", timeout_s=600, interval_s=5)
    assert cancelled == "CANCELLED", f"expected CANCELLED after cancel, got {cancelled}"

    athena.delete_capacity_reservation(Name=name)

    code_after_delete, message_after_delete = _error(lambda: athena.get_capacity_reservation(Name=name))
    assert code_after_delete == "InvalidRequestException", (
        f"expected reservation to be gone after delete, got code={code_after_delete}"
    )
    assert message_after_delete == f"Reservation with name {name} not found.", message_after_delete


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
