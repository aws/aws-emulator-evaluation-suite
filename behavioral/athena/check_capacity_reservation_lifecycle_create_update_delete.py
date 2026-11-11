"""capacity-reservation-lifecycle-create-update-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "capacity-reservation-lifecycle-create-update-delete"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CapacityReservation: create (PENDING->ACTIVE) -> update targetDpus (ACTIVE->UPDATE_PENDING->ACTIVE)
    -> cancel (ACTIVE->CANCELLING->CANCELLED) -> delete (gone), verified via GetCapacityReservation
    after each transition."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-capres-")
    athena.create_capacity_reservation(
        Name=name,
        TargetDpus=4,
        Tags=[{"Key": "sim2real", "Value": "capacity-reservation-lifecycle-state-machine"}],
    )
    ctx.on_cleanup(lambda: _cleanup_reservation(athena, name))

    status = _poll_until(
        lambda: _get_status(athena, name),
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300,
        interval_s=10,
    )
    assert status == "ACTIVE", f"reservation entered {status} instead of ACTIVE"
    res = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert res["TargetDpus"] == 4, f"expected TargetDpus=4, got {res['TargetDpus']!r}"
    assert res["AllocatedDpus"] == 4, f"expected AllocatedDpus=4, got {res['AllocatedDpus']!r}"

    athena.update_capacity_reservation(Name=name, TargetDpus=8)
    _poll_until(
        lambda: _get_status(athena, name),
        lambda s: s == "ACTIVE",
        timeout_s=300,
        interval_s=10,
    )
    res = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert res["Status"] == "ACTIVE", f"expected ACTIVE after update settled, got {res['Status']!r}"
    assert res["TargetDpus"] == 8, f"expected TargetDpus=8 after update, got {res['TargetDpus']!r}"
    assert res["AllocatedDpus"] == 8, f"expected AllocatedDpus=8 after update, got {res['AllocatedDpus']!r}"

    athena.cancel_capacity_reservation(Name=name)
    _poll_until(
        lambda: _get_status(athena, name),
        lambda s: s == "CANCELLED",
        timeout_s=180,
        interval_s=5,
    )

    athena.delete_capacity_reservation(Name=name)

    not_found = f"Reservation with name {name} not found."
    code, message = _error(lambda: athena.get_capacity_reservation(Name=name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException reading a deleted reservation, got {code!r}"
    assert message == not_found, repr(message)

    mutation_code, mutation_message = _error(lambda: athena.update_capacity_reservation(Name=name, TargetDpus=4))
    assert mutation_code == "InvalidRequestException", (
        f"expected InvalidRequestException mutating a deleted reservation, got {mutation_code!r}"
    )
    assert mutation_message == not_found, repr(mutation_message)


def _get_status(athena, name: str) -> str:
    return athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because a
    call AWS refuses on a deleted resource must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected this call on the deleted reservation to fail, but it SUCCEEDED and returned {result!r}")


def _cleanup_reservation(athena, name: str) -> None:
    from botocore.exceptions import ClientError

    # Cancel once the reservation is ACTIVE (PENDING refuses Cancel), delete it once CANCELLED;
    # only an unknown name ("... not found.") counts as already gone.
    cancelled = False
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            status = _get_status(athena, name)
            if status in ("CANCELLED", "FAILED"):
                athena.delete_capacity_reservation(Name=name)
                return
            if status == "ACTIVE" and not cancelled:
                athena.cancel_capacity_reservation(Name=name)
                cancelled = True
        except ClientError as exc:
            if "not found" in exc.response["Error"].get("Message", ""):
                return
            raise
        time.sleep(2)
    raise TimeoutError(f"capacity reservation {name} not deleted within 180s (last status {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
