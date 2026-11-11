"""capacity-reservation-unknown-name-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "capacity-reservation-unknown-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['athena']

def _error(fn):
    """Call fn() and return its (code, message); raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        return (err.get("Code") or type(exc).__name__, err.get("Message", str(exc)))
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _assert_all_reject(cases):
    """Assert every (label, callable, expected) case fails with exactly that (code, message).

    All cases run before asserting so one run reports every deviation.
    """
    deviations = {}
    for label, fn, expected in cases:
        try:
            actual = _error(fn)
        except AssertionError as exc:
            actual = f"WRONGLY SUCCEEDED ({exc})"
        if actual != expected:
            deviations[label] = {"expected": expected, "actual": actual}
    assert not deviations, f"deviations: {deviations}"


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _teardown_reservation(athena, name: str) -> None:
    def _status():
        return athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]

    from botocore.exceptions import ClientError

    try:
        _status()
    except ClientError as exc:
        # Already deleted by the positive control ("Reservation with name ... not found.").
        if "not found" in exc.response["Error"].get("Message", ""):
            return
        raise
    # A PENDING or UPDATE_PENDING reservation refuses the cancel; wait for it to settle.
    status = _poll_until(_status, lambda s: s not in ("PENDING", "UPDATE_PENDING"), timeout_s=600, interval_s=5)
    if status not in ("CANCELLED", "CANCELLING"):
        athena.cancel_capacity_reservation(Name=name)
    _poll_until(_status, lambda s: s == "CANCELLED", timeout_s=600, interval_s=5)
    athena.delete_capacity_reservation(Name=name)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Capacity-reservation reads and mutations on an unknown name fail as not found, and an
    invalid-name CreateCapacityReservation is refused; a positive control first proves the same
    calls succeed on a real reservation, so the rejections are not unconditional."""
    athena = ctx.client("athena")
    reservations = athena.list_capacity_reservations()
    assert "CapacityReservations" in reservations, "ListCapacityReservations must return a CapacityReservations list"

    wg = ctx.unique_name("sim2real-behav-wg-capacity-")
    athena.create_work_group(Name=wg, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    cr_name = ctx.unique_name("sim2real-behav-cr-real-")
    athena.create_capacity_reservation(
        Name=cr_name, TargetDpus=4, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _teardown_reservation(athena, cr_name))

    got = athena.get_capacity_reservation(Name=cr_name)["CapacityReservation"]
    assert got["Name"] == cr_name, f"expected GetCapacityReservation to return {cr_name!r}, got {got.get('Name')!r}"

    athena.put_capacity_assignment_configuration(
        CapacityReservationName=cr_name,
        CapacityAssignments=[{"WorkGroupNames": [wg]}],
    )
    cfg = athena.get_capacity_assignment_configuration(CapacityReservationName=cr_name)[
        "CapacityAssignmentConfiguration"
    ]
    assert cfg["CapacityAssignments"] == [{"WorkGroupNames": [wg]}], (
        f"expected the assignment just put to round-trip, got {cfg['CapacityAssignments']!r}"
    )

    # CancelCapacityReservation only accepts a cancel once provisioning has reached ACTIVE
    # ("Reservation cannot be modified when state is PENDING").
    _poll_until(
        lambda: athena.get_capacity_reservation(Name=cr_name)["CapacityReservation"]["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=600,
        interval_s=10,
    )
    athena.cancel_capacity_reservation(Name=cr_name)
    _poll_until(
        lambda: athena.get_capacity_reservation(Name=cr_name)["CapacityReservation"]["Status"],
        lambda s: s == "CANCELLED",
        timeout_s=600,
        interval_s=5,
    )
    athena.delete_capacity_reservation(Name=cr_name)
    code, message = _error(lambda: athena.get_capacity_reservation(Name=cr_name))
    assert code == "InvalidRequestException", (
        f"expected GetCapacityReservation on the just-deleted reservation to fail with "
        f"InvalidRequestException, got {code}"
    )
    assert message == f"Reservation with name {cr_name} not found.", message

    missing = ctx.unique_name("sim2real-behav-cr-missing-")

    not_found = ("InvalidRequestException", f"Reservation with name {missing} not found.")
    _assert_all_reject(
        [
            ("GetCapacityReservation", lambda: athena.get_capacity_reservation(Name=missing), not_found),
            ("CancelCapacityReservation", lambda: athena.cancel_capacity_reservation(Name=missing), not_found),
            ("DeleteCapacityReservation", lambda: athena.delete_capacity_reservation(Name=missing), not_found),
            (
                "GetCapacityAssignmentConfiguration",
                lambda: athena.get_capacity_assignment_configuration(CapacityReservationName=missing),
                not_found,
            ),
            (
                "PutCapacityAssignmentConfiguration",
                lambda: athena.put_capacity_assignment_configuration(
                    CapacityReservationName=missing,
                    CapacityAssignments=[{"WorkGroupNames": [wg]}],
                ),
                not_found,
            ),
        ],
    )

    # TargetDpus=4 clears botocore's client-side minimum so the request reaches the service.
    bad_name = "sim2real behav invalid name"
    try:
        athena.create_capacity_reservation(Name=bad_name, TargetDpus=4)
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        code, message = err.get("Code") or type(exc).__name__, err.get("Message", str(exc))
    else:
        # Register for teardown so a wrongly accepted create never leaks paid capacity.
        ctx.on_cleanup(lambda: _teardown_reservation(athena, bad_name))
        raise AssertionError("creating a reservation with an invalid name must be refused, but it SUCCEEDED")
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException creating a reservation with an invalid name, got {code}"
    )
    assert message == (
        "1 validation error detected: Value at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z0-9._-]+"
    ), repr(message)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
