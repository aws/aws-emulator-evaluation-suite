"""update-capacity-reservation-wrong-state-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-capacity-reservation-wrong-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityReservation on a CANCELLED reservation is rejected (wrong state, not unknown
    name) and leaves TargetDpus at the value read just before the call (0 once cancelled); the same
    call succeeds while the reservation is ACTIVE (positive control)."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-capres-")
    athena.create_capacity_reservation(
        Name=name, TargetDpus=4, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _cleanup_reservation(athena, name))
    _poll_status(athena, name, {"ACTIVE"}, timeout_s=600)

    # positive control: update succeeds while the reservation is ACTIVE
    athena.update_capacity_reservation(Name=name, TargetDpus=8)
    _poll_target_dpus(athena, name, expected=8, timeout_s=600)

    # break exactly one thing: move the reservation out of ACTIVE via cancellation
    athena.cancel_capacity_reservation(Name=name)
    _poll_status(athena, name, {"CANCELLED"}, timeout_s=900)

    # the target's own reported state immediately before the rejected call -- not a
    # guessed constant -- is what "effect absent" is measured against
    before = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    before_target_dpus = before["TargetDpus"]
    assert before_target_dpus != 12, (
        f"TargetDpus was already 12 before the rejected call; the effect-absent check "
        f"below would be meaningless, got {before_target_dpus}"
    )

    code, message = _error(
        lambda: athena.update_capacity_reservation(Name=name, TargetDpus=12)
    )
    assert code == "InvalidRequestException", (
        f"UpdateCapacityReservation while CANCELLED: expected "
        f"InvalidRequestException, got {code!r}"
    )
    assert message == "Reservation cannot be modified when state is CANCELLED", message

    # effect absent: TargetDpus is unchanged from its pre-rejection value, not 12
    reservation = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert reservation["TargetDpus"] == before_target_dpus, (
        f"TargetDpus should remain {before_target_dpus} after the rejected update, "
        f"got {reservation['TargetDpus']}"
    )


def _error(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises: a
    target accepting a call AWS refuses must fail loudly, not as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


def _poll_status(athena, name, terminal_states, timeout_s=600.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
        last = resp["Status"]
        if last in terminal_states:
            return resp
        if last == "FAILED":
            raise AssertionError(
                f"capacity reservation {name} FAILED while waiting for {terminal_states}"
            )
        time.sleep(2)
    raise AssertionError(
        f"capacity reservation {name} never reached {terminal_states}, last={last!r}"
    )


def _poll_target_dpus(athena, name, expected, timeout_s=600.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
        if resp["Status"] == "ACTIVE" and resp["TargetDpus"] == expected:
            return resp
        time.sleep(2)
    raise AssertionError(
        f"capacity reservation {name} never converged to ACTIVE with TargetDpus={expected}"
    )


def _cleanup_reservation(athena, name):
    """Cancel, wait for a terminal status, then delete; return only if the reservation is not found."""
    from botocore.exceptions import ClientError

    try:
        settled = {"ACTIVE", "CANCELLING", "CANCELLED", "FAILED"}
        if _poll_status(athena, name, settled, timeout_s=300.0)["Status"] == "ACTIVE":
            athena.cancel_capacity_reservation(Name=name)
        _poll_status(athena, name, {"CANCELLED", "FAILED"}, timeout_s=450.0)
        athena.delete_capacity_reservation(Name=name)
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] != "InvalidRequestException" or "not found" not in error.get("Message", "").lower():
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
