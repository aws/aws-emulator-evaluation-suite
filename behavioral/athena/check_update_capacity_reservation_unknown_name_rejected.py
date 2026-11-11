"""update-capacity-reservation-unknown-name-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-capacity-reservation-unknown-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityReservation on a never-created Name is rejected with InvalidRequestException
    "Reservation with name ... not found." and creates nothing, while the identical call on a real
    ACTIVE reservation succeeds and its TargetDpus converges (positive control)."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-capres-")
    athena.create_capacity_reservation(
        Name=name, TargetDpus=4, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _cleanup_reservation(athena, name))
    _poll_status(athena, name, {"ACTIVE"}, timeout_s=600)

    bogus_name = ctx.unique_name("sim2real-behav-capres-unknown-")
    expected_message = f"Reservation with name {bogus_name} not found."
    code, message = _error(
        lambda: athena.update_capacity_reservation(Name=bogus_name, TargetDpus=8)
    )
    assert code == "InvalidRequestException", (
        f"expected UpdateCapacityReservation on a never-created Name to fail with "
        f"InvalidRequestException, got {code!r}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    # effect absent: the bogus name still does not correspond to any reservation
    get_code, get_message = _error(lambda: athena.get_capacity_reservation(Name=bogus_name))
    assert get_code == "InvalidRequestException", (
        f"expected GetCapacityReservation on the still-nonexistent Name to fail with "
        f"InvalidRequestException, got {get_code!r}"
    )
    assert get_message == expected_message, (
        f"expected message {expected_message!r}, got {get_message!r}"
    )

    # positive control: the identical operation against the real, ACTIVE reservation
    # succeeds and the effect actually lands
    athena.update_capacity_reservation(Name=name, TargetDpus=8)
    _poll_target_dpus(athena, name, expected=8, timeout_s=600)


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
