"""athena-capacity-reservation-below-minimum-dpus-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "athena-capacity-reservation-below-minimum-dpus-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCapacityReservation with TargetDpus below the 4-DPU minimum is rejected by the
    service with InvalidRequestException and creates nothing under that name; the minimum
    valid TargetDpus (4) still succeeds (positive control)."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-cr-")

    # botocore's generated model carries the same TargetDpus>=4 constraint AWS
    # documents, so a validating client raises ParamValidationError locally and the
    # request never reaches the service. Disable client-side validation so the
    # rejection asserted below is the SERVICE's, not the SDK's.
    unvalidated = ctx.client("athena", config=Config(parameter_validation=False))
    code, message = _error(lambda: unvalidated.create_capacity_reservation(Name=name, TargetDpus=1))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    assert message == "Capacity must be requested in increments of 4.", repr(message)

    # The forbidden effect did not happen: an independent read of this exact name
    # finds nothing (Athena answers a Get on an unknown reservation name with the
    # same InvalidRequestException code).
    absent_code, absent_message = _error(lambda: athena.get_capacity_reservation(Name=name))
    assert absent_code == "InvalidRequestException", (
        f"expected the rejected name to be unknown to Get, got {absent_code!r}"
    )
    assert absent_message == f"Reservation with name {name} not found.", repr(absent_message)

    # Positive control: the minimum valid TargetDpus (4) succeeds.
    athena.create_capacity_reservation(Name=name, TargetDpus=4, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe_teardown(athena, name))

    reservation = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert reservation["TargetDpus"] == 4, f"expected TargetDpus=4, got {reservation['TargetDpus']}"


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because accepting input AWS refuses must not read as a mere error mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"condition not met within {timeout_s}s; last={last!r}")


def _gone(exc: ClientError) -> bool:
    """Athena answers an unknown reservation name with InvalidRequestException '... not found.'."""
    err = exc.response["Error"]
    return err["Code"] == "InvalidRequestException" and "not found" in err.get("Message", "")


def _safe_teardown(athena, name: str) -> None:
    try:
        cr = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    except ClientError as exc:
        if _gone(exc):
            return
        raise
    if cr["Status"] in ("PENDING", "ACTIVE", "UPDATE_PENDING"):
        # A PENDING reservation refuses Cancel until it turns ACTIVE: retry it to a deadline.
        _poll_until(lambda: _try_cancel(athena, name), bool, timeout_s=180.0, interval_s=2.0)
        _poll_until(
            lambda: athena.get_capacity_reservation(Name=name)["CapacityReservation"],
            lambda c: c["Status"] == "CANCELLED",
            timeout_s=180.0,
            interval_s=2.0,
        )
    try:
        athena.delete_capacity_reservation(Name=name)
    except ClientError as exc:
        if not _gone(exc):
            raise


def _try_cancel(athena, name: str) -> bool:
    """Cancel the reservation; False while it is still PENDING and refuses the cancel."""
    try:
        athena.cancel_capacity_reservation(Name=name)
    except ClientError as exc:
        if "PENDING" in exc.response["Error"].get("Message", ""):
            return False
        raise
    return True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
