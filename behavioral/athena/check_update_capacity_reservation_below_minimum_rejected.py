"""update-capacity-reservation-below-minimum-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.config import Config

from behavioral_harness import tags

CHECK = "update-capacity-reservation-below-minimum-rejected"
GROUP = "state-machine"
SERVICES = ["athena"]


# timing:real-time — cooldown: 60 s
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """UpdateCapacityReservation with TargetDpus below the minimum of 4 is rejected with the
    service's increments-of-4 message and leaves TargetDpus unchanged; a valid update to the
    same reservation succeeds (positive control)."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-cr-min-")

    athena.create_capacity_reservation(
        Name=name, TargetDpus=4, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _safe_teardown(athena, name))

    # A freshly created reservation starts out PENDING and rejects any
    # UpdateCapacityReservation call (valid or not) with InvalidRequestException until it
    # settles into ACTIVE. Wait for that first so the below-minimum rejection actually
    # exercises the minimum-value validation, and so the positive-control update further
    # down isn't rejected purely for being in the wrong lifecycle state.
    _poll_until(
        lambda: athena.get_capacity_reservation(Name=name)["CapacityReservation"],
        lambda cr: cr["Status"] == "ACTIVE",
        timeout_s=300.0,
        interval_s=10.0,
    )

    # TargetDpus carries a min:4 range constraint in the botocore service model, so a
    # normally-validating client rejects TargetDpus=2 with ParamValidationError before the
    # request ever reaches AWS -- that would make this assertion pass against ANY target,
    # including one that never enforces the minimum itself server-side. Use an unvalidated
    # client so the rejection asserted below is the service's own.
    unvalidated = ctx.client("athena", config=Config(parameter_validation=False))
    # An ACTIVE reservation still refuses every update for its first minute with a
    # cool-down message; poll past that window so the refusal graded is the minimum check.
    cooling = (
        "InvalidRequestException",
        "Unable to modify your reservation. Please try again when your capacity has been "
        "active for 1 or more minutes.",
    )
    err = _poll_until(
        lambda: _error(lambda: unvalidated.update_capacity_reservation(Name=name, TargetDpus=2)),
        lambda e: e != cooling,
        timeout_s=180.0,
        interval_s=10.0,
    )
    # The service enforces the 4-DPU floor as its increment rule, so 2 reads as an increment
    # violation rather than a separate minimum message.
    expected = ("InvalidRequestException", "Capacity must be requested in increments of 4.")
    assert err == expected, f"expected {expected!r}, got {err!r}"

    unchanged = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert unchanged["TargetDpus"] == 4, f"expected TargetDpus unchanged at 4, got {unchanged['TargetDpus']!r}"

    # Positive control: a valid TargetDpus update is accepted.
    athena.update_capacity_reservation(Name=name, TargetDpus=8)
    updated = _poll_until(
        lambda: athena.get_capacity_reservation(Name=name)["CapacityReservation"],
        lambda cr: cr["TargetDpus"] == 8,
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert updated["TargetDpus"] == 8, f"expected TargetDpus updated to 8, got {updated['TargetDpus']!r}"


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    timeout_s: float = 300.0,
    interval_s: float = 10.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection but the call succeeded: {result!r}")


def _safe_teardown(athena: Any, name: str) -> None:
    """Cancel, wait for a terminal status, then delete; return only if the reservation is not found."""
    from botocore.exceptions import ClientError

    def _get() -> Any:
        return athena.get_capacity_reservation(Name=name)["CapacityReservation"]

    try:
        cr = _poll_until(_get, lambda c: c["Status"] not in ("PENDING", "UPDATE_PENDING"), timeout_s=300.0, interval_s=2.0)
        if cr["Status"] == "ACTIVE":
            athena.cancel_capacity_reservation(Name=name)
        _poll_until(_get, lambda c: c["Status"] in ("CANCELLED", "FAILED"), timeout_s=180.0, interval_s=2.0)
        athena.delete_capacity_reservation(Name=name)
    except ClientError as err:
        error = err.response["Error"]
        if error["Code"] != "InvalidRequestException" or "not found" not in error.get("Message", "").lower():
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
