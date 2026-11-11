"""update-capacity-reservation-malformed-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-capacity-reservation-malformed-name-rejected"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityReservation rejects a Name outside [a-zA-Z0-9._-]+ with InvalidRequestException
    and creates nothing, while a well-formed Name on a real ACTIVE reservation updates successfully."""
    athena = ctx.client("athena")

    malformed_name = "not a valid reservation name!!"
    code, message = _error(
        lambda: athena.update_capacity_reservation(Name=malformed_name, TargetDpus=10)
    )
    assert code == "InvalidRequestException", (
        f"expected a malformed Name to be rejected with InvalidRequestException, got {code}"
    )
    assert message == (
        "1 validation error detected: Value at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z0-9._-]+"
    ), repr(message)
    names = {r["Name"] for r in athena.list_capacity_reservations()["CapacityReservations"]}
    assert malformed_name not in names, "a rejected malformed-name update must not create a reservation"

    # Positive control: a syntactically valid Name on a real, ACTIVE reservation succeeds.
    valid_name = ctx.unique_name("sim2real-athena-capres-name-")
    athena.create_capacity_reservation(
        Name=valid_name,
        TargetDpus=4,
        Tags=[{"Key": "sim2real", "Value": "update-capacity-reservation-malformed-name-rejected"}],
    )
    ctx.on_cleanup(lambda: _safe_cancel_and_delete(athena, valid_name))
    status = _poll_until(
        lambda: athena.get_capacity_reservation(Name=valid_name)["CapacityReservation"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=600.0,
        interval_s=10.0,
        description=f"{valid_name} to reach ACTIVE before the positive-control update",
    )
    assert status == "ACTIVE", f"expected the reservation to become ACTIVE, ended at {status!r}"
    athena.update_capacity_reservation(Name=valid_name, TargetDpus=8)
    updated = athena.get_capacity_reservation(Name=valid_name)["CapacityReservation"]
    assert updated["TargetDpus"] == 8, f"expected the valid update to persist, got {updated['TargetDpus']}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} (last value: {last!r})")


def _safe_cancel_and_delete(athena, name: str) -> None:
    def _status():
        return athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]

    try:
        _status()
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] == "InvalidRequestException" and "not found" in error.get("Message", "").lower():
            return
        raise
    # A PENDING or UPDATE_PENDING reservation refuses the cancel; wait for it to settle, then
    # cancel, wait for CANCELLED (the only state that accepts a delete) and delete.
    status = _poll_until(
        _status, lambda s: s not in ("PENDING", "UPDATE_PENDING"), timeout_s=600.0, interval_s=5.0,
        description=f"cleanup settle of {name}",
    )
    if status not in ("CANCELLING", "CANCELLED"):
        athena.cancel_capacity_reservation(Name=name)
    _poll_until(_status, lambda s: s == "CANCELLED", timeout_s=600.0, interval_s=5.0,
                description=f"cleanup cancel of {name}")
    athena.delete_capacity_reservation(Name=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
