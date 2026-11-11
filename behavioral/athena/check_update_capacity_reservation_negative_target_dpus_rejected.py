"""update-capacity-reservation-negative-target-dpus-rejected."""
from __future__ import annotations

import time

from botocore.config import Config

from behavioral_harness import tags

CHECK = "update-capacity-reservation-negative-target-dpus-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityReservation rejects TargetDpus=0 with the service's own InvalidRequestException
    (client-side validation off) and leaves TargetDpus untouched; a valid update still succeeds."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-capres-neg-")
    athena.create_capacity_reservation(Name=name, TargetDpus=4, Tags=[{"Key": "sim2real-check", "Value": CHECK}])

    def _cancel():
        """Cancel, wait for a terminal status, then delete; return only if the reservation is not found."""
        from botocore.exceptions import ClientError

        def _status():
            return athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]

        try:
            status = _poll_until(_status, lambda s: s not in ("PENDING", "UPDATE_PENDING"), timeout_s=300.0)
            if status == "ACTIVE":
                athena.cancel_capacity_reservation(Name=name)
            status = _poll_until(_status, lambda s: s in ("CANCELLED", "FAILED"), timeout_s=180.0)
            if status not in ("CANCELLED", "FAILED"):
                raise AssertionError(f"capacity reservation {name} did not reach CANCELLED (last={status})")
            athena.delete_capacity_reservation(Name=name)
        except ClientError as err:
            error = err.response["Error"]
            if error["Code"] != "InvalidRequestException" or "not found" not in error.get("Message", "").lower():
                raise

    ctx.on_cleanup(_cancel)

    status = _poll_until(
        lambda: _reservation_status(athena, name),
        lambda s: s == "ACTIVE",
        timeout_s=1800.0,
        interval_s=20.0,
    )
    assert status == "ACTIVE", f"reservation never reached ACTIVE, last status={status}"

    # botocore's shape validator would reject TargetDpus=0 locally -- the service's own
    # min-value constraint is baked into the generated model -- so client-side parameter
    # validation is disabled for this one call to force the request to the service and observe
    # *its* rejection instead of the SDK's.
    raw_athena = ctx.client("athena", config=Config(parameter_validation=False))
    code, message = _error(lambda: raw_athena.update_capacity_reservation(Name=name, TargetDpus=0))
    assert code == "InvalidRequestException", (
        f"expected TargetDpus=0 update to be rejected by the service with InvalidRequestException, got {code}"
    )
    expected_message = (
        "1 validation error detected: Value at 'targetDpus' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unchanged = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert unchanged["TargetDpus"] == 4, "a rejected update must not change TargetDpus"

    # positive control: a valid capacity change is accepted and persists
    athena.update_capacity_reservation(Name=name, TargetDpus=8)
    updated = _poll_until(
        lambda: athena.get_capacity_reservation(Name=name)["CapacityReservation"],
        lambda r: r["TargetDpus"] == 8,
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert updated["TargetDpus"] == 8, (
        f"expected the valid update to persist TargetDpus=8, got {updated['TargetDpus']}"
    )


def _reservation_status(athena, name):
    try:
        return athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
    except Exception:
        return None


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
