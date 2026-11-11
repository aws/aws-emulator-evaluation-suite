"""capacity-reservation-update-below-minimum-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "capacity-reservation-update-below-minimum-rejected"
GROUP = "state-machine"
SERVICES = ["athena"]


# timing:real-time — cooldown: 60 s
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """UpdateCapacityReservation with a TargetDpus below the documented minimum of 4 is rejected
    with InvalidRequestException, the reservation's TargetDpus is left unchanged, and a subsequent
    valid update on the same reservation succeeds (positive control in this file)."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-capres-min-")
    athena.create_capacity_reservation(
        Name=name,
        TargetDpus=4,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _cleanup_reservation(athena, name))

    _poll_until(
        lambda: _get_status(athena, name),
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300,
        interval_s=10,
    )
    assert _get_status(athena, name) == "ACTIVE"

    # Negative: TargetDpus of 1 is below the documented minimum of 4. botocore's own service
    # model carries that minimum as a range trait, so a validating client would reject it
    # locally; the call goes through a client with parameter validation off, so the refusal
    # graded here is the SERVICE's.
    from botocore.config import Config

    unvalidated = ctx.client("athena", config=Config(parameter_validation=False))
    # A reservation that turned ACTIVE moments ago refuses every update with a cooldown message
    # before it looks at the value, so retry the forbidden update (bounded) until the cooldown
    # has passed and the value itself is what gets refused.
    cooldown = (
        "Unable to modify your reservation. Please try again when your capacity has been active "
        "for 1 or more minutes."
    )
    deadline = time.monotonic() + 180
    while True:
        code, message = _error(lambda: unvalidated.update_capacity_reservation(Name=name, TargetDpus=1))
        if message != cooldown:
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"reservation {name} stayed in its post-ACTIVE update cooldown for 180s")
        time.sleep(2)
    assert code == "InvalidRequestException", (
        f"expected TargetDpus=1 (below the 4-DPU minimum) to be rejected, got {code!r}: {message!r}"
    )
    assert message == "Capacity must be requested in increments of 4.", repr(message)

    # Effect absent: reservation unchanged, still ACTIVE at TargetDpus=4.
    res = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert res["Status"] == "ACTIVE"
    assert res["TargetDpus"] == 4

    # Positive control: a valid update on the same reservation succeeds.
    athena.update_capacity_reservation(Name=name, TargetDpus=8)
    _poll_until(
        lambda: _get_status(athena, name),
        lambda s: s == "ACTIVE",
        timeout_s=300,
        interval_s=10,
    )
    res = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert res["TargetDpus"] == 8


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
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because accepting input AWS refuses must not read as a mere error mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
