"""create-fleet-invalid-capacity-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """(code, message) of the ClientError fn() raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

CHECK = "create-fleet-invalid-capacity-rejected"
GROUP = 'overly-permissive'
SERVICES = ['codebuild']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFleet rejects baseCapacity 0 with InvalidInputException and creates nothing in
    ListFleets, while an otherwise-identical request with baseCapacity 1 is accepted."""
    cb = ctx.client("codebuild")

    valid_name = ctx.unique_name("sim2real-behav-fleet-")
    valid_arn = cb.create_fleet(
        name=valid_name,
        baseCapacity=1,
        environmentType="LINUX_CONTAINER",
        computeType="BUILD_GENERAL1_SMALL",
        tags=[{"key": "sim2real", "value": "true"}],
    )["fleet"]["arn"]
    ctx.on_cleanup(lambda: _delete_fleet_once_settled(cb, valid_name, valid_arn))

    invalid_name = ctx.unique_name("sim2real-behav-fleet-")
    code, message = _error(
        lambda: cb.create_fleet(
            name=invalid_name,
            baseCapacity=0,
            environmentType="LINUX_CONTAINER",
            computeType="BUILD_GENERAL1_SMALL",
        )
    )
    assert (code, message) == (
        "InvalidInputException",
        "Capacity must be greater or equal to 1",
    ), (code, message)

    # ListFleets returns ARNs, not names; waiting for the control's ARN lets the same
    # consistency window settle the absence of the rejected one.
    arns = _poll_until(
        lambda: cb.list_fleets()["fleets"],
        lambda arns: valid_arn in arns,
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert not any(invalid_name in arn for arn in arns), (
        f"rejected fleet {invalid_name} appeared in ListFleets: {arns}"
    )

    # DeleteFleet refuses a CREATING fleet, so the control settles here before teardown.
    _poll_until(
        lambda: cb.batch_get_fleets(names=[valid_name])["fleets"][0]["status"]["statusCode"],
        lambda status: status != "CREATING",
        timeout_s=300.0,
        interval_s=5.0,
    )


def _delete_fleet_once_settled(cb, name, arn, timeout_s=45.0):
    """Wait (bounded) for a fleet to leave CREATING, then delete it; one already gone or
    deleting needs nothing more."""
    deadline = time.monotonic() + timeout_s
    while True:
        fleets = cb.batch_get_fleets(names=[name]).get("fleets", [])
        status = fleets[0]["status"]["statusCode"] if fleets else None
        if status in (None, "PENDING_DELETION", "DELETING"):
            return
        if status != "CREATING" or time.monotonic() >= deadline:
            break
        time.sleep(3)
    try:
        cb.delete_fleet(arn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last result={result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
