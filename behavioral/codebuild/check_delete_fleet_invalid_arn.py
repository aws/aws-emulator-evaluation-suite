"""delete-fleet-invalid-arn."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected
    SUCCESS raises, so an over-permissive target is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

CHECK = "delete-fleet-invalid-arn"
GROUP = 'error-semantics'
SERVICES = ['codebuild']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFleet refuses a malformed ARN with InvalidInputException "Invalid fleet ARN", while
    DeleteFleet on an ACTIVE fleet succeeds and BatchGetFleets then reports it PENDING_DELETION."""
    cb = ctx.client("codebuild")

    valid_name = ctx.unique_name("sim2real-behav-fleet-")
    valid_arn = cb.create_fleet(
        name=valid_name,
        baseCapacity=1,
        environmentType="LINUX_CONTAINER",
        computeType="BUILD_GENERAL1_SMALL",
        tags=[{"key": "sim2real", "value": "true"}],
    )["fleet"]["arn"]
    deleted = False
    def _cleanup():
        if not deleted:
            cb.delete_fleet(arn=valid_arn)
    ctx.on_cleanup(_cleanup)

    # A fresh fleet is CREATING and rejects DeleteFleet with InvalidInputException ("Cannot delete
    # fleet while status is CREATING"). Wait for a terminal status before the positive control, or
    # that race — not the malformed ARN — is what gets exercised.
    fleet = _poll_until(
        lambda: cb.batch_get_fleets(names=[valid_name])["fleets"][0],
        lambda f: f["status"]["statusCode"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert fleet["status"]["statusCode"] == "ACTIVE", f"fleet did not become ACTIVE: {fleet}"

    # Positive control: DeleteFleet on the real fleet's well-formed ARN succeeds.
    cb.delete_fleet(arn=valid_arn)
    deleted = True

    # Negative: a malformed ARN is rejected outright, never accepted.
    code, message = _error(lambda: cb.delete_fleet(arn="not-a-fleet-arn"))
    assert (code, message) == ("InvalidInputException", "Invalid fleet ARN"), (code, message)

    # Independent read at the destination: DeleteFleet's invariant (stated by the service's own
    # status message) is that a reserved-capacity fleet does not vanish
    # on the spot — it moves to PENDING_DELETION and stays resolvable/usable until its
    # instances have accumulated an hour of runtime. Assert that transition, which is what a
    # bounded poll can actually observe, rather than full disappearance.
    fleet_after_delete = _poll_until(
        lambda: cb.batch_get_fleets(names=[valid_name])["fleets"][0],
        lambda f: f["status"]["statusCode"] == "PENDING_DELETION",
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert fleet_after_delete["status"]["statusCode"] == "PENDING_DELETION", (
        f"expected fleet to enter PENDING_DELETION after DeleteFleet, got "
        f"{fleet_after_delete['status']}"
    )


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
