"""update-fleet-absent-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly here."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last result={result!r}")

def _delete_fleet_when_settled(cb, fleet_arn, timeout_s=900.0):
    """DeleteFleet refuses a fleet that is creating, updating or rotating; wait for it to settle."""
    _poll_until(
        lambda: [f["status"]["statusCode"] for f in cb.batch_get_fleets(names=[fleet_arn])["fleets"]],
        lambda codes: not codes or codes[0] not in ("CREATING", "UPDATING", "ROTATING"),
        timeout_s=timeout_s,
        interval_s=10.0,
    )
    cb.delete_fleet(arn=fleet_arn)

CHECK = "update-fleet-absent-not-found"
GROUP = 'error-semantics'
SERVICES = ['codebuild']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateFleet on a nonexistent fleet ARN fails ResourceNotFoundException with an exact message.

    A real fleet updates first as a positive control; BatchGetFleets lists the missing ARN as
    not found.
    """
    cb = ctx.client("codebuild")

    fleet_name = ctx.unique_name("sim2real-behav-fleet-")
    fleet = cb.create_fleet(
        name=fleet_name,
        baseCapacity=1,
        environmentType="LINUX_CONTAINER",
        computeType="BUILD_GENERAL1_SMALL",
        overflowBehavior="QUEUE",
        tags=[{"key": "sim2real", "value": "update-fleet-absent-not-found"}],
    )["fleet"]
    fleet_arn = fleet["arn"]
    ctx.on_cleanup(lambda: _delete_fleet_when_settled(cb, fleet_arn))

    _poll_until(
        lambda: cb.batch_get_fleets(names=[fleet_name])["fleets"][0]["status"]["statusCode"],
        lambda code: code in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=300.0,
    )

    cb.update_fleet(arn=fleet_arn, overflowBehavior="ON_DEMAND")
    updated = _poll_until(
        lambda: cb.batch_get_fleets(names=[fleet_name])["fleets"][0],
        lambda f: f["overflowBehavior"] == "ON_DEMAND",
        timeout_s=60.0,
    )
    assert updated["overflowBehavior"] == "ON_DEMAND", updated
    # UpdateFleet rotates a fleet; grade the status it settles in, not the rotation.
    settled = _poll_until(
        lambda: cb.batch_get_fleets(names=[fleet_name])["fleets"][0]["status"]["statusCode"],
        lambda code: code not in ("ROTATING", "UPDATING"),
        timeout_s=900.0,
        interval_s=10.0,
    )
    assert settled == "ACTIVE", f"fleet settled in {settled!r} after UpdateFleet"

    account_id = fleet_arn.split(":")[4]
    missing_name = ctx.unique_name("sim2real-behav-missing-fleet-")
    missing_arn = (
        f"arn:aws:codebuild:{ctx.region}:{account_id}:fleet/"
        f"{missing_name}:44444444-4444-4444-4444-444444444444"
    )
    code, message = _client_error(lambda: cb.update_fleet(arn=missing_arn, overflowBehavior="QUEUE"))
    assert code == "ResourceNotFoundException", code
    expected = f"Fleet {missing_arn} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found = cb.batch_get_fleets(names=[fleet_name, missing_arn])
    assert [f["name"] for f in not_found["fleets"]] == [fleet_name], not_found
    assert not_found["fleetsNotFound"] == [missing_arn], not_found


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
