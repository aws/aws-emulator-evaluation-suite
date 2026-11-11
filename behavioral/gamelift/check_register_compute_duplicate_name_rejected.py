"""register-compute-duplicate-name-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "register-compute-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["gamelift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterCompute rejects a ComputeName already registered on the fleet with ConflictException and its exact
    message and keeps the original IpAddress; another name registers, and the rejected call succeeds once the
    original is deregistered.
    """
    gl = ctx.client("gamelift")
    resource_tags = [{"Key": "sim2real-check", "Value": CHECK}]
    loc_name = ctx.unique_name("custom-sim2real-dupcompute-")
    gl.create_location(LocationName=loc_name, Tags=resource_tags)
    ctx.on_cleanup(lambda: gl.delete_location(LocationName=loc_name))

    fleet_name = ctx.unique_name("sim2real-dupcompute-fleet-")
    fleet_id = gl.create_fleet(
        Name=fleet_name,
        ComputeType="ANYWHERE",
        AnywhereConfiguration={"Cost": "1.0"},
        Locations=[{"Location": loc_name}],
        Tags=resource_tags,
    )["FleetAttributes"]["FleetId"]
    ctx.on_cleanup(lambda: gl.delete_fleet(FleetId=fleet_id))

    _poll_until(
        lambda: gl.describe_fleet_attributes(FleetIds=[fleet_id])["FleetAttributes"][0],
        lambda f: f["Status"] == "ACTIVE",
        timeout_s=60.0,
        interval_s=3.0,
    )

    compute_name = ctx.unique_name("sim2real-dupcompute-")
    original_ip = "10.0.0.10"
    gl.register_compute(
        FleetId=fleet_id, ComputeName=compute_name, IpAddress=original_ip, Location=loc_name
    )
    ctx.on_cleanup(lambda: _safe_deregister(gl, fleet_id, compute_name))

    code, message = _error(
        lambda: gl.register_compute(
            FleetId=fleet_id,
            ComputeName=compute_name,
            IpAddress="10.0.0.99",
            Location=loc_name,
        )
    )
    assert code == "ConflictException", (
        f"expected ConflictException registering a duplicate ComputeName on the "
        f"same fleet, got {code!r}"
    )
    expected_message = f"Compute name {compute_name} is already registered in location {loc_name}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the original compute's IP was not overwritten by the conflicting call.
    described = gl.describe_compute(FleetId=fleet_id, ComputeName=compute_name)["Compute"]
    assert described["IpAddress"] == original_ip, (
        f"expected the rejected duplicate to leave the original IP "
        f"{original_ip!r} untouched, got {described['IpAddress']!r}"
    )

    # Positive control: a different ComputeName on the same fleet registers fine,
    # confirmed via an independent ListCompute read (not the mutating call's own response).
    other_compute_name = ctx.unique_name("sim2real-dupcompute-other-")
    gl.register_compute(
        FleetId=fleet_id,
        ComputeName=other_compute_name,
        IpAddress="10.0.0.11",
        Location=loc_name,
    )
    ctx.on_cleanup(lambda: _safe_deregister(gl, fleet_id, other_compute_name))
    names_listed = [c["ComputeName"] for c in gl.list_compute(FleetId=fleet_id)["ComputeList"]]
    assert other_compute_name in names_listed, (
        f"expected {other_compute_name!r} visible via ListCompute after a "
        f"successful registration, got {names_listed!r}"
    )

    # Restore: the conflict was a state, not a permanently invalid input. Once the original registration is
    # removed, the identical call that was rejected succeeds.
    gl.deregister_compute(FleetId=fleet_id, ComputeName=compute_name)
    restored_ip = "10.0.0.99"
    gl.register_compute(
        FleetId=fleet_id,
        ComputeName=compute_name,
        IpAddress=restored_ip,
        Location=loc_name,
    )
    restored = gl.describe_compute(FleetId=fleet_id, ComputeName=compute_name)["Compute"]
    assert restored["IpAddress"] == restored_ip, (
        f"expected the restored registration of {compute_name!r} to take the new "
        f"IP {restored_ip!r} once the conflict was removed, got "
        f"{restored['IpAddress']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _safe_deregister(gl, fleet_id, compute_name):
    try:
        gl.deregister_compute(FleetId=fleet_id, ComputeName=compute_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
