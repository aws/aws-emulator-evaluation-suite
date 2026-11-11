"""anywhere-fleet-register-compute-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "anywhere-fleet-register-compute-lifecycle"
GROUP = "data-plane"
SERVICES = ["gamelift"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ANYWHERE fleet registers a compute that DescribeCompute and ListCompute show and GetComputeAuthToken issues
    an unexpired token for; after DeregisterCompute, and again after a repeat of it, DescribeCompute fails with
    NotFoundException 'Host (<name>) not found.'.
    """
    gl = ctx.client("gamelift")
    loc_name = ctx.unique_name("custom-sim2real-anyw-")
    gl.create_location(LocationName=loc_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: gl.delete_location(LocationName=loc_name))

    fleet_name = ctx.unique_name("sim2real-anywhere-fleet-")
    fleet = gl.create_fleet(
        Name=fleet_name,
        ComputeType="ANYWHERE",
        AnywhereConfiguration={"Cost": "1.0"},
        Locations=[{"Location": loc_name}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["FleetAttributes"]
    fleet_id = fleet["FleetId"]
    ctx.on_cleanup(lambda: gl.delete_fleet(FleetId=fleet_id))

    active = _poll_until(
        lambda: gl.describe_fleet_attributes(FleetIds=[fleet_id])["FleetAttributes"][0],
        lambda f: f["Status"] == "ACTIVE",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert active["ComputeType"] == "ANYWHERE", (
        f"expected ComputeType=ANYWHERE on the Anywhere fleet, got {active['ComputeType']!r}"
    )

    compute_name = ctx.unique_name("sim2real-compute-")
    registered = gl.register_compute(
        FleetId=fleet_id,
        ComputeName=compute_name,
        IpAddress="10.0.0.42",
        Location=loc_name,
    )["Compute"]
    ctx.on_cleanup(lambda: _safe_deregister(gl, fleet_id, compute_name))

    assert registered["ComputeName"] == compute_name, (
        f"expected RegisterCompute to echo ComputeName={compute_name!r}, got {registered.get('ComputeName')!r}"
    )
    assert registered["FleetId"] == fleet_id, (
        f"expected RegisterCompute to echo FleetId={fleet_id!r}, got {registered.get('FleetId')!r}"
    )
    assert registered["GameLiftServiceSdkEndpoint"], (
        "expected RegisterCompute to return a non-empty GameLiftServiceSdkEndpoint"
    )

    described = gl.describe_compute(FleetId=fleet_id, ComputeName=compute_name)["Compute"]
    assert described["ComputeName"] == compute_name, (
        f"expected DescribeCompute to return ComputeName={compute_name!r}, got {described.get('ComputeName')!r}"
    )
    # For non-container fleets the ComputeStatus may come back as a non-enumerated
    # string (e.g. "Active") rather than the enum value, per GameLift docs -- compare
    # case-insensitively rather than assuming the container-fleet enum casing.
    assert described["ComputeStatus"].upper() in ("PENDING", "ACTIVE"), (
        f"expected ComputeStatus in (PENDING, ACTIVE), got {described.get('ComputeStatus')!r}"
    )

    names_listed = [c["ComputeName"] for c in gl.list_compute(FleetId=fleet_id)["ComputeList"]]
    assert compute_name in names_listed, (
        f"expected {compute_name!r} in ListCompute's ComputeList, got {names_listed!r}"
    )

    token = gl.get_compute_auth_token(FleetId=fleet_id, ComputeName=compute_name)
    assert token["ComputeArn"], "expected GetComputeAuthToken to return a non-empty ComputeArn"
    assert token["AuthToken"], "expected GetComputeAuthToken to return a non-empty AuthToken"
    # ExpirationTimestamp comes back as a timezone-aware datetime, not epoch seconds.
    import datetime

    now = datetime.datetime.now(datetime.timezone.utc)
    assert token["ExpirationTimestamp"] > now, (
        f"expected AuthToken ExpirationTimestamp {token['ExpirationTimestamp']!r} to be in the future of {now!r}"
    )

    gl.deregister_compute(FleetId=fleet_id, ComputeName=compute_name)

    code, message = _error(
        lambda: gl.describe_compute(FleetId=fleet_id, ComputeName=compute_name)
    )
    assert code == "NotFoundException", (
        f"expected DescribeCompute on a deregistered compute to raise NotFoundException, got {code!r}"
    )
    expected_message = f"Host ({compute_name}) not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # DeregisterCompute on an already-deregistered compute succeeds as a no-op rather than raising
    # NotFoundException; the independent read below must still report it gone. A ClientError propagates.
    gl.deregister_compute(FleetId=fleet_id, ComputeName=compute_name)
    still_gone_code, still_gone_message = _error(
        lambda: gl.describe_compute(FleetId=fleet_id, ComputeName=compute_name)
    )
    assert still_gone_code == "NotFoundException", (
        f"a double-deregistered compute must not have been resurrected, got {still_gone_code!r}"
    )
    assert still_gone_message == expected_message, (
        f"expected message {expected_message!r}, got {still_gone_message!r}"
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
