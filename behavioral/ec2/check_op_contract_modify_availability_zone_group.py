"""op-contract-modify-availability-zone-group."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-availability-zone-group"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyAvailabilityZoneGroup opts a zone group in/out; unknown group and DryRun are rejected."""

    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(AllAvailabilityZones=True)["AvailabilityZones"]
    candidates = [z for z in zones if z.get("OptInStatus") == "not-opted-in" and z.get("GroupName")]
    if not candidates:
        raise AssertionError("no opt-in-eligible Availability/Local Zone group found in this account/region")
    group_name = candidates[0]["GroupName"]

    def _revert():
        ec2.modify_availability_zone_group(GroupName=group_name, OptInStatus="not-opted-in")

    ctx.on_cleanup(_revert)

    # --- error boundary #1: an unrecognized zone group name must be rejected ---
    code, msg = _error(
        lambda: ec2.modify_availability_zone_group(
            GroupName="sim2real-not-a-real-zone-group", OptInStatus="opted-in"
        )
    )
    assert code == "InvalidAZGroup.NotFound", f"expected InvalidAZGroup.NotFound, got {code!r}"
    expected = "Invalid Availability Zone group provided"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # --- error boundary #2: DryRun must reject before changing opt-in status ---
    dry_code, dry_msg = _error(
        lambda: ec2.modify_availability_zone_group(
            GroupName=group_name, OptInStatus="opted-in", DryRun=True
        )
    )
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code!r}"
    assert dry_msg == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {dry_msg!r}"

    unchanged = _zone_group_status(ec2, group_name)
    assert unchanged == "not-opted-in", "DryRun must not change opt-in status"

    # --- success path: opt in, verify the transition is observable ---
    resp = ec2.modify_availability_zone_group(GroupName=group_name, OptInStatus="opted-in")
    assert resp["Return"] is True, f"expected Return=True from the opt-in call, got {resp.get('Return')!r}"

    # Opting a zone group in is a genuinely slow, backend-orchestrated transition on real AWS —
    # it can take several minutes for OptInStatus to flip from "not-opted-in" to "opted-in",
    # well beyond the 60s this check originally allowed.
    _poll_until(
        lambda: _zone_group_status(ec2, group_name),
        lambda s: s == "opted-in",
        timeout_s=600.0,
        interval_s=15.0,
    )

    # The poll above already guarantees "opted-in" was observed once; that alone cannot
    # distinguish a durable transition from a flap the poll happened to catch mid-toggle.
    # A fresh, independent read proves the state holds.
    final = _zone_group_status(ec2, group_name)
    assert final == "opted-in", f"expected the opt-in to hold on a fresh independent read, got {final!r}"


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _zone_group_status(ec2, group_name: str) -> str:
    zones = ec2.describe_availability_zones(
        AllAvailabilityZones=True,
        Filters=[{"Name": "group-name", "Values": [group_name]}],
    )["AvailabilityZones"]
    if not zones:
        raise AssertionError(f"zone group {group_name!r} disappeared from DescribeAvailabilityZones")
    return zones[0]["OptInStatus"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
