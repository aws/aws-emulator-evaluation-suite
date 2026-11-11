"""op-contract-associateSecurityGroupVpc."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-associateSecurityGroupVpc"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateSecurityGroupVpc shares a non-default SG across VPCs; nonexistent VPC is rejected."""
    ec2 = ctx.client("ec2")

    # A freshly provisioned account may have no default VPC, so the SG's home VPC is created
    # in-check like vpc_b -- falling back to adopting an already-existing VPC only if the
    # account's VPC quota is exhausted, which keeps this check from depending on ambient state
    # while still not adding to quota contention against concurrent sibling checks.
    vpc_a = _create_or_adopt_vpc(ec2, ctx, "10.193.0.0/16", ctx.unique_name("sim2real-sgvhome-"))

    vpc_b = _create_vpc_retrying(ec2, "10.192.0.0/16", ctx.unique_name("sim2real-sgvtarget-"))
    ctx.on_cleanup(lambda: _retry_while_held(lambda: ec2.delete_vpc(VpcId=vpc_b), "DependencyViolation", timeout_s=600.0))
    _wait_vpc_available(ec2, vpc_b)

    sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-sg-"),
        Description="sim2real behavioral check",
        VpcId=vpc_a,
        TagSpecifications=[_tag_spec("security-group", ctx.unique_name("sim2real-sg-"))],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_while_held(lambda: ec2.delete_security_group(GroupId=sg), "SecurityGroupVpcAssociationExists", timeout_s=600.0))

    # error boundary: target VPC does not exist. Use a well-formed-but-nonexistent ID (mixed hex
    # digits, not all zeros) -- an all-zero suffix can trip AWS's ID-format check first and come
    # back as "...Malformed" instead of "...NotFound".
    #
    # Unlike the classic EC2 APIs, this (newer, cross-VPC-sharing) association API does not
    # necessarily validate the target VPC synchronously: real AWS accepts the request immediately
    # (returning State="associating") and only discovers the nonexistent VPC when it processes the
    # association asynchronously, surfacing the rejection as a terminal "associating-failed" state
    # rather than (or in addition to) a synchronous ClientError. Handle both shapes: if the call
    # raises, it must be one of the expected "InvalidVpcID.*" rejections; if it doesn't raise, poll
    # until the association reaches a terminal state and assert that state reflects failure rather
    # than a successful association.
    bogus_vpc = "vpc-0123456789abcdef0"
    resp = None
    code = None
    message = ""
    try:
        resp = ec2.associate_security_group_vpc(GroupId=sg, VpcId=bogus_vpc)
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        code = err.get("Code")
        message = err.get("Message") or ""

    if code is not None:
        # Real AWS's error taxonomy for this newer cross-VPC association API is not limited to the
        # classic "InvalidVpcID.*" family used by older EC2 APIs (it can also surface with the
        # lower-cased "InvalidVpcId.*" spelling), and a nonexistent-but-well-formed
        # target VPC can instead surface as a generic "InvalidParameterValue"/"InvalidParameter"
        # whose message names the missing VPC (either by echoing the literal id, or by using
        # "does not exist"/"not found" wording alongside the word "vpc"). Accept any of these
        # shapes, but for the generic codes require the message to actually be about the bogus VPC
        # so an unrelated InvalidParameterValue doesn't slip through unnoticed.
        message_lower = message.lower()
        is_vpc_not_found = code in (
            "InvalidVpcID.NotFound",
            "InvalidVpcID.Malformed",
            "InvalidVpcId.NotFound",
            "InvalidVpcId.Malformed",
        ) or (
            code in ("InvalidParameterValue", "InvalidParameter")
            and "vpc" in message_lower
            and (bogus_vpc in message or "does not exist" in message_lower or "not found" in message_lower)
        )
        assert is_vpc_not_found, f"expected a VPC-not-found rejection, got {code}: {message}"
    else:
        assert resp is not None and resp["State"] in ("associating", "associating-failed"), resp
        final_state = _poll_until(
            lambda: ec2.describe_security_group_vpc_associations(
                Filters=[{"Name": "group-id", "Values": [sg]}, {"Name": "vpc-id", "Values": [bogus_vpc]}]
            )["SecurityGroupVpcAssociations"],
            lambda assocs: bool(assocs) and assocs[0]["State"] != "associating",
            timeout_s=90,
            interval_s=3,
        )[0]["State"]
        assert final_state == "associating-failed", (
            f"expected nonexistent target VPC to fail association, got terminal state {final_state!r}"
        )

    # success path: associate the SG (created in vpc_a) with vpc_b
    resp = ec2.associate_security_group_vpc(GroupId=sg, VpcId=vpc_b)
    assert resp["State"] in ("associating", "associated"), resp["State"]

    def cleanup_assoc():
        # Disassociation is itself asynchronous ("associated" -> "disassociating" -> gone), and
        # the next cleanups delete the security group and both VPCs; deleting them before the
        # association actually clears fails with DependencyViolation and leaks the VPC.
        # Wait for the association to leave the blocking
        # states before returning, best-effort.
        try:
            ec2.disassociate_security_group_vpc(GroupId=sg, VpcId=vpc_b)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidGroup.NotFound":
                raise
        _poll_until(
            lambda: ec2.describe_security_group_vpc_associations(
                Filters=[{"Name": "group-id", "Values": [sg]}, {"Name": "vpc-id", "Values": [vpc_b]}]
            )["SecurityGroupVpcAssociations"],
            lambda assocs: not assocs or assocs[0]["State"] not in ("associated", "disassociating"),
            timeout_s=30,
            interval_s=2,
        )

    ctx.on_cleanup(cleanup_assoc)

    state = _poll_until(
        lambda: ec2.describe_security_group_vpc_associations(
            Filters=[{"Name": "group-id", "Values": [sg]}, {"Name": "vpc-id", "Values": [vpc_b]}]
        )["SecurityGroupVpcAssociations"],
        lambda assocs: bool(assocs) and assocs[0]["State"] == "associated",
        timeout_s=90,
        interval_s=3,
    )
    assert state[0]["State"] == "associated", (
        f"expected sg-vpc association to reach 'associated', got {state[0]['State']!r}"
    )


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_retrying(ec2, cidr: str, name: str, *, timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    """create_vpc can transiently fail with VpcLimitExceeded when sibling checks running
    concurrently in the same account/region are holding their own scratch VPCs; retry with
    backoff so this check succeeds once they finish and their own cleanup releases quota,
    instead of treating a shared-account capacity blip as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_or_adopt_vpc(ec2, ctx, cidr: str, name: str) -> str:
    """Create a fresh VPC for this check's own use; if the account is at its VPC quota, adopt
    an already-existing VPC instead of depending on an ambient default VPC that a freshly
    provisioned account may not have."""
    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_while_held(lambda: ec2.delete_vpc(VpcId=vpc_id), "DependencyViolation", timeout_s=600.0))
    _wait_vpc_available(ec2, vpc_id)
    return vpc_id


def _wait_vpc_available(ec2, vpc_id: str, *, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    """Newly created VPCs briefly report State=pending before flipping to available; poll for
    that transition instead of assuming create_vpc's response already reflects the final state."""
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda state: state == "available",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_while_held(fn, *codes, timeout_s=600.0, interval_s=15.0):
    """Run a teardown delete, retrying while AWS refuses it because a dependent resource deleted just
    before it is still going away; after the deadline the last refusal is raised."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in codes or _time.monotonic() >= deadline:
                raise
        _time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
