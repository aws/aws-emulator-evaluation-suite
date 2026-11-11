"""associate-profile-duplicate-vpc-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-profile-duplicate-vpc-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53profiles"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A VPC already associated with one Profile cannot be associated with a second (LimitExceededException)."""
    r53p = ctx.client("route53profiles")

    vpc_id = _create_vpc(ctx)
    profile_a = _create_profile(ctx)
    profile_b = _create_profile(ctx)

    first = r53p.associate_profile(
        ProfileId=profile_a, ResourceId=vpc_id, Name=ctx.unique_name("sim2real-behav-assoc-")
    )["ProfileAssociation"]
    first_id = first["Id"]
    ctx.on_cleanup(lambda: _disassociate_blocking(r53p, profile_a, vpc_id))
    _poll_until(
        probe=lambda: r53p.get_profile_association(ProfileAssociationId=first_id)["ProfileAssociation"][
            "Status"
        ],
        predicate=lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=420,
        interval_s=5,
    )

    error = _client_error(
        lambda: r53p.associate_profile(
            ProfileId=profile_b, ResourceId=vpc_id, Name=ctx.unique_name("sim2real-behav-assoc-")
        )
    )
    assert error["Code"] == "LimitExceededException", f"expected LimitExceededException, got {error['Code']!r}"
    expected_message = f"VPC [{vpc_id}] exceeded its maximum profile association limit."
    assert error["Message"] == expected_message, f"expected {expected_message!r}, got {error['Message']!r}"

    # the VPC must still be associated only with profile_a, not profile_b
    associations = r53p.list_profile_associations(ResourceId=vpc_id)["ProfileAssociations"]
    profile_ids = {a["ProfileId"] for a in associations}
    assert profile_a in profile_ids
    assert profile_b not in profile_ids

    # restore: freeing the VPC by disassociating profile_a must let the identical failed
    # call for profile_b succeed
    r53p.disassociate_profile(ProfileId=profile_a, ResourceId=vpc_id)
    _poll_until(
        probe=lambda: _is_gone(lambda: r53p.get_profile_association(ProfileAssociationId=first_id)),
        predicate=bool,
        timeout_s=180,
        interval_s=5,
    )
    retried = r53p.associate_profile(
        ProfileId=profile_b, ResourceId=vpc_id, Name=ctx.unique_name("sim2real-behav-assoc-")
    )["ProfileAssociation"]
    ctx.on_cleanup(lambda: _disassociate_blocking(r53p, profile_b, vpc_id))
    assert retried["ProfileId"] == profile_b
    assert retried["ResourceId"] == vpc_id


def _client_error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises: a target
    that accepts what real AWS refuses must fail loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _is_gone(fn) -> bool:
    """Poll probe: True once fn() fails not-found, False while it still succeeds."""
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


def _disassociate_blocking(r53p, profile_id: str, vpc_id: str) -> None:
    """Teardown: DisassociateProfile is asynchronous and DeleteProfile refuses a Profile that is
    still associated, so wait for the association to disappear."""
    try:
        r53p.disassociate_profile(ProfileId=profile_id, ResourceId=vpc_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if not r53p.list_profile_associations(ProfileId=profile_id, ResourceId=vpc_id)["ProfileAssociations"]:
            return
        time.sleep(5)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


def _create_vpc(ctx) -> str:
    import random

    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    octet = random.randint(1, 200)
    vpc_id = ec2.create_vpc(
        CidrBlock=f"10.{octet}.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _create_profile(ctx) -> str:
    r53p = ctx.client("route53profiles")
    name = ctx.unique_name("sim2real-behav-profile-")
    deadline = time.monotonic() + 400
    while True:
        try:
            profile_id = r53p.create_profile(
                Name=name, ClientToken=ctx.unique_name("sim2real-behav-token-")
            )["Profile"]["Id"]
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "LimitExceededException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_profile_blocking(r53p, profile_id))
    return profile_id


def _delete_profile_blocking(r53p, profile_id: str) -> None:
    try:
        r53p.delete_profile(ProfileId=profile_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            r53p.get_profile(ProfileId=profile_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
