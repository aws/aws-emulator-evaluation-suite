"""associate-profile-with-vpc-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "associate-profile-with-vpc-lifecycle"
GROUP = "state"
SERVICES = ["route53profiles"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateProfile links a Profile to a VPC and the association settles into COMPLETE."""
    r53p = ctx.client("route53profiles")

    vpc_id = _create_vpc(ctx)
    profile_id = _create_profile(ctx)

    assoc_name = ctx.unique_name("sim2real-behav-assoc-")
    assoc = r53p.associate_profile(ProfileId=profile_id, ResourceId=vpc_id, Name=assoc_name)[
        "ProfileAssociation"
    ]
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: r53p.disassociate_profile(ProfileId=profile_id, ResourceId=vpc_id))

    assert assoc["ProfileId"] == profile_id, f"expected ProfileId {profile_id!r}, got {assoc['ProfileId']!r}"
    assert assoc["ResourceId"] == vpc_id, f"expected ResourceId {vpc_id!r}, got {assoc['ResourceId']!r}"
    assert assoc["Name"] == assoc_name, f"expected Name {assoc_name!r}, got {assoc['Name']!r}"
    assert assoc["Status"] in (
        "CREATING",
        "COMPLETE",
    ), f"expected initial Status in ('CREATING', 'COMPLETE'), got {assoc['Status']!r}"

    status = _poll_until(
        probe=lambda: r53p.get_profile_association(ProfileAssociationId=assoc_id)["ProfileAssociation"][
            "Status"
        ],
        predicate=lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=420,
        interval_s=5,
    )
    assert status == "COMPLETE", f"association settled into {status!r} instead of COMPLETE"

    associations = r53p.list_profile_associations(ProfileId=profile_id)["ProfileAssociations"]
    assert any(a["Id"] == assoc_id and a["ResourceId"] == vpc_id for a in associations), (
        f"expected association {assoc_id!r} for VPC {vpc_id!r} in "
        f"list_profile_associations, got {[(a['Id'], a['ResourceId']) for a in associations]!r}"
    )


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
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _create_profile(ctx) -> str:
    from botocore.exceptions import ClientError

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


def _delete_when_released(call, timeout_s: float = 180.0) -> bool:
    """Run a delete, retrying the ConflictException AWS returns while an association is still
    being removed; False when the resource is already gone."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            call()
            return True
        except ClientError as err:
            error = err.response["Error"]
            if error["Code"] == "ResourceNotFoundException":
                return False
            if error["Code"] != "ConflictException" or "associated" not in error["Message"]:
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_profile_blocking(r53p, profile_id: str) -> None:
    from botocore.exceptions import ClientError

    if not _delete_when_released(lambda: r53p.delete_profile(ProfileId=profile_id)):
        return
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
