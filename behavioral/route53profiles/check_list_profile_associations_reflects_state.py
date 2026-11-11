"""list-profile-associations-reflects-state."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-profile-associations-reflects-state"
GROUP = "state"
SERVICES = ["route53profiles"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListProfileAssociations' ProfileId/ResourceId filters return only associations matching that filter."""
    r53p = ctx.client("route53profiles")

    vpc_a = _create_vpc(ctx, "a")
    vpc_b = _create_vpc(ctx, "b")
    profile_a = _create_profile(ctx)
    profile_b = _create_profile(ctx)

    assoc_a = r53p.associate_profile(
        ProfileId=profile_a, ResourceId=vpc_a, Name=ctx.unique_name("sim2real-behav-assoc-")
    )["ProfileAssociation"]["Id"]
    ctx.on_cleanup(lambda: r53p.disassociate_profile(ProfileId=profile_a, ResourceId=vpc_a))
    assoc_b = r53p.associate_profile(
        ProfileId=profile_b, ResourceId=vpc_b, Name=ctx.unique_name("sim2real-behav-assoc-")
    )["ProfileAssociation"]["Id"]
    ctx.on_cleanup(lambda: r53p.disassociate_profile(ProfileId=profile_b, ResourceId=vpc_b))

    for assoc_id in (assoc_a, assoc_b):
        _poll_until(
            probe=lambda aid=assoc_id: r53p.get_profile_association(ProfileAssociationId=aid)[
                "ProfileAssociation"
            ]["Status"],
            predicate=lambda s: s in ("COMPLETE", "FAILED"),
            timeout_s=420,
            interval_s=5,
        )

    by_profile = r53p.list_profile_associations(ProfileId=profile_a)["ProfileAssociations"]
    ids_by_profile = {a["Id"] for a in by_profile}
    assert assoc_a in ids_by_profile, (
        f"ListProfileAssociations(ProfileId={profile_a}) omitted its own association "
        f"{assoc_a!r}; got ids {ids_by_profile!r}"
    )
    assert assoc_b not in ids_by_profile, (
        f"ListProfileAssociations(ProfileId={profile_a}) leaked {assoc_b!r}, which belongs to "
        f"profile {profile_b!r}, into ids {ids_by_profile!r}"
    )

    by_resource = r53p.list_profile_associations(ResourceId=vpc_b)["ProfileAssociations"]
    ids_by_resource = {a["Id"] for a in by_resource}
    assert assoc_b in ids_by_resource, (
        f"ListProfileAssociations(ResourceId={vpc_b}) omitted its own association "
        f"{assoc_b!r}; got ids {ids_by_resource!r}"
    )
    assert assoc_a not in ids_by_resource, (
        f"ListProfileAssociations(ResourceId={vpc_b}) leaked {assoc_a!r}, which belongs to "
        f"VPC {vpc_a!r}, into ids {ids_by_resource!r}"
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


def _create_vpc(ctx, suffix: str) -> str:
    ec2 = ctx.client("ec2")
    cidr = "10.79.0.0/16" if suffix == "a" else "10.80.0.0/16"
    name = ctx.unique_name(f"sim2real-behav-vpc-{suffix}-")
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _create_profile(ctx) -> str:
    r53p = ctx.client("route53profiles")
    name = ctx.unique_name("sim2real-behav-profile-")
    deadline = time.monotonic() + 200
    while True:
        try:
            profile_id = r53p.create_profile(
                Name=name,
                ClientToken=ctx.unique_name("sim2real-behav-token-"),
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
