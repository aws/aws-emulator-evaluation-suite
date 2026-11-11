"""cache-subnet-group-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cache-subnet-group-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticache"]

_VPC_CIDR = "10.224.0.0/16"
_SUBNET_CIDR = "10.224.1.0/24"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A cache subnet group create with a taken name fails with CacheSubnetGroupAlreadyExists and its exact
    message and leaves the original's description intact; a new name succeeds, and once the original is
    deleted the identical rejected create succeeds."""
    ec2 = ctx.client("ec2")
    ec = ctx.client("elasticache")

    subnet_id = _make_subnet(ec2, ctx)

    group_name = ctx.unique_name("sim2real-ecsubnet-")
    original_description = "sim2real original description"
    conflicting_description = "a different, conflicting description"
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=group_name,
        CacheSubnetGroupDescription=original_description,
        SubnetIds=[subnet_id],
    )
    ctx.on_cleanup(lambda: _delete_subnet_group(ec, group_name))

    code, message = _error(
        lambda: ec.create_cache_subnet_group(
            CacheSubnetGroupName=group_name,
            CacheSubnetGroupDescription=conflicting_description,
            SubnetIds=[subnet_id],
        )
    )
    assert code == "CacheSubnetGroupAlreadyExists", (
        f"expected CacheSubnetGroupAlreadyExists, got {code}"
    )
    expected_message = f"Cache subnet group {group_name} already exists."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The original group must be untouched by the rejected duplicate-create attempt.
    current = _describe_subnet_group(ec, group_name)
    assert current is not None and current["CacheSubnetGroupDescription"] == original_description, (
        f"original subnet group description was mutated by a rejected duplicate create: {current}"
    )

    # Positive control: creating a subnet group with a genuinely new name succeeds.
    other_name = ctx.unique_name("sim2real-ecsubnet-b-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=other_name,
        CacheSubnetGroupDescription="second, distinct subnet group",
        SubnetIds=[subnet_id],
    )
    ctx.on_cleanup(lambda: _delete_subnet_group(ec, other_name))
    created = _describe_subnet_group(ec, other_name)
    assert created is not None and created["CacheSubnetGroupName"] == other_name, (
        f"expected describe to return the just-created group {other_name!r}, got {created}"
    )

    # Restore: once the original is deleted and the name is free again, the identical
    # create call that was rejected above must now succeed.
    _delete_subnet_group(ec, group_name)
    assert _describe_subnet_group(ec, group_name) is None, (
        f"{group_name} should be gone after delete, but describe still returns it"
    )
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=group_name,
        CacheSubnetGroupDescription=conflicting_description,
        SubnetIds=[subnet_id],
    )
    restored = _describe_subnet_group(ec, group_name)
    assert restored is not None and restored["CacheSubnetGroupDescription"] == conflicting_description, (
        f"expected the identical create call to succeed once the name was freed; got {restored}"
    )


def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base.

    MEASURED: elasticache subnet-group siblings in this directory disagree on whether the
    wire Error.Code carries the modeled "Fault" suffix; comparing on the base avoids
    coupling this assertion to that ambiguity.
    """
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code


def _error(fn):
    """Call fn(); return (code, message) from the ClientError it must raise.

    An unexpected SUCCESS raises immediately, because an emulator ACCEPTING input real AWS refuses
    is the strongest signal available.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _describe_subnet_group(ec, name):
    try:
        groups = ec.describe_cache_subnet_groups(CacheSubnetGroupName=name)["CacheSubnetGroups"]
    except ClientError as exc:
        if _fault_base(exc.response.get("Error", {}).get("Code")) == "CacheSubnetGroupNotFound":
            return None
        raise
    return groups[0] if groups else None


def _delete_subnet_group(ec, name):
    try:
        ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
    except ClientError as exc:
        if _fault_base(exc.response.get("Error", {}).get("Code")) != "CacheSubnetGroupNotFound":
            raise


def _delete_ec2_quietly(fn, not_found_codes):
    try:
        fn()
    except ClientError as exc:
        if (exc.response.get("Error", {}).get("Code") or "") not in not_found_codes:
            raise


def _make_subnet(ec2, ctx):
    """A throwaway VPC + one subnet, used instead of depending on an ambient default VPC
    that a freshly provisioned account may not have. VPCs/subnets are not billable."""
    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ecsubnet-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _delete_ec2_quietly(
            lambda: ec2.delete_vpc(VpcId=vpc_id), ("InvalidVpcID.NotFound",)
        )
    )
    az = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=_SUBNET_CIDR,
        AvailabilityZone=az,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ecsubnet-subnet-")}],
        }],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_ec2_quietly(
            lambda: ec2.delete_subnet(SubnetId=subnet_id), ("InvalidSubnetID.NotFound",)
        )
    )
    return subnet_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
