"""invalid-subnet-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-subnet-rejected"
GROUP = "error-semantics"
SERVICES = ["dax"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSubnetGroup with a nonexistent subnet ID fails with InvalidParameterValueException and its exact
    message and creates no group (SubnetGroupNotFoundFault), while one with real subnets reads back with
    its name, VpcId and subnet IDs."""
    dax = ctx.client("dax")
    bogus_name = ctx.unique_name("sim2real-dax-badsng-")

    ctx.on_cleanup(lambda: _safe_delete_subnet_group(ctx, bogus_name))
    code, message = _error_code(
        lambda: dax.create_subnet_group(
            SubnetGroupName=bogus_name, SubnetIds=["subnet-0000000000deadbee"]
        ),
        context="create_subnet_group with a nonexistent subnet id",
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for a nonexistent subnet id, got {code!r}"
    )
    assert message == "Some input subnets in :[subnet-0000000000deadbee] are invalid.", (
        f"unexpected message: {message!r}"
    )

    not_created_code, not_created_message = _error_code(
        lambda: dax.describe_subnet_groups(SubnetGroupNames=[bogus_name]),
        context="describe_subnet_groups on a subnet group whose creation was rejected",
    )
    assert not_created_code == "SubnetGroupNotFoundFault", (
        f"rejected create_subnet_group must leave no subnet group behind, got {not_created_code!r}"
    )
    assert not_created_message == f"Subnet group {bogus_name} not found.", (
        f"unexpected message: {not_created_message!r}"
    )

    subnet_ids, vpc_id = _default_vpc_subnet_ids(ctx, count=2)
    good_name = ctx.unique_name("sim2real-dax-goodsng-")
    dax.create_subnet_group(SubnetGroupName=good_name, SubnetIds=subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_subnet_group(ctx, good_name))
    described = dax.describe_subnet_groups(SubnetGroupNames=[good_name])["SubnetGroups"][0]
    assert described["SubnetGroupName"] == good_name, (
        f"expected the independent read to name the created subnet group {good_name!r}, got {described!r}"
    )
    assert described["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r}, got {described['VpcId']!r}"
    assert {s["SubnetIdentifier"] for s in described["Subnets"]} == set(subnet_ids), (
        f"expected subnets {subnet_ids!r}, got {described['Subnets']!r}"
    )


def _error_code(fn, *, context):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"{context}: expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_subnet_group(ctx, name):
    try:
        ctx.client("dax").delete_subnet_group(SubnetGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ServiceLinkedRoleNotFoundFault",
            "SubnetGroupNotFoundFault",
        ):
            raise


def _default_vpc_subnet_ids(ctx, count=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region for DAX subnet group creation")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if len(subnets) < count:
        raise AssertionError(f"shared network has fewer than {count} subnets available")
    return [s["SubnetId"] for s in subnets[:count]], vpc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
