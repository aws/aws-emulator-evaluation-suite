"""associate-route-table-cross-vpc-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "associate-route-table-cross-vpc-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateRouteTable rejects binding a route table from one VPC to a subnet that
    lives in a different VPC (cross-tenant/cross-network isolation boundary)."""
    ec2 = ctx.client("ec2")
    # Accounts have a small per-region VPC quota, and this account can already be at that
    # limit from other tests' VPCs -- creating brand-new VPCs unconditionally then fails with
    # VpcLimitExceeded. Reuse any already-existing VPC/subnet pair first (this check does not
    # depend on an ambient default VPC being present), and only create a new one as a last
    # resort.
    vpc_a, subnet_a = _some_vpc_subnet(ctx)
    vpc_b, subnet_b = _some_vpc_subnet(ctx, exclude_vpc_id=vpc_a, vpc_cidr="10.86.0.0/16", subnet_cidr="10.86.0.0/24")
    assert vpc_a != vpc_b

    rtb_a = ec2.create_route_table(
        VpcId=vpc_a,
        TagSpecifications=[
            {"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-rtb-")}]}
        ],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rtb_a))

    # Positive control first: associating within the same VPC succeeds, proving the account
    # and credentials can exercise AssociateRouteTable at all -- confirmed by an independent
    # read, not just the mutating call's own response.
    resp = ec2.associate_route_table(RouteTableId=rtb_a, SubnetId=subnet_a)
    assoc_id = resp["AssociationId"]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=assoc_id))
    assert resp["AssociationState"]["State"] in ("associating", "associated")

    described = ec2.describe_route_tables(RouteTableIds=[rtb_a])["RouteTables"][0]
    subnet_assocs = {a.get("SubnetId") for a in described["Associations"]}
    assert subnet_a in subnet_assocs, f"same-vpc association not reflected: {described['Associations']}"

    # rtb_a belongs to vpc_a; subnet_b belongs to vpc_b -- structurally invalid, and can never
    # become valid, so there is no restore leg for this negative.
    code, message = _client_error(lambda: ec2.associate_route_table(RouteTableId=rtb_a, SubnetId=subnet_b))
    assert code == "InvalidParameterValue", f"unexpected error code: {code}"
    expected = f"route table {rtb_a} and subnet {subnet_b} belong to different networks"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent, via an independent read at the destination: the rejected cross-VPC
    # association must never appear against rtb_a, and the earlier same-vpc association
    # must still be the only one there.
    described_after = ec2.describe_route_tables(RouteTableIds=[rtb_a])["RouteTables"][0]
    subnet_assocs_after = {a.get("SubnetId") for a in described_after["Associations"]}
    assert subnet_b not in subnet_assocs_after, (
        f"rejected cross-VPC association leaked: subnet {subnet_b} is associated to {rtb_a}: "
        f"{described_after['Associations']}"
    )
    assert subnet_assocs_after == {subnet_a}, f"unexpected associations on {rtb_a}: {described_after['Associations']}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _create_vpc_subnet(ctx, vpc_cidr: str, subnet_cidr: str):
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    try:
        vpc_id = ec2.create_vpc(
            CidrBlock=vpc_cidr,
            TagSpecifications=[
                {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpc-")}]}
            ],
        )["Vpc"]["VpcId"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "VpcLimitExceeded":
            # The account's per-region VPC quota is genuinely exhausted (e.g. by other
            # concurrently-run checks' VPCs) and there's no existing non-default VPC to
            # reuse either (checked by the caller before falling back here) -- this check
            # cannot establish its required second VPC at all, so there's nothing left to
            # validate rather than a real assertion failure to report.
            raise AssertionError(f"cannot provision a second VPC (quota exhausted): {exc}") from exc
        raise
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=subnet_cidr,
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-subnet-")}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return vpc_id, subnet_id


def _some_vpc_subnet(ctx, exclude_vpc_id=None, vpc_cidr="10.85.0.0/16", subnet_cidr="10.85.0.0/24"):
    # This check only needs *some* two distinct VPCs, each with a subnet -- not specifically
    # the default VPC, which a freshly provisioned account may not have. Reuse any
    # already-existing VPC/subnet pair (default or not) first; only mint a new VPC, subject
    # to the account's small per-region VPC quota, as a last resort.
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        if vpc_id == exclude_vpc_id:
            continue
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if subnets:
            return vpc_id, subnets[0]["SubnetId"]
    return _create_vpc_subnet(ctx, vpc_cidr, subnet_cidr)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
