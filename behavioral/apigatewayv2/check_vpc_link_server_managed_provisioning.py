"""vpc-link-server-managed-provisioning."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-link-server-managed-provisioning"
GROUP = "server-side"
SERVICES = ["apigatewayv2"]
TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-vpclink-prov"}


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created VpcLink starts PENDING and transitions to AVAILABLE purely through
    server-side provisioning, with no further client action between Create and GetVpcLink polls."""
    apigwv2 = ctx.client("apigatewayv2")
    subnet_ids = _provision_subnets(ctx, ctx.client("ec2"))
    name = ctx.unique_name("sim2real-vpclink-prov-")
    created = apigwv2.create_vpc_link(Name=name, SubnetIds=subnet_ids, Tags=TAGS)
    vpc_link_id = created["VpcLinkId"]
    ctx.on_cleanup(lambda: _delete_and_wait_gone(apigwv2, vpc_link_id))

    assert created["VpcLinkStatus"] == "PENDING", (
        f"CreateVpcLink returned status {created['VpcLinkStatus']!r}, expected the initial "
        "state to be PENDING before any server-side provisioning has occurred"
    )

    final_status = _poll_until(
        lambda: apigwv2.get_vpc_link(VpcLinkId=vpc_link_id)["VpcLinkStatus"],
        lambda s: s in ("AVAILABLE", "FAILED", "INACTIVE"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert final_status == "AVAILABLE", f"VpcLink did not reach AVAILABLE (last={final_status})"


def _provision_subnets(ctx, ec2) -> list[str]:
    """A dedicated VPC with one subnet in each of two AZs, so no account default is relied on."""
    vpc_name = ctx.unique_name("sim2real-vpclink-prov-vpc-")
    vpc = ec2.create_vpc(
        CidrBlock="10.213.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )
    vpc_id = vpc["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    assert len(azs) == 2, f"a VpcLink here needs subnets in two AZs, the region lists {azs!r}"
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_name = ctx.unique_name(f"sim2real-vpclink-prov-subnet{i}-")
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.213.0.{i * 64}/26",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}],
        )
        subnet_id = subnet["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    """Poll probe() until predicate(value); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _vpc_link_state(apigw, vpc_link_id):
    """The VpcLinkStatus while the link exists, else the error code GetVpcLink raised."""
    try:
        return apigw.get_vpc_link(VpcLinkId=vpc_link_id)["VpcLinkStatus"]
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _delete_and_wait_gone(apigw, vpc_link_id: str) -> None:
    """Delete the VpcLink and wait until GetVpcLink 404s, so its subnets can be deleted next."""
    try:
        apigw.delete_vpc_link(VpcLinkId=vpc_link_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    _poll_until(
        lambda: _vpc_link_state(apigw, vpc_link_id),
        lambda state: state == "NotFoundException",
        timeout_s=300.0,
        interval_s=10.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
