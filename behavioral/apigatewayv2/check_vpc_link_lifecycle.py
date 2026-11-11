"""vpc-link-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-link-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcLink transitions PENDING -> AVAILABLE, UpdateVpcLink mutates Name, DeleteVpcLink ->
    NotFoundException on an independent GetVpcLink, and an UpdateVpcLink on the same dead id also 404s."""
    ec2 = ctx.client("ec2")
    apigw = ctx.client("apigatewayv2")

    subnet_ids = _provision_subnets(ctx, ec2)

    name = ctx.unique_name("sim2real-vpclink-")
    created = apigw.create_vpc_link(Name=name, SubnetIds=subnet_ids, Tags={"Name": name})
    vpc_link_id = created["VpcLinkId"]
    ctx.on_cleanup(lambda: _delete_and_wait_gone(apigw, vpc_link_id))
    assert created["Name"] == name, f"expected Name={name!r} on create response, got {created['Name']!r}"

    status = _poll_until(
        lambda: apigw.get_vpc_link(VpcLinkId=vpc_link_id)["VpcLinkStatus"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert status == "AVAILABLE", f"VpcLink reached {status}, expected AVAILABLE"

    new_name = ctx.unique_name("sim2real-vpclink-upd-")
    apigw.update_vpc_link(VpcLinkId=vpc_link_id, Name=new_name)

    def _updated_name():
        return apigw.get_vpc_link(VpcLinkId=vpc_link_id)

    resp = _poll_until(
        _updated_name,
        lambda r: r["VpcLinkStatus"] in ("AVAILABLE", "FAILED"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert resp["VpcLinkStatus"] == "AVAILABLE", f"expected AVAILABLE after rename, got {resp['VpcLinkStatus']}"
    assert resp["Name"] == new_name, f"expected renamed Name={new_name!r} via independent GetVpcLink, got {resp['Name']!r}"

    apigw.delete_vpc_link(VpcLinkId=vpc_link_id)
    _poll_until(
        lambda: _vpc_link_state(apigw, vpc_link_id),
        lambda state: state == "NotFoundException",
        timeout_s=300.0,
        interval_s=10.0,
    )
    code, message = _error(lambda: apigw.get_vpc_link(VpcLinkId=vpc_link_id))
    assert (code, message) == ("NotFoundException", "Invalid Vpc Link identifier specified"), (
        f"GetVpcLink on the deleted VpcLinkId: got {code!r} {message!r}"
    )

    code, message = _error(lambda: apigw.update_vpc_link(VpcLinkId=vpc_link_id, Name="sim2real-dead-vpclink"))
    assert code == "NotFoundException", (
        f"UpdateVpcLink on a deleted VpcLinkId should also 404 with NotFoundException, got {code!r}"
    )
    assert message == "Invalid Vpc Link identifier specified", (
        f"UpdateVpcLink on the deleted VpcLinkId: message {message!r}"
    )


# ===== helpers =====
def _provision_subnets(ctx, ec2) -> list[str]:
    """Provision a dedicated VPC + one subnet per AZ (up to 2) instead of depending on an
    ambient default VPC, which a freshly provisioned account may not have."""
    vpc_name = ctx.unique_name("sim2real-vpclink-vpc-")
    vpc = ec2.create_vpc(
        CidrBlock="10.212.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )
    vpc_id = vpc["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_name = ctx.unique_name(f"sim2real-vpclink-subnet{i}-")
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.212.0.{i * 64}/26",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}],
        )
        subnet_id = subnet["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _error(fn):
    """(code, message) of the AWS error fn() raised. RAISES if fn() succeeded."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, it succeeded: {result!r}")


def _vpc_link_state(apigw, vpc_link_id):
    """The VpcLinkStatus while the link exists, else the error code GetVpcLink raised."""
    try:
        return apigw.get_vpc_link(VpcLinkId=vpc_link_id)["VpcLinkStatus"]
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _delete_and_wait_gone(apigw, vpc_link_id: str) -> None:
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
        interval_s=2.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
