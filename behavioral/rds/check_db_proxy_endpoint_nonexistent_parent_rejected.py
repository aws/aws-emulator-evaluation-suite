"""db-proxy-endpoint-nonexistent-parent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "db-proxy-endpoint-nonexistent-parent-rejected"
GROUP = "db_proxy"
SERVICES = ["rds", "ec2"]


def _rejection(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBProxyEndpoint rejects a DBProxyName naming a proxy that does not exist with
    DBProxyNotFoundFault; ModifyDBProxyEndpoint rejects an endpoint name that does not exist with
    DBProxyEndpointNotFoundFault. A plain describe on the same account still succeeds."""
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")

    control = rds.describe_db_proxies(MaxRecords=20)
    assert "DBProxies" in control, (
        f"positive control failed: unfiltered describe_db_proxies returned {control!r}"
    )

    want_type = "t3.micro"
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [want_type]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert len(usable) >= 2, f"need 2 AZs offering {want_type!r}; offered zones were {usable!r}"

    vpc = ec2.create_vpc(CidrBlock="10.80.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc))
    ec2.create_tags(Resources=[vpc], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-dbpe-vpc-")}])

    subnet_ids = []
    for i, az in enumerate(usable[:2]):
        subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=f"10.80.{i}.0/24", AvailabilityZone=az)[
            "Subnet"
        ]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet: ec2.delete_subnet(SubnetId=s))
        subnet_ids.append(subnet)

    ghost_proxy = ctx.unique_name("sim2real-dbp-")
    err_create = _rejection(
        lambda: rds.create_db_proxy_endpoint(
            DBProxyName=ghost_proxy,
            DBProxyEndpointName=ctx.unique_name("sim2real-dbpe-"),
            VpcSubnetIds=subnet_ids,
        )
    )
    assert err_create.get("Code") == "DBProxyNotFoundFault", (
        f"CreateDBProxyEndpoint on a nonexistent proxy: expected DBProxyNotFoundFault, "
        f"got {err_create}"
    )
    expected_create_msg = f"DBProxy '{ghost_proxy}' not found."
    assert err_create.get("Message") == expected_create_msg, err_create.get("Message")

    ghost_endpoint = ctx.unique_name("sim2real-dbpe-")
    err_modify = _rejection(
        lambda: rds.modify_db_proxy_endpoint(DBProxyEndpointName=ghost_endpoint)
    )
    assert err_modify.get("Code") == "DBProxyEndpointNotFoundFault", (
        f"ModifyDBProxyEndpoint on a nonexistent endpoint: expected DBProxyEndpointNotFoundFault, "
        f"got {err_modify}"
    )
    expected_modify_msg = f"DBProxyEndpoint '{ghost_endpoint}' not found."
    assert err_modify.get("Message") == expected_modify_msg, err_modify.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
