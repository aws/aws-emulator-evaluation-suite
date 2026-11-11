"""responder-gateway-lifecycle-reaches-active."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "responder-gateway-lifecycle-reaches-active"
GROUP = "lifecycle"
SERVICES = ["rtbfabric"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created responder gateway transitions PENDING_CREATION -> ACTIVE and persists port/protocol."""
    network = _create_network(ctx)
    rtb = ctx.client("rtbfabric")
    domain_name = f"{ctx.unique_name('sim2real-rtb-')}.example.com"
    resp = rtb.create_responder_gateway(
        vpcId=network["vpc_id"],
        subnetIds=[network["subnet_id"]],
        securityGroupIds=[network["sg_id"]],
        port=8443,
        protocol="HTTPS",
        domainName=domain_name,
        clientToken=ctx.unique_name("tok-"),
    )
    gateway_id = resp["gatewayId"]
    ctx.on_cleanup(lambda: rtb.delete_responder_gateway(gatewayId=gateway_id))
    assert resp["status"] in ("PENDING_CREATION", "ACTIVE"), (
        f"expected PENDING_CREATION or ACTIVE, got {resp['status']!r}"
    )

    status = _poll_until(
        lambda: rtb.get_responder_gateway(gatewayId=gateway_id)["status"],
        lambda s: s in ("ACTIVE", "ERROR"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert status == "ACTIVE", f"responder gateway settled in status {status}, expected ACTIVE"

    described = rtb.get_responder_gateway(gatewayId=gateway_id)
    assert described["port"] == 8443, f"expected port 8443, got {described['port']!r}"
    assert described["protocol"] == "HTTPS", f"expected protocol HTTPS, got {described['protocol']!r}"
    assert described["vpcId"] == network["vpc_id"], f"expected vpcId {network['vpc_id']}, got {described['vpcId']!r}"
    assert described["domainName"] == domain_name, f"expected domainName {domain_name}, got {described['domainName']!r}"
    assert described["subnetIds"] == [network["subnet_id"]], (
        f"expected subnetIds {[network['subnet_id']]}, got {described['subnetIds']!r}"
    )


# ===== helpers (self-contained) =====
def _create_network(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-rtbfabric-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.99.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
        interval_s=2.0,
    )
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.99.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=name,
        Description="sim2real rtbfabric behavioral test sg",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "sg_id": sg_id}


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation, and swallowing that leaks the VPC
# while the check passes. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached; every other error propagates. Teardown-only: nothing run() executes calls this, so it
# cannot change the verdict. The window is shared by all of one check's network deletes and fits
# the suite's 900 s cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
