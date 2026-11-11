"""link-reject-terminal-state-blocks-accept-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "link-reject-terminal-state-blocks-accept-rejected"
GROUP = "overly-permissive"
SERVICES = ["rtbfabric"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A REJECTED link is terminal: AcceptLink on it fails with ConflictException, while a fresh link can still be accepted."""
    rtb = ctx.client("rtbfabric")
    network = _create_network(ctx)
    requester_gw = _create_requester_gateway(ctx, network)
    responder_gw = _create_responder_gateway(ctx, network)
    _wait_requester_active(ctx, requester_gw)
    _wait_responder_active(ctx, responder_gw)

    # Link #1: request, then reject it (terminal state).
    rejected_link = rtb.create_link(
        gatewayId=requester_gw, peerGatewayId=responder_gw, logSettings=_log_settings()
    )
    rejected_link_id = rejected_link["linkId"]
    ctx.on_cleanup(lambda: rtb.delete_link(gatewayId=requester_gw, linkId=rejected_link_id))
    _poll_until(
        lambda: rtb.get_link(gatewayId=requester_gw, linkId=rejected_link_id)["status"],
        lambda s: s == "REQUESTED",
        timeout_s=300.0,
        interval_s=10.0,
    )
    rtb.reject_link(gatewayId=responder_gw, linkId=rejected_link_id)
    status_after_reject = _poll_until(
        lambda: rtb.get_link(gatewayId=responder_gw, linkId=rejected_link_id)["status"],
        lambda s: s == "REJECTED",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert status_after_reject == "REJECTED", f"expected REJECTED after reject_link, got {status_after_reject}"

    # Break exactly one thing: try to accept a link that is already terminally REJECTED.
    code = _error_code(
        lambda: rtb.accept_link(
            gatewayId=responder_gw, linkId=rejected_link_id, logSettings=_log_settings()
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"

    # Effect is absent: the link is still REJECTED, not ACCEPTED/ACTIVE.
    final_status = rtb.get_link(gatewayId=responder_gw, linkId=rejected_link_id)["status"]
    assert final_status == "REJECTED", f"expected link to remain REJECTED after the blocked accept, got {final_status}"

    # Positive control in the same file: a fresh REQUESTED link can be accepted successfully.
    control_link = rtb.create_link(
        gatewayId=requester_gw, peerGatewayId=responder_gw, logSettings=_log_settings()
    )
    control_link_id = control_link["linkId"]
    ctx.on_cleanup(lambda: rtb.delete_link(gatewayId=requester_gw, linkId=control_link_id))
    _poll_until(
        lambda: rtb.get_link(gatewayId=requester_gw, linkId=control_link_id)["status"],
        lambda s: s == "REQUESTED",
        timeout_s=300.0,
        interval_s=10.0,
    )
    rtb.accept_link(gatewayId=responder_gw, linkId=control_link_id, logSettings=_log_settings())
    control_status = _poll_until(
        lambda: rtb.get_link(gatewayId=responder_gw, linkId=control_link_id)["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert control_status == "ACTIVE", f"control link settled in {control_status}, expected ACTIVE"


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


def _create_requester_gateway(ctx, network):
    rtb = ctx.client("rtbfabric")
    resp = rtb.create_requester_gateway(
        vpcId=network["vpc_id"],
        subnetIds=[network["subnet_id"]],
        securityGroupIds=[network["sg_id"]],
        clientToken=ctx.unique_name("tok-"),
    )
    gateway_id = resp["gatewayId"]
    ctx.on_cleanup(lambda: rtb.delete_requester_gateway(gatewayId=gateway_id))
    return gateway_id


def _create_responder_gateway(ctx, network, port=8443, protocol="HTTPS"):
    rtb = ctx.client("rtbfabric")
    resp = rtb.create_responder_gateway(
        vpcId=network["vpc_id"],
        subnetIds=[network["subnet_id"]],
        securityGroupIds=[network["sg_id"]],
        port=port,
        protocol=protocol,
        domainName=f"{ctx.unique_name('sim2real-rtb-')}.example.com",
        clientToken=ctx.unique_name("tok-"),
    )
    gateway_id = resp["gatewayId"]
    ctx.on_cleanup(lambda: rtb.delete_responder_gateway(gatewayId=gateway_id))
    return gateway_id


def _wait_requester_active(ctx, gateway_id, timeout_s=900.0):
    rtb = ctx.client("rtbfabric")
    status = _poll_until(
        lambda: rtb.get_requester_gateway(gatewayId=gateway_id)["status"],
        lambda s: s in ("ACTIVE", "ERROR"),
        timeout_s=timeout_s,
        interval_s=15.0,
    )
    assert status == "ACTIVE", f"requester gateway settled in {status}, expected ACTIVE"


def _wait_responder_active(ctx, gateway_id, timeout_s=900.0):
    rtb = ctx.client("rtbfabric")
    status = _poll_until(
        lambda: rtb.get_responder_gateway(gatewayId=gateway_id)["status"],
        lambda s: s in ("ACTIVE", "ERROR"),
        timeout_s=timeout_s,
        interval_s=15.0,
    )
    assert status == "ACTIVE", f"responder gateway settled in {status}, expected ACTIVE"


def _log_settings():
    return {"applicationLogs": {"sampling": {"errorLog": 0.0, "filterLog": 0.0}}}


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn):
    """Call fn(); return its botocore Error code. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available and must not be
    reduced to a plain code mismatch via a falsy sentinel."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
