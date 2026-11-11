"""op-contract-search-transit-gateway-multicast-groups."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-search-transit-gateway-multicast-groups"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchTransitGatewayMulticastGroups reports a network interface registered as a static
    multicast group member for its group IP, and rejects an unknown multicast domain id with a
    NotFound error."""
    ec2 = ctx.client("ec2")

    vpc_id = _create_vpc_with_retry(ec2, "10.91.0.0/16", name=ctx.unique_name("sim2real-mcast-vpc-"))
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.91.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-mcast-subnet-")}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    tgw_id = _create_tgw_with_retry(
        ec2,
        description=ctx.unique_name("sim2real-tgw-"),
        options={"MulticastSupport": "enable", "AutoAcceptSharedAttachments": "disable"},
    )
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))
    assert _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0][
            "State"
        ],
        lambda state: state == "available",
        timeout_s=300,
        interval_s=10,
    ), "transit gateway never became available"

    attachment_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id,
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        TagSpecifications=[
            {
                "ResourceType": "transit-gateway-attachment",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-mcast-tgwa-")}],
            }
        ],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(
        lambda: _teardown_and_wait(
            lambda: ec2.delete_transit_gateway_vpc_attachment(
                TransitGatewayAttachmentId=attachment_id
            ),
            lambda: ec2.describe_transit_gateway_vpc_attachments(
                TransitGatewayAttachmentIds=[attachment_id]
            )["TransitGatewayVpcAttachments"][0]["State"],
            settle=("pending", "modifying"),
        )
    )
    assert _poll_until(
        lambda: ec2.describe_transit_gateway_vpc_attachments(
            TransitGatewayAttachmentIds=[attachment_id]
        )["TransitGatewayVpcAttachments"][0]["State"],
        lambda state: state == "available",
        timeout_s=600,
        interval_s=10,
    ), "transit gateway VPC attachment never became available"

    domain_id = ec2.create_transit_gateway_multicast_domain(
        TransitGatewayId=tgw_id,
        Options={
            "Igmpv2Support": "disable",
            "StaticSourcesSupport": "enable",
            "AutoAcceptSharedAssociations": "disable",
        },
        TagSpecifications=[
            {
                "ResourceType": "transit-gateway-multicast-domain",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-mcast-domain-")}],
            }
        ],
    )["TransitGatewayMulticastDomain"]["TransitGatewayMulticastDomainId"]
    ctx.on_cleanup(
        lambda: _teardown_and_wait(
            lambda: ec2.delete_transit_gateway_multicast_domain(
                TransitGatewayMulticastDomainId=domain_id
            ),
            lambda: ec2.describe_transit_gateway_multicast_domains(
                TransitGatewayMulticastDomainIds=[domain_id]
            )["TransitGatewayMulticastDomains"][0]["State"],
        )
    )
    assert _poll_until(
        lambda: ec2.describe_transit_gateway_multicast_domains(
            TransitGatewayMulticastDomainIds=[domain_id]
        )["TransitGatewayMulticastDomains"][0]["State"],
        lambda state: state == "available",
        timeout_s=120,
        interval_s=5,
    ), "multicast domain never became available"

    ec2.associate_transit_gateway_multicast_domain(
        TransitGatewayMulticastDomainId=domain_id,
        TransitGatewayAttachmentId=attachment_id,
        SubnetIds=[subnet_id],
    )
    ctx.on_cleanup(
        lambda: _teardown_and_wait(
            lambda: ec2.disassociate_transit_gateway_multicast_domain(
                TransitGatewayMulticastDomainId=domain_id,
                TransitGatewayAttachmentId=attachment_id,
                SubnetIds=[subnet_id],
            ),
            lambda: _association_state(ec2, domain_id, subnet_id) or "disassociated",
            gone=("disassociated",),
        )
    )
    assert _poll_until(
        lambda: _association_state(ec2, domain_id, subnet_id),
        lambda state: state == "associated",
        timeout_s=180,
        interval_s=10,
    ), "subnet association with the multicast domain never became associated"

    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        Description=ctx.unique_name("sim2real-mcast-eni-"),
        TagSpecifications=[
            {"ResourceType": "network-interface", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-mcast-eni-")}]}
        ],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    group_ip = "224.0.1.5"
    ec2.register_transit_gateway_multicast_group_members(
        TransitGatewayMulticastDomainId=domain_id,
        GroupIpAddress=group_ip,
        NetworkInterfaceIds=[eni_id],
    )
    ctx.on_cleanup(
        lambda: ec2.deregister_transit_gateway_multicast_group_members(
            TransitGatewayMulticastDomainId=domain_id,
            GroupIpAddress=group_ip,
            NetworkInterfaceIds=[eni_id],
        )
    )

    def _member_found():
        resp = ec2.search_transit_gateway_multicast_groups(
            TransitGatewayMulticastDomainId=domain_id,
            Filters=[{"Name": "group-ip-address", "Values": [group_ip]}],
        )
        for group in resp.get("MulticastGroups", []):
            if group.get("NetworkInterfaceId") == eni_id and group.get("GroupMember"):
                return True
        return False

    assert _poll_until(_member_found, lambda ok: ok, timeout_s=90, interval_s=5), (
        "registered ENI never showed up as a multicast group member via "
        "SearchTransitGatewayMulticastGroups"
    )

    err = _error(
        lambda: ec2.search_transit_gateway_multicast_groups(
            TransitGatewayMulticastDomainId="tgw-mcast-domain-00000000000000000"
        )
    )
    assert err["Code"] == "InvalidTransitGatewayMulticastDomainId.NotFound", (
        f"expected InvalidTransitGatewayMulticastDomainId.NotFound, got {err!r}"
    )
    assert err.get("Message") == "Transit Gateway Multicast Domain tgw-mcast-domain-00000000000000000 was deleted or does not exist.", (
        f"unexpected message: {err.get('Message')!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _teardown_and_wait(delete, state, *, gone=("deleted",), settle=(), timeout_s=600.0, interval_s=10.0):
    """Teardown only: wait out any ``settle`` state the delete is refused in, issue the
    asynchronous delete, then wait until the resource reads as gone, so the next teardown
    step does not hit a dependency that is still deleting. A NotFound on the read also
    counts as gone."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while settle and time.monotonic() < deadline:
        try:
            if state() not in settle:
                break
        except ClientError as err:
            if err.response["Error"]["Code"] not in (
                "InvalidTransitGatewayAttachmentID.NotFound",
                "InvalidTransitGatewayMulticastDomainId.NotFound",
            ):
                raise
            break
        time.sleep(interval_s)
    delete()
    while True:
        try:
            current = state()
        except ClientError as exc:
            if exc.response["Error"]["Code"].endswith("NotFound"):
                return
            raise
        if current in gone:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown did not finish within {timeout_s}s (state {current!r})")
        time.sleep(interval_s)


def _create_vpc_with_retry(
    ec2, cidr_block: str, *, name: str, timeout_s: float = 300.0, interval_s: float = 15.0
):
    """create_vpc can transiently fail with VpcLimitExceeded when many other tests are
    concurrently exercising their own dedicated VPCs against the same per-region quota;
    that quota frees up as those tests tear down, so retry with a bounded backoff rather
    than treating it as a real defect."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(
                CidrBlock=cidr_block,
                TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
            )["Vpc"]["VpcId"]
        except ClientError as exc:
            if (
                exc.response.get("Error", {}).get("Code") != "VpcLimitExceeded"
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _create_tgw_with_retry(
    ec2, *, description: str, options: dict, timeout_s: float = 520.0, interval_s: float = 20.0
):
    """Transit gateways are a low, account-wide quota (default 5/region) shared with every other
    concurrently-running multicast check in this suite, each holding a TGW for its own duration;
    retry with a bounded backoff on TransitGatewayLimitExceeded rather than treating a sibling's
    still-running TGW as a real capacity shortfall."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_transit_gateway(
                Description=description,
                Options=options,
                TagSpecifications=[
                    {"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": description}]}
                ],
            )["TransitGateway"]["TransitGatewayId"]
        except ClientError as exc:
            if (
                exc.response.get("Error", {}).get("Code") != "TransitGatewayLimitExceeded"
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        try:
            result = probe()
        except Exception:
            result = None
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result if predicate(result) else False


def _association_state(ec2, domain_id: str, subnet_id: str):
    resp = ec2.get_transit_gateway_multicast_domain_associations(
        TransitGatewayMulticastDomainId=domain_id
    )
    for assoc in resp.get("MulticastDomainAssociations", []):
        if assoc.get("Subnet", {}).get("SubnetId") == subnet_id:
            return assoc.get("Subnet", {}).get("State")
    return None


# Network teardown: an async delete's AWS-managed ENIs hold the subnet / security group / VPC in
# DependencyViolation, so wait for them to go and retry DependencyViolation to one deadline shared by
# all of a check's network deletes (within the suite cleanup budget), then raise naming the ENIs left.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
