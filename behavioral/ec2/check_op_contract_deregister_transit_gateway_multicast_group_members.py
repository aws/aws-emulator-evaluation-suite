"""op-contract-deregister-transit-gateway-multicast-group-members."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-deregister-transit-gateway-multicast-group-members"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterTransitGatewayMulticastGroupMembers removes a network
    interface from a multicast group so it stops showing up as a member;
    deregistering against an unknown multicast domain 404s."""
    ec2 = ctx.client("ec2")
    env = _setup_multicast_env(ctx)
    group_ip = "224.0.1.5"

    reg = ec2.register_transit_gateway_multicast_group_members(
        TransitGatewayMulticastDomainId=env["domain_id"],
        GroupIpAddress=group_ip,
        NetworkInterfaceIds=[env["eni_id"]],
    )["RegisteredMulticastGroupMembers"]
    assert env["eni_id"] in reg["RegisteredNetworkInterfaceIds"]
    assert reg["GroupIpAddress"] == group_ip

    def _is_member():
        groups = ec2.search_transit_gateway_multicast_groups(
            TransitGatewayMulticastDomainId=env["domain_id"],
            Filters=[{"Name": "group-ip-address", "Values": [group_ip]}],
        )["MulticastGroups"]
        return any(g["NetworkInterfaceId"] == env["eni_id"] and g["GroupMember"] for g in groups)

    assert _poll_until(_is_member, lambda ok: ok, timeout_s=30, interval_s=2), "member never registered"

    # success path: deregister and observe the membership actually disappear
    dereg = ec2.deregister_transit_gateway_multicast_group_members(
        TransitGatewayMulticastDomainId=env["domain_id"],
        GroupIpAddress=group_ip,
        NetworkInterfaceIds=[env["eni_id"]],
    )["DeregisteredMulticastGroupMembers"]
    assert env["eni_id"] in dereg["DeregisteredNetworkInterfaceIds"]

    assert _poll_until(_is_member, lambda ok: not ok, timeout_s=30, interval_s=2) is False, (
        "network interface still shows as a multicast group member after deregistration"
    )

    # error boundary: deregistering against a multicast domain that doesn't exist
    bogus_domain_id = "tgw-mcast-domain-00000000000000000"
    error = _error(
        lambda: ec2.deregister_transit_gateway_multicast_group_members(
            TransitGatewayMulticastDomainId=bogus_domain_id,
            GroupIpAddress=group_ip,
            NetworkInterfaceIds=[env["eni_id"]],
        )
    )
    assert error["Code"] == "InvalidTransitGatewayMulticastDomainId.NotFound", error
    assert error.get("Message") == f"Transit Gateway Multicast Domain {bogus_domain_id} was deleted or does not exist.", error


# ===== helpers =====
def _error(fn):
    """Call fn() and return its botocore Error dict; a call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


_GONE = frozenset({
    "InvalidTransitGatewayID.NotFound", "InvalidTransitGatewayAttachmentID.NotFound",
    "InvalidNetworkInterfaceID.NotFound", "InvalidTransitGatewayMulticastDomainId.NotFound",
})
_BUSY = frozenset({"IncorrectState", "DependencyViolation", "InvalidNetworkInterface.InUse"})


def _cleanup(fn, deadline_s=45.0):
    """Run one teardown call: a resource already gone returns; one AWS is still releasing is
    retried every 2 s for up to deadline_s; any other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + deadline_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _GONE:
                return
            if code not in _BUSY or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _get_or_create_vpc_and_subnet(ctx, ec2, cidr_vpc, cidr_subnet, az):
    """Reuse the run's shared network (and a subnet in it) when one exists,
    rather than always creating a brand-new VPC. Many sibling checks in this
    behavioral suite each provision their own VPC, and the per-region VPC
    quota is small and shared, so unconditionally creating one here can raise
    VpcLimitExceeded even though nothing about this specific test requires a
    dedicated VPC."""
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "availability-zone", "Values": [az]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        )["Subnets"]
        if subnets:
            return vpc_id, subnets[0]["SubnetId"]

    vpc_id = ec2.create_vpc(
        CidrBlock=cidr_vpc,
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=cidr_subnet,
        AvailabilityZone=az,
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


def _get_or_create_multicast_tgw(ctx, ec2):
    """Reuse an existing available transit gateway that already has
    multicast support enabled when one exists, rather than always creating
    a brand-new transit gateway. The per-account transit gateway quota is
    small (and shared with sibling checks in this suite as well as other
    resources in the account), so unconditionally creating one here can
    raise TransitGatewayLimitExceeded even though nothing about this
    specific test requires a dedicated transit gateway. Returns
    (tgw_id, created)."""
    tgws = ec2.describe_transit_gateways(Filters=[{"Name": "state", "Values": ["available", "pending"]}])[
        "TransitGateways"
    ]
    for tgw in tgws:
        if tgw.get("Options", {}).get("MulticastSupport") == "enable":
            return tgw["TransitGatewayId"], False

    tgw_id = ec2.create_transit_gateway(
        Options={"MulticastSupport": "enable"},
        TagSpecifications=[
            {"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-tgw-")}]}
        ],
    )["TransitGateway"]["TransitGatewayId"]
    return tgw_id, True


def _setup_multicast_env(ctx):
    """Build a minimal VPC + TGW (multicast-enabled) + associated multicast
    domain + ENI, wiring cleanup in reverse creation order."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"][0]["ZoneName"]

    vpc_id, subnet_id = _get_or_create_vpc_and_subnet(ctx, ec2, "10.202.0.0/16", "10.202.1.0/24", az)

    tgw_id, created = _get_or_create_multicast_tgw(ctx, ec2)
    if created:
        ctx.on_cleanup(lambda: _cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id), deadline_s=300.0))

    def _tgw_state():
        return ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"]

    assert _poll_until(_tgw_state, lambda s: s == "available", timeout_s=300, interval_s=5) == "available"

    # A transit gateway only allows one non-deleted VPC attachment per VPC;
    # since the transit gateway (and possibly the VPC) may be reused across
    # runs/sibling checks, look for an existing non-deleted attachment
    # between this VPC and TGW before creating a new one, to avoid
    # DuplicateTransitGatewayAttachment.
    existing_attachments = ec2.describe_transit_gateway_vpc_attachments(
        Filters=[
            {"Name": "transit-gateway-id", "Values": [tgw_id]},
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available", "pending", "modifying"]},
        ]
    )["TransitGatewayVpcAttachments"]

    attachment_created = False
    if existing_attachments:
        attachment_id = existing_attachments[0]["TransitGatewayAttachmentId"]
    else:
        attachment_id = ec2.create_transit_gateway_vpc_attachment(
            TransitGatewayId=tgw_id,
            VpcId=vpc_id,
            SubnetIds=[subnet_id],
            TagSpecifications=[
                {
                    "ResourceType": "transit-gateway-attachment",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-tgwa-")}],
                }
            ],
        )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
        attachment_created = True

    if attachment_created:
        def _cleanup_attachment():
            _cleanup(lambda: ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment_id))

        ctx.on_cleanup(_cleanup_attachment)

    def _attachment_state():
        return ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attachment_id])[
            "TransitGatewayVpcAttachments"
        ][0]["State"]

    assert _poll_until(_attachment_state, lambda s: s == "available", timeout_s=300, interval_s=5) == "available"

    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "network-interface", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-eni-")}]}
        ],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id)))

    domain_id = ec2.create_transit_gateway_multicast_domain(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {
                "ResourceType": "transit-gateway-multicast-domain",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-mdom-")}],
            }
        ],
    )["TransitGatewayMulticastDomain"]["TransitGatewayMulticastDomainId"]
    ctx.on_cleanup(
        lambda: _cleanup(lambda: ec2.delete_transit_gateway_multicast_domain(TransitGatewayMulticastDomainId=domain_id))
    )

    def _domain_state():
        return ec2.describe_transit_gateway_multicast_domains(TransitGatewayMulticastDomainIds=[domain_id])[
            "TransitGatewayMulticastDomains"
        ][0]["State"]

    assert _poll_until(_domain_state, lambda s: s == "available", timeout_s=60, interval_s=2) == "available"

    def _cleanup_association():
        _cleanup(
            lambda: ec2.disassociate_transit_gateway_multicast_domain(
                TransitGatewayMulticastDomainId=domain_id,
                TransitGatewayAttachmentId=attachment_id,
                SubnetIds=[subnet_id],
            )
        )

        def _post_dissoc_state():
            assocs = ec2.get_transit_gateway_multicast_domain_associations(
                TransitGatewayMulticastDomainId=domain_id
            )["MulticastDomainAssociations"]
            matching = [a for a in assocs if a["Subnet"]["SubnetId"] == subnet_id]
            return matching[0]["Subnet"]["State"] if matching else None

        # give the disassociation time to fully settle so the shared default
        # subnet is actually free before this check (or a sibling check
        # reusing the same subnet) tries to associate it with another domain
        _cleanup(
            lambda: _poll_until(
                _post_dissoc_state, lambda s: s in (None, "disassociated"), timeout_s=60, interval_s=3
            )
        )

    ctx.on_cleanup(_cleanup_association)

    # The reused default subnet may still be finishing its disassociation
    # from a just-deleted multicast domain (this check's own prior run, or a
    # sibling check that shares the same default subnet); that teardown is
    # asynchronous even after the domain-delete call returns, so tolerate a
    # transient Resource.AlreadyAssociated here and retry within a bounded
    # window rather than treating it as a hard failure.
    from botocore.exceptions import ClientError

    assoc_deadline = time.monotonic() + 120
    while True:
        try:
            ec2.associate_transit_gateway_multicast_domain(
                TransitGatewayMulticastDomainId=domain_id,
                TransitGatewayAttachmentId=attachment_id,
                SubnetIds=[subnet_id],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "Resource.AlreadyAssociated" or time.monotonic() >= assoc_deadline:
                raise
            time.sleep(5)

    def _association_state():
        assocs = ec2.get_transit_gateway_multicast_domain_associations(
            TransitGatewayMulticastDomainId=domain_id
        )["MulticastDomainAssociations"]
        matching = [a for a in assocs if a["Subnet"]["SubnetId"] == subnet_id]
        return matching[0]["Subnet"]["State"] if matching else None

    assert _poll_until(_association_state, lambda s: s == "associated", timeout_s=120, interval_s=3) == "associated"

    return {
        "vpc_id": vpc_id,
        "subnet_id": subnet_id,
        "tgw_id": tgw_id,
        "attachment_id": attachment_id,
        "eni_id": eni_id,
        "domain_id": domain_id,
    }


# AWS-managed ENIs (endpoints, load balancers, instances) leave a VPC asynchronously after their
# owner's delete returns, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can fail with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry inside the same window, and raise
# naming any ENIs still attached. Teardown-only: run() never calls this.
_NET_TEARDOWN_S = 300.0
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
