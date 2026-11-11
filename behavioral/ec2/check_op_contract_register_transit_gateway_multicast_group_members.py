"""op-contract-register-transit-gateway-multicast-group-members."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-register-transit-gateway-multicast-group-members"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterTransitGatewayMulticastGroupMembers registers a real ENI as a
    multicast group member on a real transit gateway multicast domain, and
    DryRun is honored on the registration call."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"][0]["ZoneName"]

    # Reuse the account's default VPC/subnet instead of creating a new VPC: this check only
    # needs *a* VPC+subnet to host the ENI and the TGW VPC attachment, and creating a fresh VPC
    # here is an unnecessary assumption of spare VPC quota (real accounts running many checks
    # concurrently can legitimately hit the per-region VPC limit).
    vpc_id = _default_vpc(ec2, ctx=ctx)
    subnet_id = _default_subnet(ec2, vpc_id, az, ctx=ctx)

    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "network-interface", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-mcast-eni-")}]}
        ],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _delete_eni(ec2, eni_id))

    # Transit gateways are a very low, account-wide quota (default 5/region). Under this batch's
    # concurrency, the account can be DURABLY saturated by sibling checks' own, still-running TGWs
    # -- at which point no amount of retrying CreateTransitGateway converges, because there's
    # nothing transient to wait out. We don't actually need EXCLUSIVE ownership of a transit
    # gateway though: we only need a multicast-enabled one to hang our own VPC attachment +
    # multicast domain off of (VPC attachments are a much higher per-TGW quota, so several checks
    # can safely share one TGW concurrently). Reuse any existing, available, multicast-enabled TGW
    # when one is present -- sidestepping the scarce create-quota entirely -- and only fall back to
    # creating (and later deleting) our own when none exists yet.
    reused_tgw_id = _reusable_multicast_tgw(ec2)
    if reused_tgw_id is not None:
        tgw_id = reused_tgw_id
    else:
        tgw_id = _create_tgw_with_retry(
            ec2,
            description=ctx.unique_name("sim2real-mcast-tgw-"),
            options={"MulticastSupport": "enable", "AutoAcceptSharedAttachments": "disable"},
            timeout_s=520,
            interval_s=20,
            tag_name=ctx.unique_name("sim2real-mcast-tgw-"),
        )
        ctx.on_cleanup(lambda: _delete_tgw(ec2, tgw_id))
        _poll_until(
            lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
            lambda s: s == "available",
            timeout_s=300,
            interval_s=10,
        )

    # A transit gateway permits only one non-deleted VPC attachment per (transit-gateway, vpc)
    # pair. Since `tgw_id` above may be a TGW shared/reused with concurrently-running sibling
    # checks, and `vpc_id` is always the account's single default VPC, blindly creating a new
    # attachment here can collide with one a sibling check already created for the very same
    # (tgw_id, vpc_id) pair (DuplicateTransitGatewayAttachment) even though we don't need
    # EXCLUSIVE ownership of the attachment -- reuse any existing, non-deleted one instead.
    existing_attach_id, _ = _reusable_vpc_attachment(ec2, tgw_id, vpc_id)
    if existing_attach_id is not None:
        attach_id = existing_attach_id
    else:
        try:
            attach_id = ec2.create_transit_gateway_vpc_attachment(
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
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DuplicateTransitGatewayAttachment":
                # A sibling check raced us and created its own attachment for this exact
                # (tgw_id, vpc_id) pair between our reuse-check above and this call; reuse it.
                attach_id, _ = _reusable_vpc_attachment(ec2, tgw_id, vpc_id)
                if attach_id is None:
                    raise
            else:
                raise
        else:
            ctx.on_cleanup(lambda: _delete_attachment(ec2, attach_id))
    _poll_until(
        lambda: ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attach_id])[
            "TransitGatewayVpcAttachments"
        ][0]["State"],
        lambda s: s == "available",
        timeout_s=300,
        interval_s=10,
    )

    # A subnet can be associated with only one multicast domain at a time. Since `subnet_id` above
    # is always the account's single default-for-AZ subnet, blindly creating-and-associating a
    # fresh domain here can permanently deadlock against a sibling check (e.g. the sources-side
    # counterpart of this contract test) that has already associated that very subnet with ITS OWN
    # domain -- retrying the association never converges in that case because nothing will ever
    # disassociate a domain we don't own. Reuse any existing, available, compatibly-configured
    # domain that already has our subnet associated instead of forcing exclusive ownership of the
    # association we don't actually need.
    reused_domain_id = _reusable_associated_domain(ec2, tgw_id, subnet_id)
    if reused_domain_id is not None:
        domain_id = reused_domain_id
    else:
        domain_id = ec2.create_transit_gateway_multicast_domain(
            TransitGatewayId=tgw_id,
            Options={"Igmpv2Support": "disable", "StaticSourcesSupport": "enable"},
            TagSpecifications=[
                {
                    "ResourceType": "transit-gateway-multicast-domain",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-mcast-mdom-")}],
                }
            ],
        )["TransitGatewayMulticastDomain"]["TransitGatewayMulticastDomainId"]
        ctx.on_cleanup(lambda: _delete_domain(ec2, domain_id))
        _poll_until(
            lambda: ec2.describe_transit_gateway_multicast_domains(TransitGatewayMulticastDomainIds=[domain_id])[
                "TransitGatewayMulticastDomains"
            ][0]["State"],
            lambda s: s == "available",
            timeout_s=120,
            interval_s=5,
        )

        _associate_with_retry(ec2, domain_id=domain_id, attach_id=attach_id, subnet_id=subnet_id)
        ctx.on_cleanup(lambda: _disassociate_domain(ec2, domain_id, attach_id, subnet_id))
        _poll_until(
            lambda: _association_state(ec2, domain_id, subnet_id),
            lambda s: s == "associated",
            timeout_s=120,
            interval_s=5,
        )

    # --- success path ---
    group_ip = "224.0.1.5"
    resp = ec2.register_transit_gateway_multicast_group_members(
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
    members = resp["RegisteredMulticastGroupMembers"]
    assert members["GroupIpAddress"] == group_ip
    assert eni_id in members["RegisteredNetworkInterfaceIds"]
    assert members["TransitGatewayMulticastDomainId"] == domain_id

    # --- independent read at the destination: the registration must be visible via
    # SearchTransitGatewayMulticastGroups, a different operation than the one that mutated,
    # not just echoed back in RegisterTransitGatewayMulticastGroupMembers's own response.
    def _member_registered():
        search_resp = ec2.search_transit_gateway_multicast_groups(
            TransitGatewayMulticastDomainId=domain_id,
            Filters=[{"Name": "group-ip-address", "Values": [group_ip]}],
        )
        for group in search_resp.get("MulticastGroups", []):
            if group.get("NetworkInterfaceId") == eni_id and group.get("GroupMember"):
                return True
        return False

    _poll_until(_member_registered, lambda ok: ok, timeout_s=90, interval_s=5)

    # --- error boundary: DryRun ---
    code, message = _error(
        lambda: ec2.register_transit_gateway_multicast_group_members(
            DryRun=True,
            TransitGatewayMulticastDomainId=domain_id,
            GroupIpAddress="224.0.1.6",
            NetworkInterfaceIds=[eni_id],
        )
    )
    assert (code, message) == ("DryRunOperation", _DRY_RUN_MESSAGE), (
        f"expected DryRunOperation {_DRY_RUN_MESSAGE!r}, got {code!r} {message!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. A success raises: an
    accepted call is the strongest signal and must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _create_tgw_with_retry(ec2, *, description, options, timeout_s=520.0, interval_s=20.0, tag_name=None):
    """Transit gateways are a low, account-wide quota (default 5/region). Under this batch's
    concurrent checks each holding a TGW for the duration of their run, CreateTransitGateway can
    transiently hit TransitGatewayLimitExceeded even though this check's OWN usage is a single,
    promptly-cleaned-up TGW; retry until a sibling check's cleanup frees a slot instead of failing
    outright on what is contention, not a real capacity shortfall."""
    deadline = time.monotonic() + timeout_s
    tag_specs = (
        [{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": tag_name}]}]
        if tag_name
        else []
    )
    while True:
        try:
            return ec2.create_transit_gateway(Description=description, Options=options, TagSpecifications=tag_specs)[
                "TransitGateway"
            ]["TransitGatewayId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransitGatewayLimitExceeded" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _reusable_multicast_tgw(ec2):
    """An existing, available, multicast-enabled transit gateway we can attach to instead of
    creating a new one -- see the note at the call site on why reuse (not a longer retry) is the
    real fix for this quota."""
    paginator = ec2.get_paginator("describe_transit_gateways")
    for page in paginator.paginate(Filters=[{"Name": "state", "Values": ["available"]}]):
        for tgw in page["TransitGateways"]:
            if tgw.get("Options", {}).get("MulticastSupport") == "enable":
                return tgw["TransitGatewayId"]
    return None


def _reusable_vpc_attachment(ec2, tgw_id, vpc_id):
    """An existing, non-deleted VPC attachment between this TGW and VPC that we can reuse
    instead of creating a new one -- see the note at the call site on why reuse (not a retry) is
    the real fix for the per-(tgw, vpc) attachment uniqueness constraint."""
    resp = ec2.describe_transit_gateway_vpc_attachments(
        Filters=[
            {"Name": "transit-gateway-id", "Values": [tgw_id]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    )
    for a in resp["TransitGatewayVpcAttachments"]:
        if a["State"] not in ("deleted", "deleting"):
            return a["TransitGatewayAttachmentId"], a["State"]
    return None, None


def _associate_with_retry(ec2, *, domain_id, attach_id, subnet_id, timeout_s=400.0, interval_s=10.0):
    """A (transit-gateway-attachment, subnet) pair can be associated with only one multicast
    domain at a time. Because this check may share its reused transit gateway, VPC attachment, AND
    the account's single default-for-AZ subnet with a concurrently-running sibling check that is
    also associating that very subnet to its own (different) multicast domain, real AWS can return
    Resource.AlreadyAssociated even though the conflict is transient contention, not a permanent
    one -- it clears as soon as the sibling holding it runs its own disassociate cleanup. Retry
    until that contention clears instead of failing outright."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.associate_transit_gateway_multicast_domain(
                TransitGatewayMulticastDomainId=domain_id,
                TransitGatewayAttachmentId=attach_id,
                SubnetIds=[subnet_id],
            )
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "Resource.AlreadyAssociated" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _reusable_associated_domain(ec2, tgw_id, subnet_id):
    """An existing, available multicast domain on this transit gateway (with the same
    StaticSourcesSupport config this check needs) that already has our target subnet associated --
    see the note at the call site on why reuse (not a longer retry) is the real fix for the
    per-subnet association exclusivity constraint."""
    paginator = ec2.get_paginator("describe_transit_gateway_multicast_domains")
    for page in paginator.paginate(
        Filters=[
            {"Name": "transit-gateway-id", "Values": [tgw_id]},
            {"Name": "state", "Values": ["available"]},
        ]
    ):
        for domain in page["TransitGatewayMulticastDomains"]:
            if domain.get("Options", {}).get("StaticSourcesSupport") != "enable":
                continue
            domain_id = domain["TransitGatewayMulticastDomainId"]
            try:
                assoc_resp = ec2.get_transit_gateway_multicast_domain_associations(
                    TransitGatewayMulticastDomainId=domain_id
                )
            except ClientError:
                continue
            for assoc in assoc_resp.get("MulticastDomainAssociations", []):
                subnet = assoc.get("Subnet", {})
                if subnet.get("SubnetId") == subnet_id and subnet.get("State") == "associated":
                    return domain_id
    return None


def _association_state(ec2, domain_id, subnet_id):
    resp = ec2.get_transit_gateway_multicast_domain_associations(
        TransitGatewayMulticastDomainId=domain_id
    )
    for assoc in resp.get("MulticastDomainAssociations", []):
        if assoc.get("Subnet", {}).get("SubnetId") == subnet_id:
            return assoc["Subnet"]["State"]
    return "not-found"


def _disassociate_domain(ec2, domain_id, attach_id, subnet_id):
    try:
        ec2.disassociate_transit_gateway_multicast_domain(
            TransitGatewayMulticastDomainId=domain_id,
            TransitGatewayAttachmentId=attach_id,
            SubnetIds=[subnet_id],
        )
        _poll_until(
            lambda: _association_state(ec2, domain_id, subnet_id),
            lambda s: s in ("disassociated", "not-found"),
            timeout_s=120,
            interval_s=5,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayMulticastDomainId.NotFound":
            raise


def _delete_domain(ec2, domain_id):
    try:
        ec2.delete_transit_gateway_multicast_domain(TransitGatewayMulticastDomainId=domain_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayMulticastDomainId.NotFound":
            raise


def _delete_attachment(ec2, attach_id):
    try:
        ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attach_id)
        _poll_until(
            lambda: ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attach_id])[
                "TransitGatewayVpcAttachments"
            ][0]["State"],
            lambda s: s == "deleted",
            timeout_s=180,
            interval_s=10,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
            raise


def _delete_tgw(ec2, tgw_id):
    try:
        ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayID.NotFound":
            raise


def _delete_eni(ec2, eni_id):
    try:
        ec2.delete_network_interface(NetworkInterfaceId=eni_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
            raise


def _default_vpc(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    return vpcs[0]["VpcId"]


def _default_subnet(ec2, vpc_id, az, *, ctx):
    filters = [{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "availability-zone", "Values": [az]}]
    subnets = ec2.describe_subnets(Filters=filters + [{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    return subnets[0]["SubnetId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

