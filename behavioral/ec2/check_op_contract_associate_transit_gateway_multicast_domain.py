"""op-contract-associateTransitGatewayMulticastDomain."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-associateTransitGatewayMulticastDomain"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateTransitGatewayMulticastDomain wires a subnet into a multicast domain; DryRun rejects."""
    ec2 = ctx.client("ec2")

    vpc = ec2.create_vpc(
        CidrBlock="10.194.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgwmc-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc))
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet = ec2.create_subnet(
        VpcId=vpc,
        CidrBlock="10.194.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgwmc-subnet-")}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet))

    tgw = ec2.create_transit_gateway(
        Description=ctx.unique_name("sim2real-tgw-"),
        Options={"MulticastSupport": "enable", "DefaultRouteTableAssociation": "disable"},
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgw-")}]}],
    )["TransitGateway"]["TransitGatewayId"]

    def cleanup_tgw():
        _tolerate_not_found(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw))

    ctx.on_cleanup(cleanup_tgw)
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180,
        interval_s=5,
    )

    domain = ec2.create_transit_gateway_multicast_domain(
        TransitGatewayId=tgw,
        TagSpecifications=[{"ResourceType": "transit-gateway-multicast-domain", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgwmc-domain-")}]}],
    )["TransitGatewayMulticastDomain"]["TransitGatewayMulticastDomainId"]

    def cleanup_domain():
        _tolerate_not_found(lambda: ec2.delete_transit_gateway_multicast_domain(TransitGatewayMulticastDomainId=domain))
        _poll_until(
            lambda: _domain_state(ec2, domain),
            lambda s: s in ("deleted", "missing"),
            timeout_s=180,
            interval_s=5,
        )

    ctx.on_cleanup(cleanup_domain)
    _poll_until(
        lambda: ec2.describe_transit_gateway_multicast_domains(TransitGatewayMulticastDomainIds=[domain])[
            "TransitGatewayMulticastDomains"
        ][0]["State"],
        lambda s: s == "available",
        timeout_s=120,
        interval_s=5,
    )

    attachment = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw,
        VpcId=vpc,
        SubnetIds=[subnet],
        TagSpecifications=[{"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgwmc-attach-")}]}],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]

    def cleanup_attachment():
        _tolerate_not_found(lambda: ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment))
        _poll_until(
            lambda: _attachment_state(ec2, attachment),
            lambda s: s in ("deleted", "missing"),
            timeout_s=420,
            interval_s=10,
        )

    ctx.on_cleanup(cleanup_attachment)
    _poll_until(
        lambda: _attachment_state(ec2, attachment),
        lambda s: s == "available",
        timeout_s=180,
        interval_s=5,
    )

    # error boundary: DryRun must short-circuit with DryRunOperation
    code, code_message = _error_code(
        lambda: ec2.associate_transit_gateway_multicast_domain(
            TransitGatewayMulticastDomainId=domain,
            TransitGatewayAttachmentId=attachment,
            SubnetIds=[subnet],
            DryRun=True,
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_code_message = "Request would have succeeded, but DryRun flag is set."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    # success path
    resp = ec2.associate_transit_gateway_multicast_domain(
        TransitGatewayMulticastDomainId=domain, TransitGatewayAttachmentId=attachment, SubnetIds=[subnet]
    )
    assoc = resp["Associations"]
    assert assoc["TransitGatewayAttachmentId"] == attachment, (
        f"expected attachment {attachment}, got {assoc['TransitGatewayAttachmentId']}"
    )
    assert assoc["Subnets"][0]["SubnetId"] == subnet, (
        f"expected subnet {subnet}, got {assoc['Subnets'][0]['SubnetId']}"
    )
    assert assoc["Subnets"][0]["State"] in ("associating", "associated"), (
        f"expected associating/associated, got {assoc['Subnets'][0]['State']}"
    )

    def cleanup_assoc():
        # The attachment and the domain refuse deletion while the subnet is still associated,
        # and disassociation is asynchronous, so wait for the row to leave before the next delete.
        _tolerate_not_found(
            lambda: ec2.disassociate_transit_gateway_multicast_domain(
                TransitGatewayMulticastDomainId=domain, TransitGatewayAttachmentId=attachment, SubnetIds=[subnet]
            )
        )
        _poll_until(
            lambda: [
                row
                for row in ec2.get_transit_gateway_multicast_domain_associations(
                    TransitGatewayMulticastDomainId=domain
                )["MulticastDomainAssociations"]
                if row["Subnet"]["SubnetId"] == subnet and row["Subnet"]["State"] != "disassociated"
            ],
            lambda rows: not rows,
            timeout_s=180,
            interval_s=5,
        )

    ctx.on_cleanup(cleanup_assoc)

    final = _poll_until(
        lambda: ec2.get_transit_gateway_multicast_domain_associations(
            TransitGatewayMulticastDomainId=domain
        )["MulticastDomainAssociations"],
        lambda rows: bool(rows) and rows[0]["Subnet"]["State"] == "associated",
        timeout_s=90,
        interval_s=5,
    )
    assert final[0]["TransitGatewayAttachmentId"] == attachment, (
        f"expected attachment {attachment}, got {final[0]['TransitGatewayAttachmentId']}"
    )
    assert final[0]["Subnet"]["State"] == "associated", (
        f"expected associated, got {final[0]['Subnet']['State']}"
    )


# ===== helpers =====
def _attachment_state(ec2, attachment_id: str) -> str:
    from botocore.exceptions import ClientError

    try:
        rows = ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attachment_id])[
            "TransitGatewayVpcAttachments"
        ]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code", "").endswith("NotFound"):
            return "missing"
        raise
    return rows[0]["State"] if rows else "missing"


def _domain_state(ec2, domain_id: str) -> str:
    from botocore.exceptions import ClientError

    try:
        rows = ec2.describe_transit_gateway_multicast_domains(TransitGatewayMulticastDomainIds=[domain_id])[
            "TransitGatewayMulticastDomains"
        ]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code", "").endswith("NotFound"):
            return "missing"
        raise
    return rows[0]["State"] if rows else "missing"


def _tolerate_not_found(fn: Callable[[], Any]) -> None:
    """Teardown delete: a resource that is already gone is fine; every other error propagates."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if not exc.response.get("Error", {}).get("Code", "").endswith("NotFound"):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


# EC2 network teardown: an asynchronously deleted dependent leaves its ENIs in the subnet / security
# group, so each delete retries DependencyViolation while they drain, inside one window shared by the
# check's network deletes and the suite's cleanup budget, then raises naming the ENIs still attached.
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
