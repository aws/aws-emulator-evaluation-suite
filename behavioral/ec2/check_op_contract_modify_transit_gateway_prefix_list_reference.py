"""op-contract-modify-transit-gateway-prefix-list-reference."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-transit-gateway-prefix-list-reference"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyTransitGatewayPrefixListReference sets Blackhole true, which a later read confirms; an
    unknown route table id fails with InvalidRouteTableID.NotFound and its exact message."""
    ec2 = ctx.client("ec2")
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}

    # TransitGateway is a scarce, account-wide resource with a low default quota (typically 5 per
    # region). Hitting TransitGatewayLimitExceeded here reflects the account's pre-existing usage,
    # not anything this check is verifying, so treat it as a skip rather than a failure.
    from botocore.exceptions import ClientError

    try:
        tgw_id = ec2.create_transit_gateway(Description=ctx.unique_name("sim2real-tgw-"))["TransitGateway"][
            "TransitGatewayId"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "TransitGatewayLimitExceeded":
            raise AssertionError("account is at its TransitGateway quota; cannot provision a test TGW")
        raise
    ctx.on_cleanup(lambda: _delete_tgw(ec2, tgw_id, teardown_deadline))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0],
        lambda t: t["State"] == "available",
        timeout_s=240,
    )

    rt_id = ec2.create_transit_gateway_route_table(TransitGatewayId=tgw_id)["TransitGatewayRouteTable"][
        "TransitGatewayRouteTableId"
    ]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=rt_id))
    _poll_until(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[rt_id])[
            "TransitGatewayRouteTables"
        ][0],
        lambda t: t["State"] == "available",
        timeout_s=120,
    )

    # A live (non-blackhole) prefix list reference must target a real
    # attachment: AWS rejects CreateTransitGatewayPrefixListReference unless
    # exactly one of Blackhole or TransitGatewayAttachmentId is provided, so
    # Blackhole=False alone (with no attachment) is a MissingParameter error.
    vpc_id = ec2.create_vpc(CidrBlock="10.236.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", teardown_deadline, VpcId=vpc_id))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0],
        lambda v: v["State"] == "available",
        timeout_s=60,
    )
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.236.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", teardown_deadline, SubnetId=subnet_id))
    attach_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id, VpcId=vpc_id, SubnetIds=[subnet_id]
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_vpc_attachment(ec2, attach_id, teardown_deadline))
    _poll_until(
        lambda: ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attach_id])[
            "TransitGatewayVpcAttachments"
        ][0],
        lambda a: a["State"] == "available",
        timeout_s=180,
    )

    pl_id = ec2.create_managed_prefix_list(
        PrefixListName=ctx.unique_name("sim2real-pl-"), MaxEntries=5, AddressFamily="IPv4"
    )["PrefixList"]["PrefixListId"]
    ctx.on_cleanup(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id))
    _poll_until(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0],
        lambda p: p["State"] == "create-complete",
        timeout_s=60,
    )

    ec2.create_transit_gateway_prefix_list_reference(
        TransitGatewayRouteTableId=rt_id, PrefixListId=pl_id, TransitGatewayAttachmentId=attach_id
    )
    ctx.on_cleanup(
        lambda: ec2.delete_transit_gateway_prefix_list_reference(
            TransitGatewayRouteTableId=rt_id, PrefixListId=pl_id
        )
    )
    _poll_until(
        lambda: _describe_ref(ec2, rt_id, pl_id), lambda r: r["State"] == "available", timeout_s=90
    )

    resp = ec2.modify_transit_gateway_prefix_list_reference(
        TransitGatewayRouteTableId=rt_id, PrefixListId=pl_id, Blackhole=True
    )
    ref = resp["TransitGatewayPrefixListReference"]
    assert ref["Blackhole"] is True, ref

    # Independent read at the destination, through a different operation than the one
    # that mutated: the mutating call's own response is not enough to prove the change stuck.
    ref_at_destination = _poll_until(
        lambda: _describe_ref(ec2, rt_id, pl_id),
        lambda r: r["State"] == "available" and r.get("Blackhole") is True,
        timeout_s=90,
    )
    assert ref_at_destination["Blackhole"] is True, ref_at_destination

    code, message = _error(
        lambda: ec2.modify_transit_gateway_prefix_list_reference(
            TransitGatewayRouteTableId="tgw-rtb-00000000000000000", PrefixListId=pl_id, Blackhole=True
        )
    )
    # A well-formed-but-fabricated (all-zero) transit gateway route table ID passes AWS's ID
    # format validation and fails the existence lookup instead, with the generic (non-TGW-prefixed)
    # route table error code.
    assert code == "InvalidRouteTableID.NotFound", f"unexpected error code: {code}"
    assert message == (
        "Transit Gateway Route Table tgw-rtb-00000000000000000 was deleted or does not exist."
    ), message


# budget.cleanup_timeout for behavioral/ec2: one deadline shared by the check's transit gateway teardowns.
_TGW_TEARDOWN_S = 840.0


def _teardown_deadline(holder: dict) -> float:
    return holder.setdefault("t", time.monotonic() + _TGW_TEARDOWN_S)


def _delete_vpc_attachment(ec2, attach_id, holder):
    """Delete the VPC attachment and wait every 2 s until it reads deleted: the transit gateway refuses
    deletion with IncorrectState while an attachment remains. Raises at the shared deadline."""
    from botocore.exceptions import ClientError

    deadline = _teardown_deadline(holder)
    try:
        ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attach_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
            raise
        return
    state = None
    while True:
        try:
            found = ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attach_id])[
                "TransitGatewayVpcAttachments"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
                raise
            return
        state = found[0]["State"] if found else "deleted"
        if state == "deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"transit gateway attachment {attach_id} still {state!r} at the teardown deadline")
        time.sleep(2)


def _delete_tgw(ec2, tgw_id, holder):
    """Delete the transit gateway, retrying IncorrectState every 2 s while an attachment of it is not
    deleted; an attachment of it still available is deleted again. Raises at the shared deadline."""
    from botocore.exceptions import ClientError

    deadline = _teardown_deadline(holder)
    while True:
        try:
            ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidTransitGatewayID.NotFound":
                return
            if code != "IncorrectState" or time.monotonic() >= deadline:
                raise
        attachments = ec2.describe_transit_gateway_attachments(
            Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
        )["TransitGatewayAttachments"]
        for att in attachments:
            if att["ResourceType"] == "vpc" and att["State"] == "available":
                try:
                    ec2.delete_transit_gateway_vpc_attachment(
                        TransitGatewayAttachmentId=att["TransitGatewayAttachmentId"]
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                        "IncorrectState", "InvalidTransitGatewayAttachmentID.NotFound",
                    ):
                        raise
        time.sleep(2)


# ===== helpers =====
def _describe_ref(ec2, rt_id, pl_id):
    resp = ec2.get_transit_gateway_prefix_list_references(
        TransitGatewayRouteTableId=rt_id, Filters=[{"Name": "prefix-list-id", "Values": [pl_id]}]
    )
    refs = resp["TransitGatewayPrefixListReferences"]
    return refs[0] if refs else {"State": "pending"}


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


# EC2 network teardown: an asynchronously deleted dependent leaves its ENIs in the subnet / security
# group, so each delete retries DependencyViolation while they drain, inside the network window and the
# check's shared teardown deadline, then raises naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, holder, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = min(held[1], _teardown_deadline(holder))
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
                        f"{op}({ident}): DependencyViolation at the teardown deadline; "
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
