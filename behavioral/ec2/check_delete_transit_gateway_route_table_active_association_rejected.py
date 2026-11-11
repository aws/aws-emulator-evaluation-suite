"""delete-transit-gateway-route-table-active-association-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-transit-gateway-route-table-active-association-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGatewayRouteTable must be rejected while an attachment is still associated with it."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwrtassoc-")

    tgw_id = _create_tgw(ctx, ec2, name)
    vpc_id, subnet_id = _create_vpc_and_subnet(ctx, ec2, name)
    attach_id = _create_vpc_attachment(ctx, ec2, tgw_id, vpc_id, subnet_id, name)
    _wait_attachment_state(ec2, attach_id, "available", timeout_s=240.0)

    route_table_id = _create_route_table(ctx, ec2, tgw_id, name)
    ec2.associate_transit_gateway_route_table(
        TransitGatewayRouteTableId=route_table_id, TransitGatewayAttachmentId=attach_id
    )
    assoc_state = _poll(
        lambda: _association_state(ec2, route_table_id, attach_id),
        lambda s: s == "associated",
        timeout_s=600.0,
    )
    assert assoc_state == "associated", f"association never settled (last={assoc_state})"

    error = _error(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_id))
    assert error["Code"] == "IncorrectState", error
    assert error.get("Message") == f"{route_table_id} has associated attachments", error

    # Independent read: the rejected delete must have left the table untouched.
    surviving_state = _rt_state(ec2, route_table_id)
    assert surviving_state == "available", f"table should still be available after the rejected delete, got {surviving_state}"

    # Clear the association, then the delete succeeds -- proving the rejection was state-specific.
    ec2.disassociate_transit_gateway_route_table(
        TransitGatewayRouteTableId=route_table_id, TransitGatewayAttachmentId=attach_id
    )
    _poll(
        lambda: _association_state(ec2, route_table_id, attach_id, treat_gone_as="gone"),
        lambda s: s == "gone",
        timeout_s=600.0,
    )
    delete_resp = ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_id)
    assert delete_resp["TransitGatewayRouteTable"]["State"] in ("deleting", "deleted")

    # Independent read: the route table must actually be gone, not just echoed as deleting.
    final_state = _poll(
        lambda: _rt_state(ec2, route_table_id, treat_notfound_as="deleted"),
        lambda s: s == "deleted",
        timeout_s=600.0,
    )
    assert final_state == "deleted", f"route table never reached deleted (last={final_state})"


# ===== helpers =====

def _poll(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn() and return its botocore Error dict; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _retry_on_incorrect_state(fn, timeout_s=180.0, interval_s=10.0):
    """A transit gateway that just reported describe-state "available" can still briefly
    reject dependent operations (e.g. CreateTransitGatewayVpcAttachment) with
    IncorrectState while the backend finishes propagating that state internally. Poll
    through that narrow window instead of treating it as fatal."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "IncorrectState":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _rt_state(ec2, route_table_id, treat_notfound_as=None):
    try:
        resp = ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[route_table_id])
        tables = resp["TransitGatewayRouteTables"]
        if not tables:
            return treat_notfound_as
        return tables[0]["State"]
    except ClientError as exc:
        if treat_notfound_as and "NotFound" in exc.response["Error"]["Code"]:
            return treat_notfound_as
        raise


def _association_state(ec2, route_table_id, attach_id, treat_gone_as=None):
    try:
        resp = ec2.get_transit_gateway_route_table_associations(
            TransitGatewayRouteTableId=route_table_id,
            Filters=[{"Name": "transit-gateway-attachment-id", "Values": [attach_id]}],
        )
        assocs = resp["Associations"]
        if not assocs:
            return treat_gone_as
        return assocs[0]["State"]
    except ClientError as exc:
        if treat_gone_as and "NotFound" in exc.response["Error"]["Code"]:
            return treat_gone_as
        raise


def _wait_attachment_state(ec2, attach_id, target, timeout_s=180.0, treat_notfound_as=None):
    def probe():
        try:
            resp = ec2.describe_transit_gateway_attachments(TransitGatewayAttachmentIds=[attach_id])
            atts = resp["TransitGatewayAttachments"]
            if not atts:
                return treat_notfound_as
            return atts[0]["State"]
        except ClientError as exc:
            if treat_notfound_as and "NotFound" in exc.response["Error"]["Code"]:
                return treat_notfound_as
            raise

    return _poll(probe, lambda s: s == target, timeout_s=timeout_s)


def _retry_on_tgw_limit(ec2, fn, timeout_s=1500.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransitGatewayLimitExceeded" or time.monotonic() >= deadline:
                raise
            _reclaim_stale_tgws(ec2)
            time.sleep(interval_s)


def _reclaim_stale_tgws(ec2, min_age_s=1200.0):
    """Best-effort: free account TGW quota tied up by transit gateways THIS SAME
    self-contained suite created and failed to tear down (e.g. an earlier check in the
    same run that crashed/timed out before its own cleanup ran). Only ever deletes an
    "available" TGW carrying this suite's Name-tag prefix, with no live attachment, AND
    old enough (well beyond any single check's own timeout budget) that it cannot be a
    TGW that a concurrently-running check just created and is still actively wiring up --
    so it can't yank a resource out from under a check that's mid-flight."""
    try:
        tgws = ec2.describe_transit_gateways(Filters=[{"Name": "state", "Values": ["available"]}])[
            "TransitGateways"
        ]
    except ClientError:
        return
    now = datetime.now(timezone.utc)
    for tgw in tgws:
        name_tag = next((t["Value"] for t in tgw.get("Tags", []) if t["Key"] == "Name"), "")
        if not name_tag.startswith("sim2real-behav-"):
            continue
        creation_time = tgw.get("CreationTime")
        if creation_time is not None and (now - creation_time).total_seconds() < min_age_s:
            continue
        tgw_id = tgw["TransitGatewayId"]
        try:
            live = ec2.describe_transit_gateway_attachments(
                Filters=[
                    {"Name": "transit-gateway-id", "Values": [tgw_id]},
                    {
                        "Name": "state",
                        "Values": [
                            "available", "pending", "pendingAcceptance", "modifying",
                            "initiatingRequest", "rollingBack",
                        ],
                    },
                ]
            )["TransitGatewayAttachments"]
        except ClientError:
            continue
        if live:
            continue
        try:
            ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
        except ClientError:
            pass


def _create_tgw(ctx, ec2, name):
    created = _retry_on_tgw_limit(
        ec2,
        lambda: ec2.create_transit_gateway(
            Description=name,
            Options={"DefaultRouteTableAssociation": "disable", "DefaultRouteTablePropagation": "disable"},
            TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
        )
    )
    tgw_id = created["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))
    _poll(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=600.0,
    )
    return tgw_id



def _retry_on_vpc_limit(ec2, fn, timeout_s=300.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_vpc_and_subnet(ctx, ec2, name):
    vpc = _retry_on_vpc_limit(
        ec2,
        lambda: ec2.create_vpc(
            CidrBlock="10.216.0.0/24",
            TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
        ),
    )
    vpc_id = vpc["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    _poll(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
    )
    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.216.0.0/26",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    subnet_id = subnet["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))
    return vpc_id, subnet_id


def _create_vpc_attachment(ctx, ec2, tgw_id, vpc_id, subnet_id, name):
    created = _retry_on_incorrect_state(
        lambda: ec2.create_transit_gateway_vpc_attachment(
            TransitGatewayId=tgw_id,
            VpcId=vpc_id,
            SubnetIds=[subnet_id],
            TagSpecifications=[
                {"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": name}]}
            ],
        )
    )
    attach_id = created["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    def _delete_attachment():
        # The delete is asynchronous and DeleteTransitGateway refuses while the attachment is not
        # deleted, so wait for it to settle.
        _best_effort(lambda: ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attach_id))
        _wait_attachment_state(ec2, attach_id, "deleted", timeout_s=600.0, treat_notfound_as="deleted")

    ctx.on_cleanup(_delete_attachment)
    return attach_id


def _create_route_table(ctx, ec2, tgw_id, name):
    created = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[{"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    route_table_id = created["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_id))
    )
    # A freshly created route table is briefly in "pending" state; associating an attachment
    # with it before AWS finishes provisioning it is rejected with IncorrectState.
    _poll(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[route_table_id])[
            "TransitGatewayRouteTables"
        ][0]["State"],
        lambda s: s == "available",
        timeout_s=600.0,
    )
    return route_table_id


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidNetworkInterfaceID.NotFound",
            "InvalidRouteTableID.NotFound",
            "InvalidTransitGatewayAttachmentID.NotFound",
            "InvalidTransitGatewayID.NotFound",
        ):
            raise


# Network teardown: resources in the VPC delete asynchronously and leave AWS-managed ENIs behind,
# so DeleteSubnet / DeleteSecurityGroup / DeleteVpc can fail with DependencyViolation. Wait (one
# window shared by a check's network deletes) for the ENIs, retrying that error, then raise.
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
