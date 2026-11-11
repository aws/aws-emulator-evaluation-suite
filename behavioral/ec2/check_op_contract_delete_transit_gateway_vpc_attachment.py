"""op-contract-deleteTransitGatewayVpcAttachment."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteTransitGatewayVpcAttachment"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGatewayVpcAttachment tears down an available attachment; bogus id -> NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwvpc-")

    tgw_id = _create_tgw(ctx, ec2, name)
    vpc_id, subnet_id = _create_vpc_and_subnet(ctx, ec2, name)
    attach_id = _create_vpc_attachment(ctx, ec2, tgw_id, vpc_id, subnet_id, name)

    state = _poll(
        lambda: _attachment_state(ec2, attach_id),
        lambda s: s == "available",
        timeout_s=240.0,
    )
    assert state == "available", f"vpc attachment never became available (last={state})"

    delete_resp = ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attach_id)
    delete_state = delete_resp["TransitGatewayVpcAttachment"]["State"]
    assert delete_state in ("deleting", "deleted"), f"unexpected state on delete response: {delete_state}"

    final_state = _poll(
        lambda: _attachment_state(ec2, attach_id, treat_notfound_as="deleted"),
        lambda s: s == "deleted",
        timeout_s=240.0,
    )
    assert final_state == "deleted", f"vpc attachment never reached deleted (last={final_state})"

    bogus_attachment_id = "tgw-attach-0123456789abcdef0"
    error = _error(
        lambda: ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=bogus_attachment_id)
    )
    assert error["Code"] == "InvalidTransitGatewayAttachmentID.NotFound", error
    assert error.get("Message") == f"Transit Gateway VPC Attachment {bogus_attachment_id} was deleted or does not exist.", error


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


def _attachment_state(ec2, attach_id, treat_notfound_as=None):
    try:
        resp = ec2.describe_transit_gateway_attachments(TransitGatewayAttachmentIds=[attach_id])
        attachments = resp["TransitGatewayAttachments"]
        if not attachments:
            if treat_notfound_as:
                return treat_notfound_as
            raise AssertionError("attachment disappeared from describe unexpectedly")
        return attachments[0]["State"]
    except ClientError as exc:
        if treat_notfound_as and "NotFound" in exc.response["Error"]["Code"]:
            return treat_notfound_as
        raise


def _reclaim_stale_tgws(ec2, min_age_s=1200.0):
    """Best-effort: free account TGW quota tied up by transit gateways THIS SAME
    self-contained suite created and failed to tear down (e.g. an earlier check in the
    same run that crashed/timed out before its own cleanup ran). Only ever deletes an
    "available" TGW carrying this suite's Name-tag prefix, with no live attachment, AND
    old enough (well beyond any single check's own timeout budget) that it cannot be a
    TGW a concurrently-running check just created and hasn't finished attaching to yet --
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


def _create_tgw(ctx, ec2, name):
    created = _retry_on_tgw_limit(
        ec2,
        lambda: ec2.create_transit_gateway(
            Description=name,
            TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
        ),
    )
    tgw_id = created["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))
    _poll(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180.0,
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
            CidrBlock="10.211.0.0/24",
            TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
        ),
    )
    vpc_id = vpc["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), busy_s=0))
    _poll(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
    )
    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.211.0.0/26",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    subnet_id = subnet["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id), busy_s=0))
    return vpc_id, subnet_id


def _create_vpc_attachment(ctx, ec2, tgw_id, vpc_id, subnet_id, name):
    created = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id,
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        TagSpecifications=[{"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    attach_id = created["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attach_id))
    )
    return attach_id


# A parent delete is refused while a child it depends on is still deleting. Per call, and
# together with the network teardown, the retries fit the suite cleanup budget.
_BUSY = ("IncorrectState", "DependencyViolation")
_BUSY_RETRY_S = 90.0


def _best_effort(fn, busy_s=_BUSY_RETRY_S):
    """Run one teardown call: already gone returns; refused as busy is retried every 2 s for up
    to busy_s; anything else raises."""
    deadline = time.monotonic() + busy_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in (
                "InvalidNetworkInterfaceID.NotFound",
                "InvalidTransitGatewayAttachmentID.NotFound",
                "InvalidTransitGatewayID.NotFound",
            ):
                return
            if code not in _BUSY or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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
