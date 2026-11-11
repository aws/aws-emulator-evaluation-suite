"""op-contract-disable-vgw-route-propagation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-disable-vgw-route-propagation"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Disabling VGW route propagation removes the gateway from the route table's
    PropagatingVgws set; DryRun reports DryRunOperation without changing state."""
    ec2 = ctx.client("ec2")

    # A VPC of its own: attaching a gateway to the default VPC would change account baseline.
    vpc_id = _create_with_retry(
        lambda: ec2.create_vpc(
            CidrBlock="10.72.0.0/16",
            TagSpecifications=[
                {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vgw-vpc-")}]}
            ],
        )["Vpc"]["VpcId"],
        retry_codes=("VpcLimitExceeded",),
        timeout_s=300.0,
        interval_s=15.0,
    )
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_id))

    vgw_id = _create_with_retry(
        lambda: _create_vpn_gateway(ec2, ctx),
        retry_codes=("VpnGatewayLimitExceeded",),
    )

    ctx.on_cleanup(lambda: _teardown_vgw(ec2, vgw_id, vpc_id))

    ec2.attach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=vgw_id)
    _poll_until(
        lambda: ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0]["VpcAttachments"],
        lambda atts: any(a["VpcId"] == vpc_id and a["State"] == "attached" for a in atts),
        # A gateway attaching to a newly created VPC commonly stays 'attaching' past two minutes.
        timeout_s=600.0,
        interval_s=10.0,
    )

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vgw-rtb-")}]}
        ],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_route_table(ec2, rtb_id))

    ec2.enable_vgw_route_propagation(GatewayId=vgw_id, RouteTableId=rtb_id)

    def _propagating_vgws():
        return ec2.describe_route_tables(RouteTableIds=[rtb_id])["RouteTables"][0].get("PropagatingVgws", [])

    _poll_until(
        _propagating_vgws,
        lambda vgws: any(v["GatewayId"] == vgw_id for v in vgws),
        timeout_s=60.0,
        interval_s=3.0,
    )

    # Error boundary: DryRun must report DryRunOperation without disabling propagation.
    code, message = _client_error(
        lambda: ec2.disable_vgw_route_propagation(GatewayId=vgw_id, RouteTableId=rtb_id, DryRun=True)
    )
    assert code == "DryRunOperation", code
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )
    propagating_after_dry_run = [v["GatewayId"] for v in _propagating_vgws()]
    assert vgw_id in propagating_after_dry_run, (
        f"DryRun disable must not remove {vgw_id} from PropagatingVgws, got {propagating_after_dry_run}"
    )

    # Error boundary: a route table id that doesn't exist is rejected with the
    # documented NotFound code, and the still-real vgw_id's propagation state
    # is untouched by the rejected call.
    notfound_code, notfound_message = _client_error(
        lambda: ec2.disable_vgw_route_propagation(GatewayId=vgw_id, RouteTableId="rtb-00000000000000000")
    )
    assert notfound_code == "InvalidRouteTableID.NotFound", notfound_code
    assert notfound_message == "The routeTable ID 'rtb-00000000000000000' does not exist", (
        f"unexpected InvalidRouteTableID.NotFound message: {notfound_message!r}"
    )
    propagating_after_notfound = [v["GatewayId"] for v in _propagating_vgws()]
    assert vgw_id in propagating_after_notfound, (
        f"rejected disable call must not remove {vgw_id} from PropagatingVgws, got {propagating_after_notfound}"
    )

    # DisableVgwRoutePropagation returns an empty response body on real AWS
    # (no "Return" member, unlike many other EC2 boolean-result operations) —
    # the operation's actual contract is the state change itself, which we
    # assert below via polling PropagatingVgws rather than a response field
    # that doesn't exist.
    ec2.disable_vgw_route_propagation(GatewayId=vgw_id, RouteTableId=rtb_id)

    _poll_until(
        _propagating_vgws,
        lambda vgws: not any(v["GatewayId"] == vgw_id for v in vgws),
        timeout_s=60.0,
        interval_s=3.0,
    )


def _teardown_vgw(ec2, vgw_id, vpc_id, timeout_s=600.0, interval_s=10.0):
    """Teardown: detach the gateway from the check's own VPC, wait until that attachment is
    detached, then delete the gateway. Not found is success; any other error, or a detach that
    does not finish in time, raises."""
    from botocore.exceptions import ClientError

    try:
        ec2.detach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=vgw_id)
    except ClientError as e:
        if e.response["Error"]["Code"] not in (
            "InvalidVpnGatewayID.NotFound",
            "InvalidVpnGatewayAttachment.NotFound",
        ):
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            gws = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidVpnGatewayID.NotFound":
                return
            raise
        atts = [a for gw in gws for a in gw.get("VpcAttachments", []) if a["VpcId"] == vpc_id]
        if all(a["State"] == "detached" for a in atts):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"VPN gateway {vgw_id} not detached from {vpc_id} within {timeout_s}s: {atts}")
        time.sleep(interval_s)
    try:
        ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidVpnGatewayID.NotFound":
            raise


def _delete_vpc(ec2, vpc_id, timeout_s=300.0, interval_s=10.0):
    """Teardown: delete the check's own VPC. DependencyViolation (a gateway or route table still
    releasing it) is retried; not found is success; any other error, or a timeout, raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidVpcID.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _delete_route_table(ec2, rtb_id):
    """Teardown: delete the check's own route table; not found is success, anything else raises."""
    from botocore.exceptions import ClientError

    try:
        ec2.delete_route_table(RouteTableId=rtb_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidRouteTableID.NotFound":
            raise


def _reclaim_stale_vpn_gateways(ec2):
    """Reclaim VPN gateway quota held by gateways an earlier, interrupted run of THIS check left
    behind: only an ``available`` gateway carrying this check's ``sim2real`` tag and with no
    non-detached VPC attachment is deleted. A gateway any other check or owner created is never
    touched, and neither is one still attached, attaching or detaching."""
    from botocore.exceptions import ClientError

    try:
        vgws = ec2.describe_vpn_gateways(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "tag:sim2real", "Values": [CHECK]},
            ]
        )["VpnGateways"]
    except ClientError:
        return
    for vgw in vgws:
        if {"Key": "sim2real", "Value": CHECK} not in vgw.get("Tags", []):
            continue
        atts = vgw.get("VpcAttachments", [])
        if any(a.get("State") != "detached" for a in atts):
            continue
        try:
            ec2.delete_vpn_gateway(VpnGatewayId=vgw["VpnGatewayId"])
        except ClientError:
            pass


def _create_vpn_gateway(ec2, ctx):
    """Reclaim VGW quota left by an earlier run of this check before every create attempt, then
    create a gateway tagged with this check's name so a later run can recognize it."""
    _reclaim_stale_vpn_gateways(ec2)
    return ec2.create_vpn_gateway(
        Type="ipsec.1",
        TagSpecifications=[
            {
                "ResourceType": "vpn-gateway",
                "Tags": [
                    {"Key": "Name", "Value": ctx.unique_name("sim2real-vgw-")},
                    {"Key": "sim2real", "Value": CHECK},
                ],
            }
        ],
    )["VpnGateway"]["VpnGatewayId"]


def _create_with_retry(fn, retry_codes, timeout_s=400.0, interval_s=20.0):
    """Retry a create-style call while the account is transiently at a
    resource-limit ceiling (shared quota contention with other concurrently
    running checks); re-raise once the timeout is exhausted or the error is
    not one of the expected transient limit codes. Bounded well under the
    check's own overall per-check timeout (900s) — a 30-minute retry window
    (the old default) guarantees the harness kills the whole check before
    the retry loop could ever return, so this stays well inside the budget
    the rest of the check (attach/propagate/disable polling, ~4 minutes
    worst case) leaves available."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
