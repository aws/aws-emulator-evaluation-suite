"""op-contract-disassociate-nat-gateway-address."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-disassociate-nat-gateway-address"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateNatGatewayAddress removes a secondary EIP from a public NAT
    gateway (the primary EIP is left untouched); DryRun reports DryRunOperation
    without changing state."""
    ec2 = ctx.client("ec2")

    # Reuse the shared network: the per-account VPC limit is low, and CreateNatGateway
    # needs only a subnet, not a route to an internet gateway.
    vpc_id, subnet_id = _pick_default_vpc_and_subnet(ec2, ctx=ctx)
    if vpc_id is None:
        vpc_id = _create_with_retry(
            lambda: ec2.create_vpc(
                CidrBlock="10.80.0.0/16",
                TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
            )["Vpc"]["VpcId"],
            retry_codes=("VpcLimitExceeded",),
            # VpcLimitExceeded can take minutes to clear while other checks hold VPCs.
            timeout_s=400.0,
            interval_s=15.0,
        )
        ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    if subnet_id is None:
        az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.80.1.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    eip_tag = [{"ResourceType": "elastic-ip", "Tags": [{"Key": "sim2real", "Value": "1"}]}]
    primary_alloc = ec2.allocate_address(Domain="vpc", TagSpecifications=eip_tag)["AllocationId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.release_address(AllocationId=primary_alloc)))
    secondary_alloc = ec2.allocate_address(Domain="vpc", TagSpecifications=eip_tag)["AllocationId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.release_address(AllocationId=secondary_alloc)))

    nat_gw_id = ec2.create_nat_gateway(
        SubnetId=subnet_id,
        AllocationId=primary_alloc,
        ConnectivityType="public",
        TagSpecifications=[{"ResourceType": "natgateway", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["NatGateway"]["NatGatewayId"]
    ctx.on_cleanup(lambda: _delete_nat_gateway_and_wait(ec2, nat_gw_id))

    _poll_until(
        lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_gw_id])["NatGateways"][0]["State"],
        lambda state: state == "available",
        timeout_s=300.0,
        interval_s=10.0,
    )

    ec2.associate_nat_gateway_address(NatGatewayId=nat_gw_id, AllocationIds=[secondary_alloc])

    def _addresses():
        return ec2.describe_nat_gateways(NatGatewayIds=[nat_gw_id])["NatGateways"][0]["NatGatewayAddresses"]

    secondary_assoc_id = _poll_until(
        lambda: next((a["AssociationId"] for a in _addresses() if a["AllocationId"] == secondary_alloc and a.get("Status") == "succeeded"), None),
        lambda v: v is not None,
        timeout_s=120.0,
        interval_s=5.0,
    )

    # Error boundary: DryRun must report DryRunOperation without disassociating.
    code, message = _error(
        lambda: ec2.disassociate_nat_gateway_address(
            NatGatewayId=nat_gw_id, AssociationIds=[secondary_assoc_id], DryRun=True
        )
    )
    assert code == "DryRunOperation", code
    assert message == DRY_RUN_MESSAGE, f"unexpected DryRun message: {message!r}"
    addrs_after_dryrun = _addresses()
    assert any(a["AllocationId"] == secondary_alloc for a in addrs_after_dryrun), (
        f"DryRun must not disassociate; secondary_alloc={secondary_alloc} missing from {addrs_after_dryrun}"
    )

    resp = ec2.disassociate_nat_gateway_address(
        NatGatewayId=nat_gw_id, AssociationIds=[secondary_assoc_id], MaxDrainDurationSeconds=1
    )
    assert resp["NatGatewayId"] == nat_gw_id, resp

    _poll_until(
        _addresses,
        lambda addrs: not any(a["AllocationId"] == secondary_alloc for a in addrs),
        timeout_s=120.0,
        interval_s=10.0,
    )

    # The primary EIP must remain untouched throughout.
    remaining = _addresses()
    assert any(a["AllocationId"] == primary_alloc and a.get("IsPrimary") is True for a in remaining), remaining


# ===== helpers =====
def _pick_default_vpc_and_subnet(ec2, *, ctx):
    """Return the shared network's VPC id and its roomiest subnet id (None where absent)."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None, None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        return vpc_id, None
    subnet = max(subnets, key=lambda s: s.get("AvailableIpAddressCount", 0))
    return vpc_id, subnet["SubnetId"]


def _create_with_retry(fn, retry_codes, timeout_s=250.0, interval_s=20.0):
    """Retry fn() while it fails with one of retry_codes (a transient quota ceiling).

    Re-raises once timeout_s is spent or on any other error."""
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


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_nat_gateway_and_wait(ec2, nat_gw_id, timeout_s=600.0):
    """Delete the NAT gateway and wait for deleted: its addresses cannot be released until then."""
    ec2.delete_nat_gateway(NatGatewayId=nat_gw_id)
    _poll_until(
        lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_gw_id])["NatGateways"],
        lambda rows: not rows or rows[0]["State"] == "deleted",
        timeout_s=timeout_s,
        interval_s=10.0,
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAllocationID.NotFound",
            "InvalidNetworkInterfaceID.NotFound",
        ):
            raise


# AWS-managed ENIs (e.g. a NAT gateway's) leave a subnet/VPC asynchronously after their owner is
# deleted, so an immediate delete fails with DependencyViolation. Teardown waits (bounded, one window
# shared by all of a check's network deletes) for them, then raises naming the ENIs still attached.
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
