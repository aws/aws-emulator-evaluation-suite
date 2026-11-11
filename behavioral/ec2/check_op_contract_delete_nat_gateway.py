"""op-contract-delete-nat-gateway."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-nat-gateway"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteNatGateway tears down a real NAT gateway (create -> available -> delete
    -> deleted); deleting a NAT gateway ID that was never actually issued by AWS
    (i.e. a synthetic, made-up ID) is rejected with NatGatewayMalformed."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-natgw-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.81.0.0/16",
        TagSpecifications=[_tag_spec("vpc", name)],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    # NOTE: on real AWS, a public NAT gateway's provisioning only succeeds
    # (reaches "available") when its VPC has an internet gateway attached; without
    # one the NAT gateway transitions to "failed". Attach one here so this check
    # exercises the normal delete-lifecycle contract rather than an environment
    # where provisioning itself cannot succeed.
    igw_id = ec2.create_internet_gateway(TagSpecifications=[_tag_spec("internet-gateway", name)])[
        "InternetGateway"
    ]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _cleanup_ignore_error(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))
    )

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.81.1.0/24", TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    alloc_id = ec2.allocate_address(
        Domain="vpc", TagSpecifications=[_tag_spec("elastic-ip", name)]
    )["AllocationId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.release_address(AllocationId=alloc_id)))

    nat_id = ec2.create_nat_gateway(
        SubnetId=subnet_id,
        AllocationId=alloc_id,
        ConnectivityType="public",
        TagSpecifications=[_tag_spec("natgateway", name)],
    )["NatGateway"]["NatGatewayId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_nat_gateway(NatGatewayId=nat_id)))

    def _describe():
        resp = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])
        return resp["NatGateways"][0] if resp["NatGateways"] else None

    # NAT gateway provisioning can take several minutes on real AWS (well beyond the
    # ~1-2 minutes typically seen in lightweight test environments), so use a generous
    # bounded poll rather than assuming a short provisioning time.
    available = _poll_until(
        _describe, lambda n: n is not None and n["State"] in ("available", "failed"), timeout_s=600.0, interval_s=15.0
    )
    assert available["State"] == "available", f"NAT gateway did not become available: {available}"

    ec2.delete_nat_gateway(NatGatewayId=nat_id)

    # Wait for the NAT gateway to reach its terminal "deleted" state (not just
    # "deleting") before probing the malformed-id contract below.
    deleted = _poll_until(
        _describe, lambda n: n is not None and n["State"] == "deleted", timeout_s=180.0, interval_s=10.0
    )
    assert deleted["State"] == "deleted", f"unexpected state after delete: {deleted}"

    # NOTE: re-issuing DeleteNatGateway against the same (now fully "deleted")
    # ID is idempotent on real AWS -- it returns success rather than an error,
    # so it cannot be used to isolate an error contract. Instead, probe with a
    # NAT gateway ID that has the right surface shape ("nat-" + 17 hex chars)
    # but was never actually issued by AWS. Real AWS validates these IDs with
    # more than a simple regex -- it appears to check that the suffix is a
    # plausible AWS-generated identifier (both low-entropy/sequential suffixes
    # like an all-zero or ascending "0123456789abcdef0" *and* genuinely random
    # hex suffixes are rejected the same way) -- so any synthetic ID that was
    # never actually allocated by the service is uniformly rejected with
    # NatGatewayMalformed before AWS ever gets to an existence/not-found check.
    random_suffix = "".join(random.choice("0123456789abcdef") for _ in range(17))
    bogus_id = f"nat-{random_suffix}"
    err = _error(lambda: ec2.delete_nat_gateway(NatGatewayId=bogus_id))
    assert err == ("NatGatewayMalformed", f"Invalid Nat Gateway {bogus_id}"), f"unexpected error: {err}"


# ===== helpers =====
def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _cleanup_ignore_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAllocationID.NotFound",
            "InvalidNetworkInterfaceID.NotFound",
            "NatGatewayNotFound",
        ):
            raise


# AWS-managed ENIs (endpoints, load balancers, instances) leave a VPC asynchronously after their
# owner's delete returns, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can fail with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry inside the same window, and raise
# naming any ENIs still attached. Teardown-only: run() never calls this.
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
