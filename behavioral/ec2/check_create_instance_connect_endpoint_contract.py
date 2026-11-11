"""create-instance-connect-endpoint-contract."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-instance-connect-endpoint-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInstanceConnectEndpoint provisions a real endpoint that
    transitions from 'create-in-progress' to 'create-complete' in the target
    subnet's VPC, and rejects a non-existent subnet id.
    """
    ec2 = ctx.client("ec2")

    # Reuse an existing default VPC/subnet rather than creating a new VPC:
    # accounts have a default VPC-per-region quota, and this check does not
    # need a dedicated VPC to exercise the CreateInstanceConnectEndpoint
    # contract.
    vpc_id, subnet_id = _existing_vpc_and_subnet(ec2, ctx)

    # Instance Connect Endpoints are subject to a low per-account/region
    # quota. Leftover endpoints from earlier runs of this same check (e.g. a
    # prior run that errored out before its cleanup ran) can leave the
    # account sitting at that quota, so CreateInstanceConnectEndpoint raises
    # ResourceLimitExceeded before this check ever gets to exercise the real
    # contract under test. Reclaim quota by deleting stale same-family
    # endpoints, but only once the quota is actually exhausted -- reaping on
    # every run regardless would risk deleting another run's in-flight
    # endpoint before it ever hit a quota problem of its own.
    resp = _create_endpoint_reclaiming_quota(ec2, subnet_id, ctx)
    endpoint = resp["InstanceConnectEndpoint"]
    endpoint_id = endpoint["InstanceConnectEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_instance_connect_endpoint(InstanceConnectEndpointId=endpoint_id))

    assert endpoint["SubnetId"] == subnet_id, f"expected SubnetId {subnet_id!r}, got {endpoint['SubnetId']!r}"
    assert endpoint["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r}, got {endpoint['VpcId']!r}"
    assert endpoint["State"] in ("create-in-progress", "create-complete"), (
        f"unexpected initial state {endpoint['State']!r}"
    )

    state = _poll_until(
        lambda: ec2.describe_instance_connect_endpoints(InstanceConnectEndpointIds=[endpoint_id])[
            "InstanceConnectEndpoints"
        ][0]["State"],
        lambda s: s in ("create-complete", "create-failed"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert state == "create-complete", f"expected create-complete, got {state!r}"

    # Error boundary: a non-existent subnet must be rejected up front.
    code, message = _error(lambda: ec2.create_instance_connect_endpoint(SubnetId="subnet-0123456789abcdef0"))
    assert code == "InvalidSubnetID.NotFound", f"expected InvalidSubnetID.NotFound, got {code!r}"
    assert message == "The subnet ID 'subnet-0123456789abcdef0' does not exist", message


# ===== helpers =====
def _create_endpoint_reclaiming_quota(ec2, subnet_id, ctx, timeout_s=120.0, interval_s=5.0):
    """CreateInstanceConnectEndpoint against a low per-account/region quota.

    Self-heals by deleting this check's own stale, tagged endpoints, but only after
    actually hitting ResourceLimitExceeded -- never unconditionally, since reaping on
    every run would risk deleting a concurrently-running invocation's in-flight endpoint.
    """
    try:
        return ec2.create_instance_connect_endpoint(
            SubnetId=subnet_id, TagSpecifications=[_tag_spec(ctx, "instance-connect-endpoint")]
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceLimitExceeded":
            raise

    _delete_stale_endpoints(ec2, timeout_s=timeout_s, interval_s=interval_s)
    return ec2.create_instance_connect_endpoint(
        SubnetId=subnet_id, TagSpecifications=[_tag_spec(ctx, "instance-connect-endpoint")]
    )


def _delete_stale_endpoints(ec2, timeout_s=120.0, interval_s=5.0):
    """Delete any leftover Instance Connect Endpoints tagged by earlier runs
    of this check, and wait for them to actually clear so the account's low
    per-region quota is freed before we try to create a fresh one.
    """
    endpoints = ec2.describe_instance_connect_endpoints()["InstanceConnectEndpoints"]
    stale_ids = []
    for endpoint in endpoints:
        tags = {t["Key"]: t["Value"] for t in endpoint.get("Tags", [])}
        name = tags.get("Name", "")
        if not name.startswith("sim2real-behav-instance-connect-endpoint-"):
            continue
        if endpoint["State"] in ("delete-complete",):
            continue
        try:
            ec2.delete_instance_connect_endpoint(
                InstanceConnectEndpointId=endpoint["InstanceConnectEndpointId"]
            )
        except ClientError:
            pass
        stale_ids.append(endpoint["InstanceConnectEndpointId"])

    if not stale_ids:
        return

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = ec2.describe_instance_connect_endpoints(InstanceConnectEndpointIds=stale_ids)[
            "InstanceConnectEndpoints"
        ]
        if all(r["State"] == "delete-complete" for r in remaining):
            return
        time.sleep(interval_s)


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-behav-{resource_type}-")}],
    }


def _existing_vpc_and_subnet(ec2, ctx):
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    candidate_vpc_ids = [v["VpcId"] for v in default_vpcs]
    if not candidate_vpc_ids:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")

    for vpc_id in candidate_vpc_ids:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if subnets:
            return vpc_id, subnets[0]["SubnetId"]

    # No usable VPC/subnet exists yet in this account/region; fall back to
    # creating a dedicated one (and clean it up).
    vpc_id = ec2.create_vpc(CidrBlock="10.99.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.99.1.0/24", TagSpecifications=[_tag_spec(ctx, "subnet")]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


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
