"""resolver-endpoint-lifecycle-creating-to-operational."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "resolver-endpoint-lifecycle-creating-to-operational"
GROUP = 'resolver-endpoint'
SERVICES = ['route53resolver']

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

def _error(fn):
    """Call fn(); return (code, HTTP status, message) of the ClientError it raises. A success
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_test_vpc_with_subnets(ctx, subnet_count=2):
    """Create a dedicated VPC, subnets and security group; return (vpc_id, subnet_ids, sg_id)."""
    ec2 = ctx.client("ec2")
    subnet_ids = []
    vpc_id = ec2.create_vpc(CidrBlock="10.90.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda v=vpc_id: _delete_net(ec2, "delete_vpc", VpcId=v))
    try:
        ec2.create_tags(
            Resources=[vpc_id],
            Tags=TAGS_KV + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
        )
    except Exception:
        pass

    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "opt-in-status", "Values": ["opt-in-not-required"]},
            ]
        )["AvailabilityZones"]
    ][:subnet_count]
    if len(azs) < subnet_count:
        raise AssertionError(
            f"region {ctx.region} exposes only {len(azs)} usable AZs, need {subnet_count}"
        )
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.90.{i}.0/24", AvailabilityZone=az
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda s=sid: _delete_net(ec2, "delete_subnet", SubnetId=s))

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-behav-r53r-sg-"),
        Description="route53resolver behavioral test sg",
    )["GroupId"]
    ctx.on_cleanup(lambda s=sg_id: _delete_net(ec2, "delete_security_group", GroupId=s))

    return vpc_id, subnet_ids, sg_id


def _endpoint_gone(r53, ep_id) -> bool:
    try:
        r53.get_resolver_endpoint(ResolverEndpointId=ep_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return True
        raise
    return False


def _cleanup_endpoint(r53, ep_id):
    """Delete the endpoint and wait until it is gone; a timeout raises so a leak is reported."""
    try:
        r53.delete_resolver_endpoint(ResolverEndpointId=ep_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    _poll(lambda: _endpoint_gone(r53, ep_id), bool, timeout_s=300, interval_s=5,
          description=f"teardown: resolver endpoint {ep_id} to be gone")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ResolverEndpoint reaches OPERATIONAL with its two IP addresses ATTACHED in the requested
    subnets and is listed by its VPC; once deleted it is gone from reads and the listing, and an
    update of the dead id is refused. Only terminal states are graded.
    """
    r53 = ctx.client("route53resolver")
    vpc_id, subnet_ids, sg_id = _create_test_vpc_with_subnets(ctx, 2)

    ep = r53.create_resolver_endpoint(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-ep-"),
        SecurityGroupIds=[sg_id],
        Direction="INBOUND",
        IpAddresses=[{"SubnetId": s} for s in subnet_ids],
    )["ResolverEndpoint"]
    ep_id = ep["Id"]
    ctx.on_cleanup(lambda x=ep_id: _cleanup_endpoint(r53, x))
    assert ep["Direction"] == "INBOUND", f"Direction {ep.get('Direction')!r}"
    assert ep["IpAddressCount"] == 2, f"expected IpAddressCount=2, got {ep.get('IpAddressCount')}"
    assert ep["HostVPCId"] == vpc_id, f"HostVPCId {ep.get('HostVPCId')!r}, expected {vpc_id!r}"
    assert ep["Id"].startswith("rslvr-in-"), f"inbound endpoint id shape: {ep['Id']}"

    settled = _poll(
        lambda: r53.get_resolver_endpoint(ResolverEndpointId=ep_id)["ResolverEndpoint"],
        lambda e: e["Status"] not in ("CREATING", "UPDATING"),
        timeout_s=900,
        interval_s=10,
        description="resolver endpoint leaves CREATING",
    )
    assert settled["Status"] == "OPERATIONAL", (
        f"expected the endpoint to settle OPERATIONAL, got {settled['Status']!r}: "
        f"{settled.get('StatusMessage')!r}"
    )

    ips = _poll(
        lambda: r53.list_resolver_endpoint_ip_addresses(ResolverEndpointId=ep_id)["IpAddresses"],
        lambda items: items and all(i["Status"] == "ATTACHED" for i in items),
        timeout_s=300,
        interval_s=10,
        description="endpoint IP addresses reach ATTACHED",
    )
    assert len(ips) == 2, f"expected 2 IP addresses, got {len(ips)}"
    assert sorted(ip["SubnetId"] for ip in ips) == sorted(subnet_ids), ips

    listed = r53.list_resolver_endpoints(
        Filters=[{"Name": "HostVPCId", "Values": [vpc_id]}]
    )["ResolverEndpoints"]
    assert [e["Id"] for e in listed] == [ep_id], f"ListResolverEndpoints for {vpc_id}: {listed!r}"

    deleted = r53.delete_resolver_endpoint(ResolverEndpointId=ep_id)["ResolverEndpoint"]
    assert deleted["Id"] == ep_id, f"DeleteResolverEndpoint named {deleted['Id']!r}"

    def ep_gone():
        try:
            r53.get_resolver_endpoint(ResolverEndpointId=ep_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return True
            raise
        return False

    _poll(ep_gone, bool, timeout_s=600, interval_s=10, description="deleted endpoint disappears")
    code, status, message = _error(lambda: r53.get_resolver_endpoint(ResolverEndpointId=ep_id))
    assert code == "ResourceNotFoundException", code
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx from GetResolverEndpoint after delete, got {status!r}"
    expected_message = f'[RSLVR-00501] Resolver endpoint with ID "{ep_id}" does not exist.'
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    listed_after = r53.list_resolver_endpoints(
        Filters=[{"Name": "HostVPCId", "Values": [vpc_id]}]
    )["ResolverEndpoints"]
    assert listed_after == [], f"ListResolverEndpoints for {vpc_id} after delete: {listed_after!r}"
    code, status, message = _error(
        lambda: r53.update_resolver_endpoint(ResolverEndpointId=ep_id, Name="sim2real-dead")
    )
    assert code == "ResourceNotFoundException", f"UpdateResolverEndpoint after delete: got {code!r}"
    assert isinstance(status, int) and 400 <= status < 500, f"UpdateResolverEndpoint after delete: expected HTTP 4xx, got {status!r}"
    expected_message = f'[RSLVR-00501] Resolver endpoint with ID "{ep_id}" does not exist.'
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. Resources in this VPC
# delete asynchronously and their ENIs linger in the subnet / security group, so an immediate
# DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait (bounded) for
# the ENIs to go, retry DependencyViolation in the same window, then raise naming the ENIs still
# attached. The window is shared by all of one check's network deletes.
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
            if code.endswith(".NotFound"):
                return None  # EC2's own not-found: already gone
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
