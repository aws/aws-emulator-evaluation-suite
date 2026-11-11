"""disassociate-ip-below-minimum."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "disassociate-ip-below-minimum"
GROUP = 'overly-permissive'
SERVICES = ['route53resolver']

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

def _try(fn, **kwargs):
    """Delete; True once done or already gone. _delete_net retries DependencyViolation itself."""
    try:
        fn(**kwargs)
        return True
    except ClientError as exc:
        if "NotFound" in exc.response.get("Error", {}).get("Code", ""):
            return True
        raise


def _wait_until(probe, timeout_s=120.0, interval_s=2.0):
    """Poll probe() until truthy; raise when the deadline passes first."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    raise AssertionError(f"teardown condition not met within {timeout_s}s")


def _wait_gone(probe, timeout_s=240.0, interval_s=3.0):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            probe()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("ResourceNotFoundException", "NoSuchEntity", "NotFoundException"):
                return True
            return False
        except Exception:
            return False
        time.sleep(interval_s)
    return False


def _client_error(fn):
    """Call fn(), which AWS refuses; return the (code, message) of its ClientError."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded; expected AWS to refuse it with a ClientError")


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
    """Return (vpc_id, [subnet_ids], sg_id) usable for resolver testing.

    Prefers a dedicated, self-created VPC (full isolation). If the account forbids
    VPC creation or is at quota, borrows the shared network's subnets -- borrowed
    resources are never registered for teardown.
    """
    ec2 = ctx.client("ec2")
    vpc_id = None
    subnet_ids = []
    try:
        vpc_id = ec2.create_vpc(CidrBlock="10.90.0.0/16")["Vpc"]["VpcId"]
        ctx.on_cleanup(
            lambda v=vpc_id: _wait_until(lambda: _try((lambda **_kw: _delete_net(ec2, "delete_vpc", **_kw)), VpcId=v), timeout_s=180)
        )
        try:
            ec2.create_tags(
                Resources=[vpc_id],
                Tags=TAGS_KV + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
            )
        except Exception:
            pass
    except Exception:
        vpc_id = None

    if vpc_id is not None:
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
            ctx.on_cleanup(
                lambda s=sid: _wait_until(lambda: _try((lambda **_kw: _delete_net(ec2, "delete_subnet", **_kw)), SubnetId=s), timeout_s=180)
            )
    else:
        defaults = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
        if not defaults:
            raise AssertionError("cannot create a VPC and no shared network VPC exists to borrow")
        vpc_id = defaults[0]["VpcId"]
        seen_azs = set()
        for sn in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]:
            if sn["AvailabilityZone"] in seen_azs:
                continue
            seen_azs.add(sn["AvailabilityZone"])
            subnet_ids.append(sn["SubnetId"])
            if len(subnet_ids) == subnet_count:
                break
        if len(subnet_ids) < subnet_count:
            raise AssertionError(
                f"shared network VPC {vpc_id} has fewer than {subnet_count} subnets in distinct AZs"
            )

    sg_id = None
    try:
        sg_id = ec2.create_security_group(
            VpcId=vpc_id,
            GroupName=ctx.unique_name("sim2real-behav-r53r-sg-"),
            Description="route53resolver behavioral test sg",
        )["GroupId"]
        ctx.on_cleanup(
            lambda s=sg_id: _wait_until(
                lambda: _try((lambda **_kw: _delete_net(ec2, "delete_security_group", **_kw)), GroupId=s), timeout_s=180
            )
        )
    except Exception:
        groups = ec2.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": ["default"]},
            ]
        )["SecurityGroups"]
        if not groups:
            raise AssertionError(f"no usable security group in VPC {vpc_id}") from None
        sg_id = groups[0]["GroupId"]

    return vpc_id, subnet_ids, sg_id


def _cleanup_endpoint(r53, ep_id):
    try:
        r53.delete_resolver_endpoint(ResolverEndpointId=ep_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    if not _wait_gone(lambda: r53.get_resolver_endpoint(ResolverEndpointId=ep_id), timeout_s=240):
        raise AssertionError(f"resolver endpoint {ep_id} still present 240s after DeleteResolverEndpoint")


def _wait_operational(ctx, r53, ep_id):
    """Wait (bounded) for the endpoint to reach OPERATIONAL; provisioning can take minutes."""
    def status():
        return r53.get_resolver_endpoint(ResolverEndpointId=ep_id)["ResolverEndpoint"]["Status"]

    _poll(status, lambda s: s == "OPERATIONAL", timeout_s=600, interval_s=5,
          description="resolver endpoint reaches OPERATIONAL")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateResolverEndpointIpAddress succeeds from 3 IPs to 2 but is rejected with
    InvalidRequestException when it would leave an endpoint below its 2-IP minimum.
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

    _wait_operational(ctx, r53, ep_id)

    ips = r53.list_resolver_endpoint_ip_addresses(ResolverEndpointId=ep_id)["IpAddresses"]
    assert len(ips) == 2, f"expected the endpoint to have exactly 2 IPs, got {len(ips)}"

    r53.associate_resolver_endpoint_ip_address(
        ResolverEndpointId=ep_id, IpAddress={"SubnetId": subnet_ids[0]}
    )
    _wait_operational(ctx, r53, ep_id)
    ips_after_add = r53.list_resolver_endpoint_ip_addresses(ResolverEndpointId=ep_id)["IpAddresses"]
    assert len(ips_after_add) == 3, f"expected 3 IPs after the control add, got {len(ips_after_add)}"
    extra_ip = next(ip for ip in ips_after_add if ip["SubnetId"] == subnet_ids[0] and ip["IpId"] not in {i["IpId"] for i in ips})

    r53.disassociate_resolver_endpoint_ip_address(
        ResolverEndpointId=ep_id, IpAddress={"IpId": extra_ip["IpId"]}
    )
    _wait_operational(ctx, r53, ep_id)
    ips_after_control_remove = r53.list_resolver_endpoint_ip_addresses(ResolverEndpointId=ep_id)["IpAddresses"]
    assert len(ips_after_control_remove) == 2, (
        f"positive control: expected disassociate above the floor to succeed and leave 2 IPs, "
        f"got {len(ips_after_control_remove)}"
    )
    remaining_ip_id = ips_after_control_remove[0]["IpId"]

    code, message = _client_error(
        lambda: r53.disassociate_resolver_endpoint_ip_address(
            ResolverEndpointId=ep_id, IpAddress={"IpId": remaining_ip_id}
        )
    )
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException dropping below the 2-IP minimum, got {code}"
    )
    expected_message = "[RSLVR-00505] Can only remove IP from resolver endpoints with more than 2 IP addresses."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    ips_after_rejection = r53.list_resolver_endpoint_ip_addresses(ResolverEndpointId=ep_id)["IpAddresses"]
    assert len(ips_after_rejection) == 2, (
        f"rejected disassociate must have no effect: expected 2 IPs to remain, "
        f"got {len(ips_after_rejection)}"
    )


# Asynchronously deleted resources leave AWS-managed ENIs in the VPC for a while, so an immediate
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
