"""set-security-groups-invalid-sg-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-security-groups-invalid-sg-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetSecurityGroups with a non-existent group id is rejected with
    InvalidConfigurationRequestException and leaves the load balancer's applied security groups
    unchanged."""
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids = _get_network(ctx, count=2)
    sg_id = _create_security_group(ctx, vpc_id)
    arn = _create_lb(ctx, subnet_ids, [sg_id])
    _wait_lb_active(ctx, arn)

    # Positive control: the wiring genuinely accepts a real security group through this same
    # operation before we probe the negative -- otherwise a target that rejects every
    # SetSecurityGroups call would pass this check for the wrong reason.
    resp = elbv2.set_security_groups(LoadBalancerArn=arn, SecurityGroups=[sg_id])
    assert resp["SecurityGroupIds"] == [sg_id], (
        f"expected the valid security group {sg_id!r} to be applied, got {resp['SecurityGroupIds']!r}"
    )
    applied = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
    assert applied["SecurityGroups"] == [sg_id], (
        f"expected DescribeLoadBalancers to reflect {[sg_id]!r}, got {applied['SecurityGroups']!r}"
    )

    fake_sg = "sg-0123456789abcdef0"
    code, message = _error(
        lambda: elbv2.set_security_groups(LoadBalancerArn=arn, SecurityGroups=[fake_sg])
    )
    assert code == "InvalidConfigurationRequest", (
        f"expected the unknown security group to be rejected with InvalidConfigurationRequest, got {code!r}"
    )
    expected_message = "One or more security groups are invalid"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect-absent: the rejected call must not have changed the load balancer's applied
    # security groups away from the value the positive control just proved was live.
    unchanged = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
    assert unchanged["SecurityGroups"] == [sg_id], (
        f"expected security groups to remain {[sg_id]!r} after the rejected call, "
        f"got {unchanged['SecurityGroups']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _tags_kv(ctx, resource):
    return [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-elbv2-{resource}-")}]


def _get_network(ctx, count=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]
    for vpc in sorted(vpcs, key=lambda v: not v.get("IsDefault", False)):
        vpc_id = vpc["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= count:
            return vpc_id, sorted(by_az.values())[:count]

    # No existing VPC has enough distinct-AZ subnets -- provision our own rather than depend
    # on an ambient default VPC that a freshly provisioned account may not have.
    vpc_id = ec2.create_vpc(CidrBlock="10.98.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=_tags_kv(ctx, "vpc"))
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    subnet_ids = []
    for i in range(count):
        az = azs[i % len(azs)]["ZoneName"]
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.98.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
        ec2.create_tags(Resources=[sid], Tags=_tags_kv(ctx, "subnet"))
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)
    return vpc_id, subnet_ids


def _create_security_group(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-elbv2-sg-"),
        Description="sim2real elbv2 behavioral test security group",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv(ctx, "sg")}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return sg_id


def _safe_delete_lb(ctx, arn):
    elbv2 = ctx.client("elbv2")
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise


def _create_lb(ctx, subnet_ids, sg_ids, scheme="internal", lb_type="application"):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-")
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        SecurityGroups=sg_ids,
        Scheme=scheme,
        Type=lb_type,
        Tags=_tags_kv(ctx, "lb"),
    )
    arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe_delete_lb(ctx, arn))
    return arn


def _wait_lb_active(ctx, arn, timeout_s=180.0, interval_s=5.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
        state = desc["State"]["Code"]
        if state == "active":
            return state
        if state == "failed":
            raise AssertionError(f"load balancer entered failed state: {desc['State'].get('Reason')}")
        time.sleep(interval_s)
    raise AssertionError(f"load balancer did not reach active within {timeout_s}s")


# Subnet / security group / VPC deletes fail with DependencyViolation while AWS-managed ENIs of an
# asynchronously deleted resource (e.g. a load balancer) remain, so wait (bounded) for them to go,
# retry inside one shared window, and finally raise naming the ENIs still attached.
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
