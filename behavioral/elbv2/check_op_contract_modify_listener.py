"""op-contract-modify-listener."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-modify-listener"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyListener updates port/default-action in place; a bogus ListenerArn is rejected."""
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    if len(subnet_ids) < 2:

        raise AssertionError("need >=2 subnets in distinct AZs to create an ALB")

    elbv2 = ctx.client("elbv2")
    lb = _create_alb(ctx, subnet_ids)
    tg1 = _create_tg(ctx, vpc_id, name=ctx.unique_name("sim2real-tg-1-"))
    tg2 = _create_tg(ctx, vpc_id, name=ctx.unique_name("sim2real-tg-2-"))
    listener = _create_listener(ctx, lb["LoadBalancerArn"], tg1["TargetGroupArn"], port=80)

    before = elbv2.describe_listeners(ListenerArns=[listener["ListenerArn"]])["Listeners"][0]
    assert before["Port"] == 80, f"expected initial port 80, got {before['Port']}"
    assert before["DefaultActions"][0]["TargetGroupArn"] == tg1["TargetGroupArn"], (
        f"expected initial default action to target {tg1['TargetGroupArn']}, "
        f"got {before['DefaultActions'][0]['TargetGroupArn']}"
    )

    modified = elbv2.modify_listener(
        ListenerArn=listener["ListenerArn"],
        Port=8443,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg2["TargetGroupArn"]}],
    )["Listeners"][0]
    assert modified["ListenerArn"] == listener["ListenerArn"], "ARN must remain stable across modify"
    assert modified["Port"] == 8443, f"modify response should report new port 8443, got {modified['Port']}"
    assert modified["DefaultActions"][0]["TargetGroupArn"] == tg2["TargetGroupArn"], (
        f"modify response should report new default action target {tg2['TargetGroupArn']}, "
        f"got {modified['DefaultActions'][0]['TargetGroupArn']}"
    )

    after = elbv2.describe_listeners(ListenerArns=[listener["ListenerArn"]])["Listeners"][0]
    assert after["Port"] == 8443, f"independent read should reflect new port 8443, got {after['Port']}"
    assert after["DefaultActions"][0]["TargetGroupArn"] == tg2["TargetGroupArn"], (
        f"independent read should reflect new default action target {tg2['TargetGroupArn']}, "
        f"got {after['DefaultActions'][0]['TargetGroupArn']}"
    )

    bogus_arn = listener["ListenerArn"][:-1] + ("0" if listener["ListenerArn"][-1] != "0" else "1")
    code, message = _error(lambda: elbv2.modify_listener(ListenerArn=bogus_arn, Port=9000))
    # Real AWS's ELBv2 API returns the error type WITHOUT the "Exception" suffix on the wire
    # (unlike the shape name used by the botocore model / docs).
    assert code == "ListenerNotFound", f"expected not-found, got {code}"
    expected = f"Listener '{bogus_arn}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its error (code, message); an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) >= 2:
        return vpc_id, list(by_az.values())

    # No usable ambient VPC (a freshly provisioned account may have none) — create one.
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=_managed_tags(ctx))
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    subnet_ids = []
    for i in range(2):
        az = azs[i % len(azs)]["ZoneName"]
        subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)["Subnet"]
        subnet_id = subnet["SubnetId"]
        ctx.on_cleanup(lambda subnet_id=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
        ec2.create_tags(Resources=[subnet_id], Tags=_managed_tags(ctx))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _managed_tags(ctx):
    return [
        {"Key": "sim2real:check", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-alb-")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids[:2], Type="application", Tags=_managed_tags(ctx)
    )
    lb = resp["LoadBalancers"][0]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb["LoadBalancerArn"]))
    return lb


def _create_tg(ctx, vpc_id, name=None, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-tg-")
    params = dict(
        Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance", Tags=_managed_tags(ctx)
    )
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg["TargetGroupArn"]))
    return tg


def _create_listener(ctx, lb_arn, tg_arn, port=80):
    elbv2 = ctx.client("elbv2")
    resp = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=_managed_tags(ctx),
    )
    listener = resp["Listeners"][0]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener["ListenerArn"]))
    return listener


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes asynchronously: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached; every other error propagates. The window is shared by all of one
# check's network deletes.
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



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
