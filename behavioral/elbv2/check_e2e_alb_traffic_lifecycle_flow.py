"""e2e-alb-traffic-lifecycle-flow."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "e2e-alb-traffic-lifecycle-flow"
GROUP = "e2e"
SERVICES = ["elbv2"]

_CIDR = "10.91.0.0/16"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Full ALB lifecycle: a real EC2 target behind ALB+TG+listener+rule becomes healthy and is
    reachable over HTTP through the weighted-forward rule; deregister and delete then leave
    no dangling resources."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    ssm = ctx.client("ssm")

    tagspec = lambda kind, name: {  # noqa: E731
        "ResourceType": kind,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{name}-")}],
    }

    vpc_id = ec2.create_vpc(CidrBlock=_CIDR, TagSpecifications=[tagspec("vpc", "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(_safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"][:2]
    ]
    if len(azs) < 2:
        raise AssertionError("region does not expose 2 available AZs for ALB subnets")

    subnet_ids = []
    for i, az in enumerate(azs):
        sn = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.91.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[tagspec("subnet", f"subnet-{i}")],
        )["Subnet"]
        subnet_ids.append(sn["SubnetId"])
        ctx.on_cleanup(_safe(lambda sid=sn["SubnetId"]: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        ec2.modify_subnet_attribute(SubnetId=sn["SubnetId"], MapPublicIpOnLaunch={"Value": True})

    igw_id = ec2.create_internet_gateway(TagSpecifications=[tagspec("internet-gateway", "igw")])[
        "InternetGateway"
    ]["InternetGatewayId"]

    def _teardown_igw():
        _safe(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))()
        _safe(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))()

    ctx.on_cleanup(_teardown_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=[tagspec("route-table", "rtb")])[
        "RouteTable"
    ]["RouteTableId"]
    ctx.on_cleanup(_safe(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rtb_id)))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    for sid in subnet_ids:
        assoc_id = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(_safe(lambda aid=assoc_id: ec2.disassociate_route_table(AssociationId=aid)))

    alb_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-alb-sg-"),
        Description="alb sg",
        VpcId=vpc_id,
        TagSpecifications=[tagspec("security-group", "alb-sg")],
    )["GroupId"]
    ctx.on_cleanup(_safe(lambda: _delete_net(ec2, "delete_security_group", GroupId=alb_sg)))
    ec2.authorize_security_group_ingress(
        GroupId=alb_sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}],
    )

    inst_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-inst-sg-"),
        Description="instance sg",
        VpcId=vpc_id,
        TagSpecifications=[tagspec("security-group", "inst-sg")],
    )["GroupId"]
    ctx.on_cleanup(_safe(lambda: _delete_net(ec2, "delete_security_group", GroupId=inst_sg)))
    ec2.authorize_security_group_ingress(
        GroupId=inst_sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": _CIDR}]}],
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    user_data = (
        "#!/bin/bash\n"
        "mkdir -p /srv/www\n"
        "echo sim2real-alb-target-ok > /srv/www/index.html\n"
        "cd /srv/www && nohup python3 -m http.server 80 >/var/log/sim2real-http.log 2>&1 &\n"
    )
    instance_id = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_ids[0],
        SecurityGroupIds=[inst_sg],
        UserData=user_data,
        TagSpecifications=[tagspec("instance", "target")],
    )["Instances"][0]["InstanceId"]

    def _teardown_instance():
        from botocore.exceptions import ClientError

        try:
            ec2.terminate_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                return
            raise
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_teardown_instance)
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-tg-"),
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="instance",
        HealthCheckProtocol="HTTP",
        HealthCheckPath="/",
        HealthCheckIntervalSeconds=10,
        HealthCheckTimeoutSeconds=5,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(_safe(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))
    # Shrink the deregistration delay so the post-deregister poll below stays bounded
    # (the default is 300s).
    elbv2.modify_target_group_attributes(
        TargetGroupArn=tg_arn, Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": "10"}]
    )

    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": instance_id, "Port": 80}])

    lb_resp = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-alb-"),
        Subnets=subnet_ids,
        SecurityGroups=[alb_sg],
        Scheme="internet-facing",
        Type="application",
    )["LoadBalancers"][0]
    lb_arn = lb_resp["LoadBalancerArn"]
    ctx.on_cleanup(_safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))

    lb_state = _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=180,
        interval_s=5,
    )
    assert lb_state == "active", f"load balancer never became active, last state={lb_state!r}"
    dns_name = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["DNSName"]

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[
            {"Type": "forward", "ForwardConfig": {"TargetGroups": [{"TargetGroupArn": tg_arn, "Weight": 100}]}}
        ],
    )["Listeners"][0]["ListenerArn"]

    rule_arn = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=10,
        Conditions=[{"Field": "path-pattern", "Values": ["/*"]}],
        Actions=[
            {"Type": "forward", "ForwardConfig": {"TargetGroups": [{"TargetGroupArn": tg_arn, "Weight": 100}]}}
        ],
    )["Rules"][0]["RuleArn"]

    # Independent read: the rule's condition and priority actually persisted at the
    # listener, not just echoed back by the mutating call.
    listener_rules = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    matching = [r for r in listener_rules if r["RuleArn"] == rule_arn]
    assert matching, f"created rule {rule_arn} not present in DescribeRules for its listener"
    stored = matching[0]
    assert stored["Priority"] == "10", f"expected rule priority '10', got {stored['Priority']!r}"
    assert stored["Conditions"][0]["Values"] == ["/*"], (
        f"expected path-pattern condition ['/*'], got {stored['Conditions'][0].get('Values')!r}"
    )

    def _target_state():
        descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        return descs[0]["TargetHealth"]["State"] if descs else None

    healthy = _poll_until(_target_state, lambda s: s == "healthy", timeout_s=300, interval_s=10)
    assert healthy == "healthy", f"target never became healthy, last state={healthy!r}"

    def _fetch_ok():
        try:
            _url, _route = ctx.endpoint_route(f"http://{dns_name}/")
            with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=5) as resp:
                return resp.status == 200 and b"sim2real-alb-target-ok" in resp.read()
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            return False

    reached = _poll_until(_fetch_ok, lambda ok: ok is True, timeout_s=120, interval_s=5)
    assert reached is True, "ALB never forwarded a successful HTTP response from the registered target"

    elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": instance_id, "Port": 80}])

    def _target_count():
        return len(elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"])

    remaining = _poll_until(_target_count, lambda n: n == 0, timeout_s=120, interval_s=5)
    assert remaining == 0, "target was not removed from the target group after deregistration"

    elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)

    def _lb_gone():
        try:
            return _error(lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn]))[0] == "LoadBalancerNotFound"
        except AssertionError:
            return False

    gone = _poll_until(_lb_gone, lambda g: g is True, timeout_s=120, interval_s=5)
    assert gone is True, "load balancer still describable after DeleteLoadBalancer"

    # The load balancer (and its listener/rule referencing this target group)
    # was just deleted above; the target-group-in-use flag can lag briefly
    # behind LoadBalancerNotFound, so bound-retry the final delete.
    def _try_delete_tg():
        try:
            elbv2.delete_target_group(TargetGroupArn=tg_arn)
            return True
        except Exception as err:
            resp = getattr(err, "response", None)
            if resp and resp.get("Error", {}).get("Code") == "ResourceInUse":
                return False
            raise

    deleted = _poll_until(_try_delete_tg, lambda ok: ok is True, timeout_s=120, interval_s=5)
    assert deleted is True, "target group deletion still rejected as in-use long after load balancer deletion"
    code, message = _error(lambda: elbv2.describe_target_groups(TargetGroupArns=[tg_arn]))
    assert code == "TargetGroupNotFound", f"expected TargetGroupNotFound after delete, got {code!r}"
    expected_message = "One or more target groups not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====
_GONE = {
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "Gateway.NotAttached",
    "InvalidInternetGatewayID.NotFound", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound", "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
    "TargetGroupNotFound", "LoadBalancerNotFound", "ListenerNotFound", "RuleNotFound",
}


def _safe(fn, timeout_s=120.0):
    """Teardown: done once the resource is gone; retries ResourceInUse while a listener releases it."""
    from botocore.exceptions import ClientError

    def _wrapped():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in _GONE:
                    return
                if code != "ResourceInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return _wrapped


def _error(fn):
    """Return (code, message) of the AWS error fn raises; raise AssertionError if it succeeds."""
    try:
        result = fn()
    except Exception as err:
        resp = getattr(err, "response", None)
        if resp is None:
            raise
        return resp.get("Error", {}).get("Code"), resp.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    return value


# Network teardown: load balancers and similar resources delete asynchronously and leave ENIs in
# the subnet or security group, so an immediate delete fails with DependencyViolation. Wait for
# the ENIs (bounded, shared by all of one check's network deletes), then retry within the window.
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
