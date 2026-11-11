"""elbv2-target-reaches-healthy."""

from __future__ import annotations

import time
from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "elbv2-target-reaches-healthy"
GROUP = "data-plane"
SERVICES = ["elbv2"]

_THROTTLE_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "RequestThrottled",
        "TooManyRequestsException",
    }
)


# Marks a data-plane failure: an ELB target only becomes `healthy` once something actually
# probes it, so a target with no health checker stays initial/unused.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")


@tags(
    "axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data"
)
def run(ctx) -> None:
    """A real EC2 backend in a target group reports 'unhealthy' while its health-check port has no
    ingress and turns 'healthy' once the port opens: the health check really probes the target.
    """

    elb = ctx.client("elbv2")
    ec2 = ctx.client("ec2")
    _net_cache = {}

    def _tags_kv():
        return [
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ]

    def _ec2_tag_specs(*resource_types):
        return [{"ResourceType": rt, "Tags": _tags_kv()} for rt in resource_types]

    def _retry_throttled(fn, attempts=5):
        delays = [3, 6, 12, 24, 30]
        last_exc = None
        for attempt in range(attempts):
            try:
                return fn()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code not in _THROTTLE_CODES:
                    raise
                last_exc = exc
                time.sleep(delays[min(attempt, len(delays) - 1)])
        raise last_exc

    def _poll_until(
        probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"
    ):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(
            f"{description} not met within {timeout_s}s. Last result: {last!r}"
        )

    def _setup_network(num_subnets=2):
        if _net_cache:
            return _net_cache["net"]
        default_vpcs = ec2.describe_vpcs(
            Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]
        )["Vpcs"]
        if default_vpcs:
            vpc_id = default_vpcs[0]["VpcId"]
            subnets = ec2.describe_subnets(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
                ]
            )["Subnets"]
            per_az = {}
            for subnet in sorted(subnets, key=lambda s: s["SubnetId"]):
                per_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
            subnet_ids = [per_az[az] for az in sorted(per_az)][:num_subnets]
            if len(subnet_ids) >= min(num_subnets, 2):
                _net_cache["net"] = (vpc_id, subnet_ids)
                return _net_cache["net"]
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        def _drop_vpc():
            _gone_ok(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound")

        ctx.on_cleanup(_drop_vpc)
        try:
            ec2.create_tags(
                Resources=[vpc_id],
                Tags=_tags_kv()
                + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
            )
        except Exception:
            pass
        azs = ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        subnet_ids = []
        for i in range(num_subnets):
            az = azs[i % len(azs)]["ZoneName"]
            sid = ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az
            )["Subnet"]["SubnetId"]
            subnet_ids.append(sid)

            def _drop_subnet(sid=sid):
                _gone_ok(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid), "InvalidSubnetID.NotFound")

            ctx.on_cleanup(_drop_subnet)
        _net_cache["net"] = (vpc_id, subnet_ids)
        return _net_cache["net"]

    def _create_target_group(name=None, vpc_id=None, **kwargs):
        name = _clamp_name(name or ctx.unique_name("sim2real-behav-tg-"))
        params = dict(Name=name, Protocol="HTTP", Port=80, TargetType="ip")
        params.update(kwargs)
        if vpc_id is None:
            vpc_id, _ = _setup_network()
        params.setdefault("VpcId", vpc_id)
        params.setdefault("Tags", _tags_kv())
        tg = _retry_throttled(lambda: elb.create_target_group(**params))[
            "TargetGroups"
        ][0]
        arn = tg["TargetGroupArn"]

        def _drop_tg():
            # A target group stays ResourceInUse until its listener is released.
            deadline = time.monotonic() + 60
            while True:
                try:
                    elb.delete_target_group(TargetGroupArn=arn)
                    return
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code == "TargetGroupNotFound":
                        return
                    if code != "ResourceInUse" or time.monotonic() >= deadline:
                        raise
                time.sleep(2)

        ctx.on_cleanup(_drop_tg)
        return tg

    def _create_load_balancer(name=None, subnet_ids=None, **kwargs):
        name = _clamp_name(name or ctx.unique_name("sim2real-behav-lb-"))
        if subnet_ids is None:
            _, subnet_ids = _setup_network()
        params = dict(
            Name=name,
            Subnets=subnet_ids,
            Type=kwargs.pop("Type", "application"),
            Scheme=kwargs.pop("Scheme", "internal"),
            Tags=kwargs.pop("Tags", _tags_kv()),
        )
        params.update(kwargs)
        lb = _retry_throttled(lambda: elb.create_load_balancer(**params))[
            "LoadBalancers"
        ][0]
        arn = lb["LoadBalancerArn"]

        def _drop_lb():
            try:
                elb.delete_load_balancer(LoadBalancerArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            for _ in range(30):
                try:
                    elb.describe_load_balancers(LoadBalancerArns=[arn])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                        raise
                    break
                time.sleep(2)

        ctx.on_cleanup(_drop_lb)
        return lb

    def _create_listener(load_balancer_arn, **kwargs):
        params = dict(LoadBalancerArn=load_balancer_arn, Protocol="HTTP", Port=80)
        params.update(kwargs)
        listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][
            0
        ]
        arn = listener["ListenerArn"]
        ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=arn))
        return listener

    def _wait_for_lb_terminal_state(lb_arn, timeout_s=230, interval_s=10):
        return _poll_until(
            lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])[
                "LoadBalancers"
            ][0],
            lambda lb: lb["State"]["Code"] in ("active", "active_impaired", "failed"),
            timeout_s=timeout_s,
            interval_s=interval_s,
            description="load balancer reaching a terminal state",
        )

    vpc_id, subnet_ids = _setup_network()

    # Security group allowing the health-check port (80) inbound. Used by both
    # the instance and the (internal) load balancer.
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 health-check backend",
        VpcId=vpc_id,
    )["GroupId"]

    def _drop_sg():
        _gone_ok(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id), "InvalidGroup.NotFound")

    ctx.on_cleanup(_drop_sg)
    try:
        ec2.create_tags(Resources=[sg_id], Tags=_tags_kv())
    except Exception:
        pass
    # The port-80 ingress rule is deliberately withheld here. It is added only after the
    # negative-control leg below observes 'unhealthy' with no delivery path at all.

    # Resolve a launchable Amazon Linux 2023 AMI for this region.
    try:
        ami = ctx.client("ssm").get_parameter(
            Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        )["Parameter"]["Value"]
    except Exception as exc:  # pragma: no cover - environment dependent
        raise AssertionError(f"no Amazon Linux 2023 AMI resolvable: {exc}") from exc

    user_data = "#!/bin/bash\nnohup python3 -m http.server 80 >/tmp/httpd.log 2>&1 &\n"
    reservation = ec2.run_instances(
        ImageId=ami,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_ids[0],
        SecurityGroupIds=[sg_id],
        UserData=user_data,
        TagSpecifications=_ec2_tag_specs("instance"),
    )
    instance_id = reservation["Instances"][0]["InstanceId"]

    def _drop_instance():
        # Wait for 'terminated': the instance ENI holds the security group.
        _gone_ok(lambda: ec2.terminate_instances(InstanceIds=[instance_id]), "InvalidInstanceID.NotFound")
        deadline = time.monotonic() + 300
        state = None
        while time.monotonic() < deadline:
            try:
                found = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                    return
                raise
            if not found:
                return
            state = found[0]["Instances"][0]["State"]["Name"]
            if state == "terminated":
                return
            time.sleep(2)
        raise AssertionError(f"instance {instance_id} is {state!r}, not terminated, 300s after its terminate")

    ctx.on_cleanup(_drop_instance)

    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 200}
    )

    tg = _create_target_group(
        vpc_id=vpc_id,
        TargetType="instance",
        Protocol="HTTP",
        Port=80,
        HealthCheckProtocol="HTTP",
        HealthCheckPort="80",
        HealthCheckPath="/",
        HealthCheckIntervalSeconds=5,
        HealthCheckTimeoutSeconds=4,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
        Matcher={"HttpCode": "200"},
    )

    lb = _create_load_balancer(subnet_ids=subnet_ids, SecurityGroups=[sg_id])
    _wait_for_lb_terminal_state(lb["LoadBalancerArn"])
    _create_listener(
        lb["LoadBalancerArn"],
        Port=80,
        Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )

    _retry_throttled(
        lambda: elb.register_targets(
            TargetGroupArn=tg["TargetGroupArn"],
            Targets=[{"Id": instance_id, "Port": 80}],
        )
    )

    def health_desc():
        descs = elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])[
            "TargetHealthDescriptions"
        ]
        return descs[0] if descs else None

    def probe():
        desc = health_desc()
        return desc["TargetHealth"]["State"] if desc else None

    # NEGATIVE CONTROL: the security group has no port-80 ingress yet, so nothing --
    # not the load balancer, not anything else -- can reach the backend. A target that
    # reports 'healthy' here would mean the health check is not actually being performed;
    # that is exactly the gap a stub that flips every target to 'healthy' after a fixed
    # delay would hide.
    blocked = _poll_until(
        probe,
        lambda s: s in ("healthy", "unhealthy"),
        timeout_s=180,
        interval_s=2,
        description="registered target reaching a terminal health state with the "
        "health-check port closed",
    )
    blocked_reason = (health_desc() or {}).get("TargetHealth", {}).get("Reason")
    assert blocked == "unhealthy", (
        f"{DATAPLANE_MARKER}: target reported {blocked!r} (reason={blocked_reason!r}) "
        f"while its health-check port (80) had NO security-group ingress -- nothing "
        f"could have probed it, so 'healthy' here is not a real health check"
    )

    # RESTORE: open the exact port the health check uses. The SAME target, still
    # registered, must now transition to healthy once the load balancer's probes
    # actually reach it.
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "UserIdGroupPairs": [{"GroupId": sg_id}],
            }
        ],
    )

    # The poll's terminal set is 'healthy' ONLY: the target is already sitting in
    # 'unhealthy' from the leg above, so admitting that value here would let the poll
    # return immediately on stale state instead of waiting for a real re-check.
    _poll_until(
        probe,
        lambda s: s == "healthy",
        timeout_s=360,
        interval_s=2,
        description=f"{DATAPLANE_MARKER}: registered target reaching 'healthy' after "
        "opening the health-check port",
    )


# ===== helpers =====
def _gone_ok(fn, *gone):
    """Teardown: done once the resource is gone (one of the `gone` codes); any other failure raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code", "") not in gone:
            raise


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
