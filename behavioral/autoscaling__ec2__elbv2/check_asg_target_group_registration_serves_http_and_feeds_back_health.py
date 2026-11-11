"""asg-target-group-registration-serves-http-and-feeds-back-health."""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "asg-target-group-registration-serves-http-and-feeds-back-health"

GROUP = "container-capacity-load-balancing"

SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An ASG registers its instance in a target group, the ALB serves that instance's HTTP body,
    and with HealthCheckType=ELB the load balancer's verdict shows as InService/Healthy in the ASG.

    Reference: https://docs.aws.amazon.com/autoscaling/ec2/userguide/attach-load-balancer-asg.html
    """
    asg_client = ctx.client("autoscaling")

    vpc_id, subnets = _default_vpc(ctx, min_subnets=2)
    subnets = subnets[:2]
    sg_id = _http_sg(ctx, vpc_id, 80, {"IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]})
    backend_sg = _http_sg(ctx, vpc_id, 80, {"UserIdGroupPairs": [{"GroupId": sg_id}]})

    marker = "sim2real-asg-alb-" + ctx.unique_name("")[:8]
    tg = _create_target_group(ctx, vpc_id, TargetType="instance")
    tg_arn = tg["TargetGroupArn"]
    lb = _create_alb(ctx, subnets, [sg_id])
    _create_listener(ctx, lb["LoadBalancerArn"], tg_arn)
    url = "http://" + lb["DNSName"] + "/"
    assert _target_health(ctx, tg_arn) == {}, "target group is not empty before the ASG"

    ami = _ssm_ami(
        ctx,
        "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
    )
    user_data = (
        "#!/bin/bash\n"
        "mkdir -p /var/www\n"
        f'echo "{marker} $(hostname)" > /var/www/index.html\n'
        "nohup python3 -m http.server 80 --directory /var/www "
        "> /var/log/sim2real-httpd.log 2>&1 &\n"
    )
    lt_name = _launch_template(ctx, ami, user_data, sg_ids=[backend_sg])
    asg_name = _create_asg(
        ctx,
        lt_name,
        subnets,
        min_size=1,
        max_size=1,
        desired=1,
        target_group_arns=[tg_arn],
        health_check_type="ELB",
        grace=180,
    )

    group = _describe_asg(ctx, asg_name)
    assert group["TargetGroupARNs"] == [tg_arn], group["TargetGroupARNs"]
    assert group["HealthCheckType"] == "ELB", group["HealthCheckType"]

    # Each leg is a real convergence (launch, cloud-init, two passing health checks, ASG ingesting
    # the ELB verdict), hence the long bounds.
    instances = _poll_until(
        lambda: _describe_asg(ctx, asg_name)["Instances"],
        lambda ins: len(ins) == 1,
        timeout_s=600,
        interval_s=15,
        description=f"ASG {asg_name} launched its one instance",
    )
    instance_id = instances[0]["InstanceId"]

    # --- Forwards: the ASG registered the instance and the health check passed.
    _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda h: instance_id in h,
        timeout_s=420,
        interval_s=10,
        description=f"ASG registered {instance_id} in the target group",
    )
    _poll_until(
        lambda: _target_health(ctx, tg_arn),
        lambda h: h.get(instance_id) == "healthy",
        timeout_s=600,
        interval_s=15,
        description=f"target {instance_id} healthy",
    )
    status, body = _poll_until(
        lambda: _http_get(ctx, url),
        lambda r: r[0] == 200,
        timeout_s=420,
        interval_s=10,
        description=f"HTTP 200 through the load balancer at {url}",
    )
    assert status == 200, (status, body)
    assert marker in body, f"the load balancer answered 200 but not from the ASG instance: {body!r}"

    # --- Backwards: the load balancer's verdict is what Auto Scaling reports.
    final = _poll_until(
        lambda: _describe_asg(ctx, asg_name)["Instances"][0],
        lambda i: i["LifecycleState"] == "InService" and i["HealthStatus"] == "Healthy",
        timeout_s=600,
        interval_s=15,
        description=f"instance {instance_id} InService/Healthy under ELB health checks",
    )
    assert final["LifecycleState"] == "InService", final
    assert final["HealthStatus"] == "Healthy", final
    described = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert described["DesiredCapacity"] == 1, described["DesiredCapacity"]


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _teardown_step(fn, *, gone=(), busy=(), timeout_s=300.0):
    """Run one teardown call: done on success or a `gone` (already deleted) code; a `busy`
    refusal is retried every 2 s to timeout_s; anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone:
                return
            if code not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy and return it; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _default_vpc(ctx, min_subnets=1):
    """(vpc_id, subnet_ids) from the shared network VPC, one usable subnet per AZ."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    ).get("Subnets", [])
    per_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["SubnetId"]):
        if sn.get("AvailableIpAddressCount", 0) > 0:
            per_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    ids = [per_az[az] for az in sorted(per_az)]
    if len(ids) < min_subnets:
        raise AssertionError(
            f"shared network VPC {vpc_id} has {len(ids)} usable subnets, need {min_subnets}"
        )
    return vpc_id, ids


def _http_sg(ctx, vpc_id: str, port: int, source: dict) -> str:
    """A security group allowing inbound tcp/port from *source*; its delete is retried because a
    load balancer ENI keeps the group referenced for a while after its owner is deleted."""
    ec2 = ctx.client("ec2")
    gid = ec2.create_security_group(
        GroupName=ctx.unique_name(_XSVC_PREFIX + "sg-"),
        Description="sim2real xsvc container archetype HTTP ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv()}],
    )["GroupId"]

    def _drop():
        for _ in range(18):
            try:
                ec2.delete_security_group(GroupId=gid)
                return
            except Exception as exc:  # noqa: BLE001 - ENI still detaching
                if "InvalidGroup.NotFound" in str(exc):
                    return
                last = exc
                time.sleep(10)
        raise AssertionError(f"security group {gid} could not be deleted: {last!r}")

    ctx.on_cleanup(_drop)
    ec2.authorize_security_group_ingress(
        GroupId=gid,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
                **source,
            }
        ],
    )
    return gid


def _ssm_ami(ctx, parameter: str) -> str:
    """An AMI id from an AWS-published SSM public parameter rather than a region-bound literal."""
    value = ctx.client("ssm").get_parameter(Name=parameter)["Parameter"]["Value"]
    if value.startswith("{"):
        value = json.loads(value)["image_id"]
    assert value.startswith("ami-"), f"{parameter} did not resolve to an AMI: {value!r}"
    return value


def _launch_template(
    ctx, image_id, user_data, *, instance_type="t3.micro", instance_profile=None, sg_ids=None
):
    """A launch template that tags both the instance and its volume at launch."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(_XSVC_PREFIX + "lt-")
    data: dict = {
        "ImageId": image_id,
        "InstanceType": instance_type,
        "UserData": base64.b64encode(user_data.encode("utf-8")).decode("ascii"),
        "TagSpecifications": [
            {"ResourceType": "instance", "Tags": _tags_kv()},
            {"ResourceType": "volume", "Tags": _tags_kv()},
        ],
    }
    if instance_profile:
        data["IamInstanceProfile"] = {"Name": instance_profile}
    if sg_ids:
        data["SecurityGroupIds"] = list(sg_ids)
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData=data,
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
    )

    def _drop():
        _teardown_step(lambda: ec2.delete_launch_template(LaunchTemplateName=name),
                       gone=("InvalidLaunchTemplateName.NotFoundException",))

    ctx.on_cleanup(_drop)
    return name


def _create_asg(
    ctx,
    lt_name,
    subnets,
    *,
    min_size=0,
    max_size=1,
    desired=0,
    target_group_arns=None,
    health_check_type=None,
    grace=None,
):
    """An Auto Scaling group whose teardown force-deletes and waits for it to disappear, so its
    instances are terminated before the launch template and security groups are deleted."""
    asg = ctx.client("autoscaling")
    name = ctx.unique_name(_XSVC_PREFIX + "asg-")
    kwargs: dict = dict(
        AutoScalingGroupName=name,
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        VPCZoneIdentifier=",".join(subnets),
        Tags=[{"Key": k, "Value": v, "PropagateAtLaunch": True} for k, v in _MANAGED_TAGS.items()],
    )
    if target_group_arns:
        kwargs["TargetGroupARNs"] = list(target_group_arns)
    if health_check_type:
        kwargs["HealthCheckType"] = health_check_type
    if grace is not None:
        kwargs["HealthCheckGracePeriod"] = grace
    asg.create_auto_scaling_group(**kwargs)

    def _drop():
        busy = ("ScalingActivityInProgress", "ResourceInUse")
        _teardown_step(
            lambda: asg.update_auto_scaling_group(
                AutoScalingGroupName=name, MinSize=0, DesiredCapacity=0
            ),
            busy=busy,
        )
        _teardown_step(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True),
                       busy=busy)
        _poll_until(
            lambda: asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name]),
            lambda r: not r["AutoScalingGroups"],
            timeout_s=600,
            interval_s=2,
            description=f"auto scaling group {name} deleted",
        )

    ctx.on_cleanup(_drop)
    return name


def _describe_asg(ctx, name) -> dict:
    groups = (
        ctx.client("autoscaling")
        .describe_auto_scaling_groups(AutoScalingGroupNames=[name])
        .get("AutoScalingGroups", [])
    )
    assert groups, f"auto scaling group {name} not found"
    return groups[0]


def _http_get(ctx, url: str, timeout_s: float = 10.0):
    """(status, body) for a plain GET; HTTP error statuses are returned, and a transport failure
    returns (None, reason)."""
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, headers={**({"User-Agent": "sim2real-xsvc"}), **_route})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # retried by the caller
        return None, f"{type(exc).__name__}: {exc}"


def _create_target_group(ctx, vpc_id, **kwargs):
    """An ELBv2 target group with a 5s deregistration delay so teardown is not blocked."""
    elb = ctx.client("elbv2")
    params = dict(
        Name=ctx.unique_name(_XSVC_PREFIX + "tg-"),
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
        HealthCheckProtocol="HTTP",
        HealthCheckPath="/",
        HealthCheckIntervalSeconds=10,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
        HealthCheckTimeoutSeconds=5,
        Matcher={"HttpCode": "200"},
        Tags=_tags_kv(),
    )
    params.update(kwargs)
    tg = elb.create_target_group(**params)["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop():
        # A listener or a draining target keeps the group in use for a while.
        _teardown_step(lambda: elb.delete_target_group(TargetGroupArn=arn), busy=("ResourceInUse",))

    ctx.on_cleanup(_drop)
    elb.modify_target_group_attributes(
        TargetGroupArn=arn,
        Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": "5"}],
    )
    return tg


def _create_alb(ctx, subnets, sg_ids):
    """An internet-facing ALB, waited to 'active', so HTTP can reach it from outside the VPC."""
    elb = ctx.client("elbv2")
    lb = elb.create_load_balancer(
        Name=ctx.unique_name(_XSVC_PREFIX + "lb-"),
        Subnets=subnets,
        SecurityGroups=sg_ids,
        Scheme="internet-facing",
        Type="application",
        IpAddressType="ipv4",
        Tags=_tags_kv(),
    )["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop():
        _teardown_step(lambda: elb.delete_load_balancer(LoadBalancerArn=arn))
        # Wait for the ALB's ENIs to go away before the security group teardown runs.
        deadline = time.monotonic() + 300.0
        while True:
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
                    return
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(f"load balancer {arn} still described 300 s after its delete")
            time.sleep(2)

    ctx.on_cleanup(_drop)
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] in ("active", "failed"),
        timeout_s=420,
        interval_s=10,
        description=f"load balancer {arn} active",
    )
    assert lb["State"]["Code"] == "active", lb["State"]
    return lb


def _create_listener(ctx, lb_arn, tg_arn, port=80):
    elb = ctx.client("elbv2")
    listener = elb.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=_tags_kv(),
    )["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: _teardown_step(lambda: elb.delete_listener(ListenerArn=arn),
                                          gone=("ListenerNotFound",)))
    return listener


def _target_health(ctx, tg_arn) -> dict[str, str]:
    """{target-id: health-state} for every target currently in the group."""
    descs = ctx.client("elbv2").describe_target_health(TargetGroupArn=tg_arn)[
        "TargetHealthDescriptions"
    ]
    return {d["Target"]["Id"]: d["TargetHealth"]["State"] for d in descs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
