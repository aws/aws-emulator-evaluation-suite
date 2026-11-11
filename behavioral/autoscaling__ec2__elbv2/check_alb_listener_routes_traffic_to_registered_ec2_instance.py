"""alb-listener-routes-traffic-to-registered-ec2-instance."""
from __future__ import annotations

import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "alb-listener-routes-traffic-to-registered-ec2-instance"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """An HTTP request sent to an internet-facing ALB's listener is actually forwarded to
    the registered, healthy EC2 instance target and returns that instance's response body.
    """
    marker = ctx.unique_name("sim2real-albtraf-body-")
    vpc_id, subnet_ids = _default_vpc_subnets(ctx)
    sg_id = _create_http_sg(ctx, vpc_id, ctx.unique_name("sim2real-albtraf-sg-"),
                            {"IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]})
    backend_sg = _create_http_sg(ctx, vpc_id, ctx.unique_name("sim2real-albtraf-besg-"),
                                 {"UserIdGroupPairs": [{"GroupId": sg_id}]})
    instance_id = _launch_http_instance(
        ctx, subnet_ids[0], backend_sg, ctx.unique_name("sim2real-albtraf-inst-"), body_marker=marker
    )
    tg_arn = _create_target_group(
        ctx, vpc_id, ctx.unique_name("sim2real-albtraf-tg-"),
        interval=10, healthy_threshold=2, unhealthy_threshold=2,
    )
    lb_arn, dns_name = _create_load_balancer(
        ctx, subnet_ids, sg_id, ctx.unique_name("sim2real-albtraf-lb-"),
        lb_type="application", scheme="internet-facing",
    )
    _create_listener(ctx, lb_arn, tg_arn, port=80, protocol="HTTP")

    elbv2 = ctx.client("elbv2")
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": instance_id, "Port": 80}])
    state, _ = _poll_target_state(ctx, tg_arn, instance_id, 80, {"healthy"}, timeout_s=420.0, interval_s=15.0)
    assert state == "healthy"

    body = _fetch_body_with_retry(ctx, f"http://{dns_name}/", timeout_s=180.0, interval_s=10.0)
    assert body.strip() == marker, f"unexpected response body via ALB (want marker {marker!r}): {body!r}"


def _tag_spec(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _default_vpc_subnets(ctx: Any, min_count: int = 2) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host the test ALB/EC2 topology")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < min_count:
        raise AssertionError(f"shared network has fewer than {min_count} distinct-AZ subnets")
    return vpc_id, subnet_ids[:min_count]


def _latest_al2023_ami(ctx: Any) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _create_http_sg(ctx: Any, vpc_id: str, name: str, source: dict) -> str:
    """A security group admitting tcp/80 from *source* (IpRanges or UserIdGroupPairs)."""
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=name, Description="sim2real behavioral test sg", VpcId=vpc_id,
        TagSpecifications=_tag_spec("security-group", name),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg(ec2, sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, **source}],
    )
    return sg_id


def _delete_sg(ec2: Any, sg_id: str, timeout_s: float = 300.0) -> None:
    """Delete *sg_id*, retrying while the load balancer's or instance's ENIs still hold it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except Exception as exc:  # noqa: BLE001 - DependencyViolation until the ENIs are released
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
        time.sleep(10)


def _terminate_and_wait(ctx: Any, instance_id: str) -> None:
    ec2 = ctx.client("ec2")
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _launch_http_instance(ctx: Any, subnet_id: str, sg_id: str, name: str, body_marker: str) -> str:
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)
    kwargs: dict[str, Any] = dict(
        ImageId=ami_id, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        NetworkInterfaces=[{
            "DeviceIndex": 0, "SubnetId": subnet_id, "Groups": [sg_id], "AssociatePublicIpAddress": True,
        }],
        TagSpecifications=_tag_spec("instance", name),
        UserData=(
            "#!/bin/bash\n"
            "dnf install -y httpd 2>/dev/null || yum install -y httpd\n"
            f"echo {body_marker} > /var/www/html/index.html\n"
            "systemctl enable httpd\n"
            "systemctl start httpd\n"
        ),
    )
    instance_id = ec2.run_instances(**kwargs)["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return instance_id


def _create_target_group(
    ctx: Any, vpc_id: str, name: str, protocol: str = "HTTP", port: int = 80, health_path: str = "/",
    interval: int = 10, healthy_threshold: int = 2, unhealthy_threshold: int = 2,
) -> str:
    elbv2 = ctx.client("elbv2")
    kwargs: dict[str, Any] = dict(
        Name=name, Protocol=protocol, Port=port, VpcId=vpc_id, TargetType="instance",
        HealthCheckIntervalSeconds=interval, HealthyThresholdCount=healthy_threshold,
        UnhealthyThresholdCount=unhealthy_threshold,
    )
    if protocol in ("HTTP", "HTTPS"):
        kwargs["HealthCheckProtocol"] = protocol
        kwargs["HealthCheckPath"] = health_path
    tg_arn = elbv2.create_target_group(**kwargs)["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    return tg_arn


def _create_load_balancer(
    ctx: Any, subnet_ids: list[str], sg_id: str, name: str,
    lb_type: str = "application", scheme: str = "internet-facing",
) -> tuple[str, str]:
    elbv2 = ctx.client("elbv2")
    kwargs: dict[str, Any] = dict(Name=name, Subnets=subnet_ids, Scheme=scheme, Type=lb_type)
    if lb_type == "application":
        kwargs["SecurityGroups"] = [sg_id]
    lb = elbv2.create_load_balancer(**kwargs)["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    elbv2.get_waiter("load_balancer_available").wait(LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return lb_arn, lb["DNSName"]


def _create_listener(ctx: Any, lb_arn: str, tg_arn: str, port: int = 80, protocol: str = "HTTP") -> str:
    elbv2 = ctx.client("elbv2")
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol=protocol, Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _target_health(ctx: Any, tg_arn: str, target_id: str, port: int = 80) -> dict | None:
    elbv2 = ctx.client("elbv2")
    desc = elbv2.describe_target_health(TargetGroupArn=tg_arn, Targets=[{"Id": target_id, "Port": port}])
    descs = desc.get("TargetHealthDescriptions", [])
    return descs[0] if descs else None


def _poll_target_state(
    ctx: Any, tg_arn: str, target_id: str, port: int, desired_states: set[str],
    timeout_s: float = 300.0, interval_s: float = 10.0,
) -> tuple[str | None, str | None]:
    deadline = time.monotonic() + timeout_s
    last_state = None
    last_reason = None
    while time.monotonic() < deadline:
        d = _target_health(ctx, tg_arn, target_id, port)
        if d is not None:
            health = d["TargetHealth"]
            last_state = health["State"]
            last_reason = health.get("Reason")
            if last_state in desired_states:
                return last_state, last_reason
        time.sleep(interval_s)
    raise AssertionError(f"target never reached {desired_states}, last_state={last_state} reason={last_reason}")


def _fetch_body_with_retry(ctx, url: str, timeout_s: float = 180.0, interval_s: float = 10.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            _url, _route = ctx.endpoint_route(url)
            with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=10) as resp:  # noqa: S310
                if resp.status == 200:
                    return resp.read().decode("utf-8", errors="replace")
                last_err = AssertionError(f"HTTP {resp.status}")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as err:
            last_err = err
        time.sleep(interval_s)
    raise AssertionError(f"never got a 200 response from {url} within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
