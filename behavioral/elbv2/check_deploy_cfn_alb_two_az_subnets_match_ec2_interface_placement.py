"""deploy-cfn-alb-two-az-subnets-match-ec2-interface-placement."""
from __future__ import annotations

import ipaddress
import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-alb-two-az-subnets-match-ec2-interface-placement"
GROUP = "deploy"
SERVICES = ["cloudformation", "elbv2", "ec2"]

_STACK_TIMEOUT_S = 600.0


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last: {last!r}")


def _eni_subnet_ids(ec2, description: str) -> list[str]:
    """The subnet ids of every EC2 network interface carrying ``description``."""
    subnet_ids: list[str] = []
    token = None
    while True:
        kw = {"Filters": [{"Name": "description", "Values": [description]}]}
        if token:
            kw["NextToken"] = token
        page = ec2.describe_network_interfaces(**kw)
        subnet_ids.extend(eni["SubnetId"] for eni in page["NetworkInterfaces"])
        token = page.get("NextToken")
        if not token:
            return subnet_ids


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-declared ALB on two subnets in two availability zones, with a target
    registered in each, reports AvailabilityZones whose subnets exactly match those declared,
    and EC2's own network interfaces for it cover every one of those subnets and none outside.
    """
    cfn = ctx.client("cloudformation")
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    network = ctx.network()
    subnet_ids = network.subnet_ids[:2]
    assert len(subnet_ids) == 2, f"the shared network offers {len(subnet_ids)} subnet(s), need 2"
    subnets = ec2.describe_subnets(SubnetIds=subnet_ids)["Subnets"]
    # A target registered in each AZ is what makes ELB provision a network interface there.
    target_ips = [
        str(ipaddress.ip_network(s["CidrBlock"])[10]) for s in sorted(subnets, key=lambda s: s["SubnetId"])
    ]

    stack_name = ctx.unique_name("sim2real-behav-stack-")
    template = json.dumps({
        "Resources": {
            "Alb": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Type": "application",
                    "Scheme": "internal",
                    "Subnets": subnet_ids,
                },
            },
            "Tg": {
                "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                "Properties": {
                    "TargetType": "ip",
                    "Protocol": "HTTP",
                    "Port": 80,
                    "VpcId": network.vpc_id,
                    "Targets": [{"Id": ip, "Port": 80} for ip in target_ips],
                },
            },
            "Listener": {
                "Type": "AWS::ElasticLoadBalancingV2::Listener",
                "Properties": {
                    "LoadBalancerArn": {"Ref": "Alb"},
                    "Protocol": "HTTP",
                    "Port": 80,
                    "DefaultActions": [{"Type": "forward", "TargetGroupArn": {"Ref": "Tg"}}],
                },
            },
        }
    })

    def _delete_stack():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(StackName=stack_name, TemplateBody=template,
                     Tags=[{"Key": "sim2real", "Value": "behav"}])
    ctx.on_cleanup(_delete_stack)
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
    except Exception as exc:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        failures = [
            f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
            for e in events
            if e.get("ResourceStatus", "").endswith("FAILED")
        ]
        raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE: {failures}") from exc

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    alb_resources = [r for r in resources if r["LogicalResourceId"] == "Alb"]
    assert len(alb_resources) == 1, (
        f"stack {stack_name} has {len(alb_resources)} resource(s) named 'Alb': {resources!r}"
    )
    lb_arn = alb_resources[0]["PhysicalResourceId"]

    lb = _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda lb: lb["State"]["Code"] in ("active", "active_impaired", "failed"),
        timeout_s=_STACK_TIMEOUT_S, interval_s=3.0,
        description=f"load balancer {lb_arn} reaching a terminal state",
    )
    assert lb["State"]["Code"] == "active", (
        f"load balancer {lb_arn} settled in {lb['State']!r}, expected 'active'"
    )

    reported_subnet_ids = {az["SubnetId"] for az in lb["AvailabilityZones"]}
    assert reported_subnet_ids == set(subnet_ids), (
        f"AvailabilityZones reported subnets {sorted(reported_subnet_ids)!r}, expected exactly "
        f"the declared subnets {sorted(subnet_ids)!r}"
    )

    suffix = lb_arn.split(":loadbalancer/", 1)[1]
    eni_description = f"ELB {suffix}"
    eni_subnet_ids = _poll_until(
        lambda: _eni_subnet_ids(ec2, eni_description),
        lambda ids: set(ids) == set(subnet_ids),
        timeout_s=180.0, interval_s=3.0,
        description=f"an EC2 network interface in each declared subnet for {lb_arn}",
    )
    stray = set(eni_subnet_ids) - set(subnet_ids)
    assert not stray, (
        f"EC2 network interfaces described '{eni_description}' sit in {sorted(stray)!r}, outside "
        f"the declared subnets {sorted(subnet_ids)!r}"
    )
    missing = set(subnet_ids) - set(eni_subnet_ids)
    assert not missing, (
        f"declared subnet(s) {sorted(missing)!r} have no EC2 network interface described "
        f"'{eni_description}'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
