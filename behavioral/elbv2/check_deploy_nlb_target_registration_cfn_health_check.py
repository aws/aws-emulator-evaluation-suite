"""deploy-nlb-target-registration-cfn-health-check."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-nlb-target-registration-cfn-health-check"
GROUP = "deploy"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A target (an ALB) registered with a CFN-deployed NLB target group starts 'initial' and turns
    'healthy', and the live target group carries the template's health-check settings."""
    subnets = _get_default_subnets(ctx)
    backend_alb_arn = _create_backend_alb(ctx, subnets["subnet_ids"], subnets["vpc_id"])

    tg_name = _short_name(ctx, "sim2realnlbtg")
    nlb_name = _short_name(ctx, "sim2realnlb")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"},
            "VpcId": {"Type": "AWS::EC2::VPC::Id"},
        },
        "Resources": {
            "Nlb": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Name": nlb_name,
                    "Type": "network",
                    "Scheme": "internet-facing",
                    "Subnets": {"Ref": "SubnetIds"},
                },
            },
            "Tg": {
                "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                "Properties": {
                    "Name": tg_name,
                    "TargetType": "alb",
                    "Protocol": "TCP",
                    "Port": 80,
                    "VpcId": {"Ref": "VpcId"},
                    "HealthCheckProtocol": "HTTP",
                    "HealthCheckPath": "/",
                    "HealthCheckIntervalSeconds": 10,
                },
            },
            "Listener": {
                "Type": "AWS::ElasticLoadBalancingV2::Listener",
                "Properties": {
                    "LoadBalancerArn": {"Ref": "Nlb"},
                    "Port": 80,
                    "Protocol": "TCP",
                    "DefaultActions": [{"Type": "forward", "TargetGroupArn": {"Ref": "Tg"}}],
                },
            },
        },
        "Outputs": {
            "NlbArn": {"Value": {"Ref": "Nlb"}},
            "ListenerArn": {"Value": {"Ref": "Listener"}},
            "TgArn": {"Value": {"Ref": "Tg"}},
        },
    }
    outputs = _deploy_cfn(
        ctx,
        template,
        parameters=[
            {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(subnets["subnet_ids"])},
            {"ParameterKey": "VpcId", "ParameterValue": subnets["vpc_id"]},
        ],
    )
    tg_arn = outputs["TgArn"]

    elbv2 = ctx.client("elbv2")
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": backend_alb_arn}])
    ctx.on_cleanup(
        lambda: elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": backend_alb_arn}])
    )

    # Immediately after registration the target must not already be healthy: AWS starts it in
    # 'initial' (reason Elb.RegistrationInProgress) before the first health check cycle runs.
    initial_resp = elbv2.describe_target_health(TargetGroupArn=tg_arn, Targets=[{"Id": backend_alb_arn}])
    initial_state = initial_resp["TargetHealthDescriptions"][0]["TargetHealth"]["State"]
    assert initial_state == "initial", f"expected initial state right after RegisterTargets, got {initial_state!r}"

    _poll_target_health(ctx, tg_arn, backend_alb_arn, want_state="healthy", timeout_s=280.0)

    # The terminal read confirms CFN actually wired the template's health-check properties through
    # to the live target group, rather than silently dropping them: a default target group would
    # not carry this exact interval/path/protocol combination.
    tg = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    assert tg["HealthCheckIntervalSeconds"] == 10, (
        f"expected CFN-configured HealthCheckIntervalSeconds=10, got {tg['HealthCheckIntervalSeconds']!r}"
    )
    assert tg["HealthCheckProtocol"] == "HTTP", (
        f"expected CFN-configured HealthCheckProtocol='HTTP', got {tg['HealthCheckProtocol']!r}"
    )
    assert tg["HealthCheckPath"] == "/", (
        f"expected CFN-configured HealthCheckPath='/', got {tg['HealthCheckPath']!r}"
    )




def _short_name(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _get_default_subnets(ctx) -> dict:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    by_az: dict[str, dict] = {}
    for s in resp.get("Subnets", []):
        by_az.setdefault(s["AvailabilityZone"], s)
    if len(by_az) < 2:
        raise AssertionError(
            "account has no default VPC with subnets in >=2 distinct AZs; "
            "an NLB requires at least 2 AZ subnets and this check has no fallback VPC provisioning"
        )
    chosen = list(by_az.values())[:2]
    return {"subnet_ids": [s["SubnetId"] for s in chosen], "vpc_id": chosen[0]["VpcId"]}


def _poll_lb_active(ctx, lb_arn: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        lbs = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"]
        state = lbs[0]["State"]["Code"]
        if state == "active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"load balancer never became active, last state {state!r}")


def _create_backend_alb(ctx, subnet_ids: list[str], vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    sg_name = _short_name(ctx, "sim2realbealbsg")
    sg = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real backend ALB ingress for NLB health checks",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}],
    )
    sg_id = sg["GroupId"]

    def _cleanup_sg() -> None:
        deadline = time.monotonic() + 120.0
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except Exception:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(5)

    ctx.on_cleanup(_cleanup_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": ctx.network().cidr}]}],
    )
    name = _short_name(ctx, "sim2realbealb")
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Type="application",
        Scheme="internet-facing",
        SecurityGroups=[sg_id],
        Tags=[{"Key": "Name", "Value": name}],
    )
    lb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    _poll_lb_active(ctx, lb_arn)
    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Port=80,
        Protocol="HTTP",
        DefaultActions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "ok"},
            }
        ],
    )["Listeners"][0]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener["ListenerArn"]))
    return lb_arn


def _deploy_cfn(ctx, template_body: dict, parameters: list[dict] | None = None) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-nlbstack-")
    kwargs = {"StackName": stack_name, "TemplateBody": json.dumps(template_body)}
    if parameters:
        kwargs["Parameters"] = parameters

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(**kwargs)
    ctx.on_cleanup(_cleanup)
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
    except Exception as exc:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        reasons = [e.get("ResourceStatusReason", "") for e in events if "FAILED" in e.get("ResourceStatus", "")]
        raise AssertionError(f"stack {stack_name} failed to create: {reasons}") from exc
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _poll_target_health(
    ctx, tg_arn: str, target_id: str, want_state: str = "healthy", timeout_s: float = 150.0, interval_s: float = 5.0
) -> str:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = elbv2.describe_target_health(TargetGroupArn=tg_arn, Targets=[{"Id": target_id}])
        descs = resp["TargetHealthDescriptions"]
        if descs:
            last = descs[0]["TargetHealth"]["State"]
            if last == want_state:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"target never reached {want_state!r}, last observed state={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
