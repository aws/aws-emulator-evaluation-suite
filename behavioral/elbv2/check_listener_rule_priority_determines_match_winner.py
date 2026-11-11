"""listener-rule-priority-determines-match-winner."""
from __future__ import annotations

import time
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "listener-rule-priority-determines-match-winner"
GROUP = "ordering"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """When two rules' conditions both match a request, the lowest numeric priority wins, in
    DescribeRules ordering and in the HTTP response, before and after SetRulePriorities swaps them."""
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids = _get_default_vpc_subnets(ctx)
    sg_id = _create_http_sg(ctx, vpc_id)
    lb_arn, dns_name = _create_alb(ctx, subnet_ids, sg_id)
    listener_arn = _create_listener(ctx, lb_arn, 80, "default-body")

    rule_high = elbv2.create_rule(
        ListenerArn=listener_arn,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/test*"]}}],
        Priority=5,
        Actions=[_fixed_response_action("P5")],
    )["Rules"][0]["RuleArn"]
    rule_low = elbv2.create_rule(
        ListenerArn=listener_arn,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/test*"]}}],
        Priority=50,
        Actions=[_fixed_response_action("P50")],
    )["Rules"][0]["RuleArn"]

    rules_before = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    non_default = sorted((r for r in rules_before if not r["IsDefault"]), key=lambda r: int(r["Priority"]))
    assert non_default[0]["RuleArn"] == rule_high, "lowest-priority rule should sort first"

    url = f"http://{dns_name}/test"
    body_before = _wait_for_http_body(ctx, url, timeout_s=180.0)
    assert body_before == "P5", f"expected priority-5 rule to win, got body {body_before!r}"

    # Swap priorities atomically in one call - SetRulePriorities accepts multiple
    # entries and applies them together, so the two new values (100, 1) never
    # collide with each other or with the current values (5, 50) mid-update.
    elbv2.set_rule_priorities(
        RulePriorities=[
            {"RuleArn": rule_high, "Priority": 100},
            {"RuleArn": rule_low, "Priority": 1},
        ]
    )

    rules_after = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    non_default_after = sorted((r for r in rules_after if not r["IsDefault"]), key=lambda r: int(r["Priority"]))
    assert non_default_after[0]["RuleArn"] == rule_low, "rule_low should now sort first after swap"

    # _wait_for_http_body(..., expected=...) raises on its own if "P50" is never served,
    # so reaching this line already proves the swap took effect.
    _wait_for_http_body(ctx, url, timeout_s=180.0, expected="P50")


# ===== helpers =====

def _fixed_response_action(body: str) -> dict[str, Any]:
    return {
        "Type": "fixed-response",
        "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": body},
    }


def _get_default_vpc_subnets(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision an ALB for this check")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        if s.get("MapPublicIpOnLaunch"):
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 AZs")
    return vpc_id, subnet_ids


def _create_http_sg(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-sg-")
    sg = ec2.create_security_group(GroupName=name, Description="sim2real behavioral test", VpcId=vpc_id)
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}],
    )
    ctx.on_cleanup(lambda: _delete_sg_with_retry(ctx, sg_id))
    return sg_id


def _delete_sg_with_retry(ctx, sg_id: str, timeout_s: float = 180.0) -> None:
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    # The ALB's ENIs hold the group until they are released: retry only DependencyViolation.
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_alb(ctx, subnet_ids: list[str], sg_id: str) -> tuple[str, str]:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-behav-")[:32]
    lb = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id], Scheme="internet-facing", Type="application",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    _wait_lb_active(ctx, lb_arn)
    dns_name = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["DNSName"]
    return lb_arn, dns_name


def _wait_lb_active(ctx, lb_arn: str, timeout_s: float = 240.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        if lb["State"]["Code"] == "active":
            return
        if lb["State"]["Code"] == "failed":
            raise AssertionError(f"load balancer entered failed state: {lb['State']}")
        time.sleep(5)
    raise AssertionError("load balancer never became active in time")


def _create_listener(ctx, lb_arn: str, port: int, default_body: str) -> str:
    elbv2 = ctx.client("elbv2")
    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=port,
        DefaultActions=[_fixed_response_action(default_body)],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _wait_for_http_body(ctx, url: str, timeout_s: float, expected: str | None = None) -> str:
    deadline = time.monotonic() + timeout_s
    last_body = ""
    seen: list[str] = []
    while time.monotonic() < deadline:
        try:
            _url, _route = ctx.endpoint_route(url)
            with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=5) as resp:  # noqa: S310 - plain HTTP by design
                last_body = resp.read().decode("utf-8", errors="replace")
            seen.append(last_body)
            if expected is None or last_body == expected:
                return last_body
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            seen.append(f"<transport: {exc}>")
        time.sleep(5)
    if expected is not None:
        raise AssertionError(
            f"{url} never served {expected!r} within {timeout_s}s; last observed: {seen[-5:]}"
        )
    return last_body


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
