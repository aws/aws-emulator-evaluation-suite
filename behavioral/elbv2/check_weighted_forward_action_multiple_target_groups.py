"""weighted-forward-action-multiple-target-groups."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "weighted-forward-action-multiple-target-groups"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A rule's weighted forward action across multiple target groups round-trips its weights exactly."""
    net = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    # Target groups are created BEFORE the load balancer so LIFO cleanup deletes the load
    # balancer (and its listener's DefaultAction reference to tg1) first.
    tg1 = _create_target_group(ctx, net["vpc_id"])
    tg2 = _create_target_group(ctx, net["vpc_id"])
    lb = _create_alb(ctx, net["subnet_ids"])

    listener = elbv2.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"],
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg1["TargetGroupArn"]}],
    )["Listeners"][0]

    rule = elbv2.create_rule(
        ListenerArn=listener["ListenerArn"],
        Priority=5,
        Conditions=[{"Field": "path-pattern", "Values": ["/canary/*"]}],
        Actions=[
            {
                "Type": "forward",
                "ForwardConfig": {
                    "TargetGroups": [
                        {"TargetGroupArn": tg1["TargetGroupArn"], "Weight": 70},
                        {"TargetGroupArn": tg2["TargetGroupArn"], "Weight": 30},
                    ]
                },
            }
        ],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-elbv2-"}],
    )["Rules"][0]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_rule(RuleArn=rule["RuleArn"])))

    described = elbv2.describe_rules(RuleArns=[rule["RuleArn"]])["Rules"][0]
    action = described["Actions"][0]
    assert action["Type"] == "forward", f"expected action type 'forward', got {action['Type']!r}"
    weights = {tg["TargetGroupArn"]: tg["Weight"] for tg in action["ForwardConfig"]["TargetGroups"]}
    assert weights[tg1["TargetGroupArn"]] == 70, weights
    assert weights[tg2["TargetGroupArn"]] == 30, weights
    assert len(weights) == 2, f"expected exactly 2 target groups in ForwardConfig, got {weights!r}"


# ===== helpers =====
def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("LoadBalancerNotFound", "RuleNotFound"):
            raise


def _default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 availability zones")
    chosen = list(by_az.values())[:2]
    return {
        "vpc_id": vpc_id,
        "subnet_ids": [s["SubnetId"] for s in chosen],
        "subnet_cidrs": [s["CidrBlock"] for s in chosen],
    }


_TAGS = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-elbv2-"}]


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(Name=name, Subnets=subnet_ids, Type="application", Tags=list(_TAGS))
    lb = resp["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn)))
    return lb


def _create_target_group(ctx, vpc_id, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-elbv2-tg-")
    params = {"Name": name, "Protocol": "HTTP", "Port": 80, "VpcId": vpc_id, "TargetType": "ip", "Tags": list(_TAGS)}
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop_tg():
        # delete_load_balancer (LIFO-earlier in cleanup) is asynchronous: the listener whose
        # DefaultAction references this target group can outlive it by several seconds, so
        # retry ResourceInUse every 2 s to a deadline; an already-deleted group is clean.
        deadline = time.monotonic() + 120
        while True:
            try:
                elbv2.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "TargetGroupNotFound":
                    return
                if code != "ResourceInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_drop_tg)
    return tg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
