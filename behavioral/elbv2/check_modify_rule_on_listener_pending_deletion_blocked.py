"""modify-rule-on-listener-pending-deletion-blocked."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-rule-on-listener-pending-deletion-blocked"
GROUP = "negative-classes"
SERVICES = ["elbv2"]

_FIXED_RESPONSE = lambda body: {  # noqa: E731
    "Type": "fixed-response",
    "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": body},
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteListener, ModifyRule and DescribeRules on that listener's rule fail with
    RuleNotFound, while ModifyRule on a rule of another live listener on the same load balancer
    still succeeds and takes effect."""
    elbv2 = ctx.client("elbv2")
    subnet_ids = _vpc_and_subnets(ctx)

    lb_arn = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-ruledel-"), Subnets=subnet_ids, Scheme="internal", Type="application",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))

    doomed_listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Port=80, Protocol="HTTP", DefaultActions=[_FIXED_RESPONSE("default-1")],
    )["Listeners"][0]["ListenerArn"]
    doomed_rule_arn = elbv2.create_rule(
        ListenerArn=doomed_listener_arn, Priority=10,
        Conditions=[{"Field": "path-pattern", "Values": ["/doomed"]}],
        Actions=[_FIXED_RESPONSE("doomed")],
    )["Rules"][0]["RuleArn"]

    live_listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Port=8080, Protocol="HTTP", DefaultActions=[_FIXED_RESPONSE("default-2")],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=live_listener_arn))
    live_rule_arn = elbv2.create_rule(
        ListenerArn=live_listener_arn, Priority=10,
        Conditions=[{"Field": "path-pattern", "Values": ["/live"]}],
        Actions=[_FIXED_RESPONSE("live-before")],
    )["Rules"][0]["RuleArn"]
    ctx.on_cleanup(lambda: elbv2.delete_rule(RuleArn=live_rule_arn))

    # Listener/rule deletion is documented as synchronous, so no wait follows.
    elbv2.delete_listener(ListenerArn=doomed_listener_arn)

    def _modify_doomed():
        elbv2.modify_rule(RuleArn=doomed_rule_arn, Actions=[_FIXED_RESPONSE("should-not-apply")])

    code, message = _error(_modify_doomed)
    assert code == "RuleNotFound", f"CODE={code!r}"
    expected = f"Rule '{doomed_rule_arn}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    describe_code, describe_message = _error(lambda: elbv2.describe_rules(RuleArns=[doomed_rule_arn]))
    assert describe_code == "RuleNotFound", f"CODE={describe_code!r}"
    expected = "One or more rules not found"
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"

    elbv2.modify_rule(RuleArn=live_rule_arn, Actions=[_FIXED_RESPONSE("live-after")])
    refreshed = elbv2.describe_rules(RuleArns=[live_rule_arn])["Rules"][0]
    assert refreshed["Actions"][0]["FixedResponseConfig"]["MessageBody"] == "live-after"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = list(by_az.values())[:2]
        if len(subnet_ids) >= 2:
            return subnet_ids

    # No usable shared network (a freshly provisioned account may not have one) — provision our own.
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[
        {"Key": "sim2real", "Value": "behavioral"},
        {"Key": "Name", "Value": ctx.unique_name("sim2real-ruledel-vpc-")},
    ])
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    subnet_ids = []
    for i in range(2):
        az = azs[i % len(azs)]["ZoneName"]
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: ec2.delete_subnet(SubnetId=sid))
        subnet_ids.append(sid)
    return subnet_ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
