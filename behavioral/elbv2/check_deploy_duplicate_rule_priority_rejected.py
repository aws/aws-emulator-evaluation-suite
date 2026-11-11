"""deploy-duplicate-rule-priority-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-duplicate-rule-priority-rejected"
GROUP = "deploy"
SERVICES = ["elbv2"]

_TEMPLATE = json.dumps(
    {
        "Parameters": {"SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"}},
        "Resources": {
            "Alb": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {"Type": "application", "Scheme": "internal", "Subnets": {"Ref": "SubnetIds"}},
            },
            "Listener": {
                "Type": "AWS::ElasticLoadBalancingV2::Listener",
                "Properties": {
                    "LoadBalancerArn": {"Ref": "Alb"},
                    "Port": 80,
                    "Protocol": "HTTP",
                    "DefaultActions": [
                        {
                            "Type": "fixed-response",
                            "FixedResponseConfig": {
                                "StatusCode": "404",
                                "ContentType": "text/plain",
                                "MessageBody": "no-match",
                            },
                        }
                    ],
                },
            },
            "BaseRule": {
                "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
                "Properties": {
                    "ListenerArn": {"Ref": "Listener"},
                    "Priority": 20,
                    "Conditions": [{"Field": "path-pattern", "Values": ["/base"]}],
                    "Actions": [
                        {
                            "Type": "fixed-response",
                            "FixedResponseConfig": {
                                "StatusCode": "200",
                                "ContentType": "text/plain",
                                "MessageBody": "base",
                            },
                        }
                    ],
                },
            },
        },
        "Outputs": {"ListenerArn": {"Value": {"Ref": "Listener"}}},
    }
)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRule at a priority already occupied by a CloudFormation-deployed rule on the same
    listener is rejected with PriorityInUseException, the clashing rule is never created, and a
    rule creation at a free priority on that same listener still succeeds."""
    subnet_ids = _default_vpc_subnets(ctx)
    outputs = _deploy_cfn(
        ctx, _TEMPLATE, [{"ParameterKey": "SubnetIds", "ParameterValue": ",".join(subnet_ids)}]
    )
    listener_arn = outputs["ListenerArn"]
    elbv2 = ctx.client("elbv2")

    def _clash():
        elbv2.create_rule(
            ListenerArn=listener_arn,
            Priority=20,
            Conditions=[{"Field": "path-pattern", "Values": ["/clash"]}],
            Actions=[
                {
                    "Type": "fixed-response",
                    "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "clash"},
                }
            ],
        )

    code, message = _error(_clash)
    assert code == "PriorityInUse", f"expected PriorityInUse, got CODE={code!r}"
    assert message == "Priority '20' is currently in use", f"create_rule MESSAGE={message!r}"

    rules = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    non_default = [r for r in rules if not r["IsDefault"]]
    assert len(non_default) == 1, f"the rejected clashing rule must not have been created, saw {non_default!r}"
    assert non_default[0]["Priority"] == "20", f"expected priority '20', got {non_default[0]['Priority']!r}"
    assert non_default[0]["Conditions"][0]["Values"] == ["/base"], (
        f"expected the CFN-deployed BaseRule's condition to survive, got {non_default[0]['Conditions']!r}"
    )

    # Positive control: rule creation at a free priority on the very same listener still works.
    created = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=30,
        Conditions=[{"Field": "path-pattern", "Values": ["/ok"]}],
        Actions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "ok"},
            }
        ],
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["Rules"][0]
    ctx.on_cleanup(lambda: elbv2.delete_rule(RuleArn=created["RuleArn"]))
    assert created["Priority"] == "30", f"expected the free-priority create to land at '30', got {created['Priority']!r}"

    rules_after = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    non_default_after = [r for r in rules_after if not r["IsDefault"]]
    got_priorities = sorted(int(r["Priority"]) for r in non_default_after)
    assert got_priorities == [20, 30], (
        f"expected the CFN-deployed rule (20) and the free-priority rule (30) to coexist, got {got_priorities!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account has no shared network VPC to attach the load balancer to")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 distinct AZs")
    return subnet_ids


def _deploy_cfn(ctx, template_body, parameters):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
