"""deploy-cfn-alb-nonexistent-subnet-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-cfn-alb-nonexistent-subnet-rejected"
GROUP = "deploy"
SERVICES = ["elbv2"]

_TEMPLATE = json.dumps(
    {
        "Parameters": {"SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"}},
        "Resources": {
            "Alb": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Type": "application",
                    "Scheme": "internal",
                    "Subnets": {"Ref": "SubnetIds"},
                },
            },
        },
        "Outputs": {"LoadBalancerArn": {"Value": {"Ref": "Alb"}}},
    }
)

_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN ALB stack naming a nonexistent subnet id rolls back (ROLLBACK_COMPLETE, reason naming the
    subnet) without creating the load balancer; the same template with real subnets succeeds."""
    cfn = ctx.client("cloudformation")
    elbv2 = ctx.client("elbv2")

    good_subnet_ids = _setup_network(ctx)
    bad_name = ctx.unique_name("sim2real-behav-stack-b-")
    bad_subnet = "subnet-00000000000000000"
    bad_subnets = [good_subnet_ids[0], bad_subnet]

    cfn.create_stack(
        StackName=bad_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "SubnetIds", "ParameterValue": ",".join(bad_subnets)}],
        Tags=_TAGS_KV,
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=bad_name))
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=bad_name, WaiterConfig={"Delay": 2, "MaxAttempts": 75}
        )
        raise AssertionError("expected the bad-subnet stack to roll back, but it reached CREATE_COMPLETE")
    except WaiterError:
        pass

    status = cfn.describe_stacks(StackName=bad_name)["Stacks"][0]["StackStatus"]
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    reasons = [
        e.get("ResourceStatusReason", "")
        for e in cfn.describe_stack_events(StackName=bad_name)["StackEvents"]
    ]
    assert any(bad_subnet in r and "does not exist" in r for r in reasons), (
        f"expected a stack event citing {bad_subnet!r} as nonexistent, got reasons: {reasons!r}"
    )

    # Effect absent: the load balancer resource itself was never created.
    code, code_msg = _error(lambda: cfn.describe_stack_resource(StackName=bad_name, LogicalResourceId="Alb"))
    assert code == "ValidationError", (
        f"expected the Alb resource to never have existed, got {code}"
    )
    want = f"Resource Alb does not exist for stack {bad_name}"
    assert code_msg == want, f"describing the never-created Alb said {code_msg!r}, expected {want!r}"

    # Positive control: the identical template with real subnet ids succeeds.
    good_name = ctx.unique_name("sim2real-behav-stack-g-")

    def _cleanup():
        cfn.delete_stack(StackName=good_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=good_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=good_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "SubnetIds", "ParameterValue": ",".join(good_subnet_ids)}],
        Tags=_TAGS_KV,
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=good_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    desc = cfn.describe_stacks(StackName=good_name)["Stacks"][0]
    lb_arn = {o["OutputKey"]: o["OutputValue"] for o in desc["Outputs"]}["LoadBalancerArn"]
    lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
    assert sorted(az["SubnetId"] for az in lb["AvailabilityZones"]) == sorted(good_subnet_ids), (
        f"expected the accepted stack's ALB to use {sorted(good_subnet_ids)!r}, "
        f"got {sorted(az['SubnetId'] for az in lb['AvailabilityZones'])!r}"
    )




def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


def _delete_when_free(delete, deadline_s: float = 300.0) -> None:
    """Run an EC2 network delete, retrying DependencyViolation while the deleted load balancer's
    ENIs drain from the subnet (they outlive DELETE_COMPLETE); raises once the deadline passes."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
        time.sleep(10)


def _setup_network(ctx, num_subnets: int = 2) -> list[str]:
    """A VPC of the check's own with one subnet per AZ; never the account's default VPC."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS_KV}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    if len(azs) < num_subnets:
        raise AssertionError(f"region has only {len(azs)} available AZ(s), need {num_subnets}")
    subnet_ids = []
    for i in range(num_subnets):
        az = azs[i]["ZoneName"]
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.0.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS_KV}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_when_free(lambda: ec2.delete_subnet(SubnetId=sid)))
    return subnet_ids


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
