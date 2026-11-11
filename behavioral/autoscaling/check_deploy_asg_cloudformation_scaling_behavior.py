"""deploy-asg-cloudformation-scaling-behavior."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-asg-cloudformation-scaling-behavior"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed ASG actually honors SetDesiredCapacity by launching real
    instances after CREATE_COMPLETE -- not just reaching CREATE_COMPLETE on the stack."""
    autoscaling = ctx.client("autoscaling")
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    subnet_id = _default_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)
    asg_name = ctx.unique_name("sim2real-asg-cfn-")
    stack_name = ctx.unique_name("sim2real-stack-cfn-")

    template = {
        "Resources": {
            "LaunchTemplate": {
                "Type": "AWS::EC2::LaunchTemplate",
                "Properties": {
                    "LaunchTemplateData": {"ImageId": ami_id, "InstanceType": "t3.micro"},
                    "TagSpecifications": [
                        {
                            "ResourceType": "launch-template",
                            "Tags": [{"Key": "sim2real", "Value": CHECK}],
                        }
                    ],
                },
            },
            "ASG": {
                "Type": "AWS::AutoScaling::AutoScalingGroup",
                "Properties": {
                    "AutoScalingGroupName": asg_name,
                    "MinSize": "0",
                    "MaxSize": "3",
                    "DesiredCapacity": "0",
                    "VPCZoneIdentifier": [subnet_id],
                    "LaunchTemplate": {
                        "LaunchTemplateId": {"Ref": "LaunchTemplate"},
                        "Version": {"Fn::GetAtt": ["LaunchTemplate", "LatestVersionNumber"]},
                    },
                    "Tags": [{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
                },
            },
        }
    }

    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template), OnFailure="DELETE")
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"unexpected stack status {status}"

    # The stack created the group with DesiredCapacity=0 -- no instances exist yet.
    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group["Instances"] == [], (
        f"expected zero instances at DesiredCapacity=0, found {group['Instances']}"
    )

    # Now drive the real scale-out through the deployed group.
    autoscaling.set_desired_capacity(
        AutoScalingGroupName=asg_name, DesiredCapacity=2, HonorCooldown=False
    )

    def _instances() -> list[dict[str, Any]]:
        return autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ][0]["Instances"]

    launching_states = {"Pending", "Pending:Wait", "Pending:Proceed", "InService"}
    instances = _poll_until(
        _instances, lambda insts: len(insts) >= 2, timeout_s=300, interval_s=15
    )
    assert len(instances) == 2, f"expected 2 instances after SetDesiredCapacity(2), got {instances}"
    assert all(i["LifecycleState"] in launching_states for i in instances), (
        f"instance(s) in an unexpected lifecycle state: {instances}"
    )

    # Independent read at the true destination: the ASG's own bookkeeping must correspond to
    # real, non-terminated EC2 instances -- not merely entries fabricated in its own response.
    instance_ids = [i["InstanceId"] for i in instances]
    reservations = ec2.describe_instances(InstanceIds=instance_ids)["Reservations"]
    ec2_states = {
        inst["InstanceId"]: inst["State"]["Name"]
        for res in reservations
        for inst in res["Instances"]
    }
    assert set(ec2_states) == set(instance_ids), (
        f"ASG reported instances {instance_ids} but EC2 describe_instances knows about {list(ec2_states)}"
    )
    assert all(state in ("pending", "running") for state in ec2_states.values()), (
        f"expected EC2 instances pending/running, observed {ec2_states}"
    )


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if not subnets:
        raise AssertionError(
            "no shared-network subnet found in this account/region to launch ASG instances into"
        )
    return subnets[0]["SubnetId"]


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]


def _delete_stack(cfn, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" not in exc.response["Error"]["Message"]
        ):
            raise


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 180.0,
    interval_s: float = 10.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
