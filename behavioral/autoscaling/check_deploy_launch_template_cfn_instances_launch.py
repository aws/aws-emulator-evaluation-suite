"""deploy-launch-template-cfn-instances-launch."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "deploy-launch-template-cfn-instances-launch"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed ASG backed by an AWS::EC2::LaunchTemplate resource actually
    results in a real, running EC2 instance matching the template's AMI and instance type --
    the template linkage is functionally live, not merely a control-plane cross-reference."""
    autoscaling = ctx.client("autoscaling")
    cfn = ctx.client("cloudformation")

    subnet_id = _default_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)
    asg_name = ctx.unique_name("sim2real-asg-lt-")
    stack_name = ctx.unique_name("sim2real-stack-lt-")

    template = {
        "Resources": {
            "LaunchTemplate": {
                "Type": "AWS::EC2::LaunchTemplate",
                "Properties": {
                    "LaunchTemplateData": {"ImageId": ami_id, "InstanceType": "t3.micro"}
                },
            },
            "ASG": {
                "Type": "AWS::AutoScaling::AutoScalingGroup",
                "Properties": {
                    "AutoScalingGroupName": asg_name,
                    "MinSize": "1",
                    "MaxSize": "1",
                    "DesiredCapacity": "1",
                    "VPCZoneIdentifier": [subnet_id],
                    "LaunchTemplate": {
                        "LaunchTemplateId": {"Ref": "LaunchTemplate"},
                        "Version": {"Fn::GetAtt": ["LaunchTemplate", "LatestVersionNumber"]},
                    },
                },
            },
        }
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        OnFailure="DELETE",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"unexpected stack status {status}"

    def _find_instances() -> list[dict[str, Any]]:
        resp = autoscaling.describe_auto_scaling_instances()
        return [
            i for i in resp["AutoScalingInstances"] if i["AutoScalingGroupName"] == asg_name
        ]

    # InService is the only terminal state here -- Pending/Pending:Wait/Pending:Proceed are
    # transient, so accepting them would pass a target that never actually finishes launching.
    instances = _poll_until(
        _find_instances,
        lambda insts: len(insts) >= 1 and insts[0]["LifecycleState"] == "InService",
        timeout_s=240,
        interval_s=10,
    )
    instance_id = instances[0]["InstanceId"]

    # The ASG's own bookkeeping says InService; cross-check at EC2 -- the destination the
    # template linkage actually targets -- that a real instance matching the template exists.
    ec2 = ctx.client("ec2")
    ec2_instance = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
        "Instances"
    ][0]
    assert ec2_instance["State"]["Name"] == "running", (
        f"EC2 reports {ec2_instance['State']['Name']}, not running, for {instance_id}"
    )
    assert ec2_instance["ImageId"] == ami_id, (
        f"expected AMI {ami_id} from the launch template, got {ec2_instance['ImageId']}"
    )
    assert ec2_instance["InstanceType"] == "t3.micro", (
        f"expected t3.micro from the launch template, got {ec2_instance['InstanceType']}"
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
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )


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
