"""deploy-model-package-group-policy-cfn-enforced."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-model-package-group-policy-cfn-enforced"
GROUP = "deploy"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource policy attached to a ModelPackageGroup via the ModelPackageGroupPolicy
    CloudFormation property is actually enforced/readable through GetModelPackageGroupPolicy
    after stack deployment -- not just accepted and dropped on the floor.
    """
    cf = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    stack_name = ctx.unique_name("sim2real-mpg-stack-")
    group_name = ctx.unique_name("sim2real-mpg-cfn-")
    group_logical_id = "ModelGroup"

    account_id = sts.get_caller_identity()["Account"]
    group_arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:model-package-group/{group_name}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Sim2RealCfnEnforced",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:DescribeModelPackageGroup",
                "Resource": group_arn,
            }
        ],
    }

    template = {
        "Resources": {
            group_logical_id: {
                "Type": "AWS::SageMaker::ModelPackageGroup",
                "Properties": {
                    "ModelPackageGroupName": group_name,
                    "ModelPackageGroupPolicy": policy,
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            }
        }
    }

    _deploy_cfn(ctx, cf, stack_name, template)

    fetched = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    fetched_policy = json.loads(fetched["ResourcePolicy"])
    assert fetched_policy == policy, f"expected {policy!r}, got {fetched_policy!r}"


def _deploy_cfn(ctx, cf, stack_name: str, template: dict) -> None:
    cf.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_name))
    waiter = cf.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _delete_stack(cf, stack_name: str) -> None:
    cf.delete_stack(StackName=stack_name)
    waiter = cf.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
