"""cfn-change-set-preview-ec2-ssm-association-update-positive."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-change-set-preview-ec2-ssm-association-update-positive"
GROUP = "deployment-order"
SERVICES = ["cloudformation", "ec2", "ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A change set for an SSM association's Targets update (one EC2 fleet group to another) lists
    exactly one Modify on the association; after execution the live association carries the new
    Targets and its executions resolve targets."""

    def _template(target_group: str) -> str:
        return json.dumps(
            {
                "Parameters": {
                    "ImageId": {
                        "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                        "Default": _AMI_PARAM,
                    }
                },
                "Resources": {
                    "InstanceRole": {
                        "Type": "AWS::IAM::Role",
                        "Properties": {
                            "AssumeRolePolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Principal": {"Service": "ec2.amazonaws.com"},
                                        "Action": "sts:AssumeRole",
                                    }
                                ],
                            },
                            "ManagedPolicyArns": [
                                "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
                            ],
                        },
                    },
                    "InstanceProfile": {
                        "Type": "AWS::IAM::InstanceProfile",
                        "Properties": {"Roles": [{"Ref": "InstanceRole"}]},
                    },
                    "Instance1": {
                        "Type": "AWS::EC2::Instance",
                        "Properties": {
                            "ImageId": {"Ref": "ImageId"},
                            "InstanceType": "t3.micro",
                            "IamInstanceProfile": {"Ref": "InstanceProfile"},
                            "Tags": _xsvc_tags_kv()
                            + [{"Key": "Group", "Value": "fleet-v1"}],
                            "SubnetId": ctx.network().subnet_ids[0],
                        },
                    },
                    "Instance2": {
                        "Type": "AWS::EC2::Instance",
                        "Properties": {
                            "ImageId": {"Ref": "ImageId"},
                            "InstanceType": "t3.micro",
                            "IamInstanceProfile": {"Ref": "InstanceProfile"},
                            "Tags": _xsvc_tags_kv()
                            + [{"Key": "Group", "Value": "fleet-v2"}],
                            "SubnetId": ctx.network().subnet_ids[0],
                        },
                    },
                    "FleetAssoc": {
                        "Type": "AWS::SSM::Association",
                        "Properties": {
                            "Name": "AWS-RunShellScript",
                            "Targets": [{"Key": "tag:Group", "Values": [target_group]}],
                            "Parameters": {"commands": ["echo sim2real"]},
                        },
                    },
                },
                "Outputs": {
                    "AssociationId": {"Value": {"Ref": "FleetAssoc"}},
                    "Instance1Id": {"Value": {"Ref": "Instance1"}},
                    "Instance2Id": {"Value": {"Ref": "Instance2"}},
                },
            }
        )

    stack = _deploy_cfn(ctx, _template("fleet-v1"), timeout_s=240)
    stack_name = stack["stack_name"]
    association_id = stack["outputs"]["AssociationId"]
    instance1_id = stack["outputs"]["Instance1Id"]
    instance2_id = stack["outputs"]["Instance2Id"]

    ssm = ctx.client("ssm")
    cfn = ctx.client("cloudformation")

    def _ping_status(instance_id: str) -> str:
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp["InstanceInformationList"]
        return infos[0]["PingStatus"] if infos else "NOT_REGISTERED"

    for instance_id in (instance1_id, instance2_id):
        _poll_until(
            lambda iid=instance_id: _ping_status(iid),
            lambda s: s == "Online",
            timeout_s=360.0,
            interval_s=10.0,
            description=f"SSM Agent registers {instance_id} as Online",
        )

    def _executions() -> list[dict[str, Any]]:
        return ssm.describe_association_executions(AssociationId=association_id)[
            "AssociationExecutions"
        ]

    initial_execs = _poll_until(
        _executions,
        lambda e: len(e) >= 1 and e[0]["ResourceCountByStatus"] != "{}",
        timeout_s=180.0,
        interval_s=5.0,
        description="initial association execution resolves at least one target",
    )
    assert initial_execs[0]["ResourceCountByStatus"] != "{}", (
        "initial association (targeting fleet-v1) unexpectedly matched zero instances"
    )
    initial_count = len(initial_execs)

    change_set_name = ctx.unique_name("sim2real-xsvc-cs-")
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=_template("fleet-v2"),
        ChangeSetType="UPDATE",
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    cs_status = _poll_until(
        lambda: cfn.describe_change_set(
            StackName=stack_name, ChangeSetName=change_set_name
        )["Status"],
        lambda s: s in {"CREATE_COMPLETE", "FAILED"},
        timeout_s=120.0,
        interval_s=5.0,
        description="change set reaches CREATE_COMPLETE",
    )
    assert cs_status == "CREATE_COMPLETE", (
        f"expected change set to reach CREATE_COMPLETE, got {cs_status}"
    )

    change_set = cfn.describe_change_set(
        StackName=stack_name, ChangeSetName=change_set_name
    )
    assoc_changes = [
        c["ResourceChange"]
        for c in change_set["Changes"]
        if c["ResourceChange"]["LogicalResourceId"] == "FleetAssoc"
    ]
    assert len(assoc_changes) == 1, (
        f"expected exactly one ResourceChange for FleetAssoc, got {len(assoc_changes)}: {assoc_changes!r}"
    )
    assert assoc_changes[0]["Action"] == "Modify", (
        f"expected change set to preview a Modify on FleetAssoc, got {assoc_changes[0]['Action']!r}"
    )

    cfn.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED"},
        timeout_s=180.0,
        interval_s=5.0,
        description="change set execution reaches a terminal stack status",
    )
    final_status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert final_status == "UPDATE_COMPLETE", f"stack update ended in {final_status}"

    live_association = ssm.describe_association(AssociationId=association_id)[
        "AssociationDescription"
    ]
    assert live_association["Targets"] == [
        {"Key": "tag:Group", "Values": ["fleet-v2"]}
    ], (
        f"expected the live association's Targets to have retargeted to fleet-v2, "
        f"got {live_association['Targets']!r}"
    )

    new_execs = _poll_until(
        _executions,
        lambda e: len(e) > initial_count and e[0]["ResourceCountByStatus"] != "{}",
        timeout_s=180.0,
        interval_s=5.0,
        description="a fresh association execution is recorded and resolves a target after the retarget",
    )
    assert new_execs[0]["ResourceCountByStatus"] != "{}", (
        "retargeted association (now targeting fleet-v2) unexpectedly matched zero instances"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
