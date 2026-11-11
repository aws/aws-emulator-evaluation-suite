"""cfn-deploy-ssm-patch-baseline-associated-ec2-positive."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-ssm-patch-baseline-associated-ec2-positive"
GROUP = "event-propagation"
SERVICES = ["cloudformation", "ec2", "ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CFN-deployed SSM patch baseline (registered to a Patch Group) associated to a real,
    SSM-managed EC2 instance triggers AWS-RunPatchBaseline and produces patch compliance data."""
    patch_group = ctx.unique_name("sim2real-patchgrp-")
    template = json.dumps(
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
                "Instance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Ref": "ImageId"},
                        "InstanceType": "t3.micro",
                        "IamInstanceProfile": {"Ref": "InstanceProfile"},
                        "Tags": _xsvc_tags_kv()
                        + [{"Key": "Patch Group", "Value": patch_group}],
                        "SubnetId": ctx.network().subnet_ids[0],
                    },
                },
                "PatchBaseline": {
                    "Type": "AWS::SSM::PatchBaseline",
                    "Properties": {
                        "Name": ctx.unique_name("sim2real-xsvc-pb-"),
                        "OperatingSystem": "AMAZON_LINUX_2023",
                        "ApprovalRules": {
                            "PatchRules": [
                                {
                                    "PatchFilterGroup": {
                                        "PatchFilters": [
                                            {
                                                "Key": "CLASSIFICATION",
                                                "Values": ["Security", "Bugfix"],
                                            }
                                        ]
                                    },
                                    "ApproveAfterDays": 0,
                                    "ComplianceLevel": "CRITICAL",
                                }
                            ]
                        },
                        "PatchGroups": [patch_group],
                    },
                },
                "Association": {
                    "Type": "AWS::SSM::Association",
                    "Properties": {
                        "Name": "AWS-RunPatchBaseline",
                        "Targets": [
                            {"Key": "tag:Patch Group", "Values": [patch_group]}
                        ],
                        "Parameters": {"Operation": ["Scan"]},
                    },
                },
            },
            "Outputs": {
                "InstanceId": {"Value": {"Ref": "Instance"}},
                "AssociationId": {"Value": {"Ref": "Association"}},
                "PatchBaselineId": {"Value": {"Ref": "PatchBaseline"}},
            },
        }
    )

    stack = _deploy_cfn(ctx, template, timeout_s=300)
    instance_id = stack["outputs"]["InstanceId"]
    association_id = stack["outputs"]["AssociationId"]
    patch_baseline_id = stack["outputs"]["PatchBaselineId"]

    ssm = ctx.client("ssm")

    def _ping_status() -> str:
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp["InstanceInformationList"]
        return infos[0]["PingStatus"] if infos else "NOT_REGISTERED"

    _poll_until(
        _ping_status,
        lambda s: s == "Online",
        timeout_s=360.0,
        interval_s=10.0,
        description="SSM Agent registers instance as Online",
    )

    ssm.start_associations_once(AssociationIds=[association_id])

    def _patch_state() -> dict[str, Any] | None:
        states = ssm.describe_instance_patch_states(InstanceIds=[instance_id])[
            "InstancePatchStates"
        ]
        return states[0] if states else None

    state = _poll_until(
        _patch_state,
        lambda s: s is not None,
        timeout_s=300.0,
        interval_s=10.0,
        description="AWS-RunPatchBaseline scan reports instance patch state",
    )
    # An independent read (DescribeInstancePatchStates, not the StartAssociationsOnce that triggered
    # it) must trace back to the exact CFN-created baseline and patch group — not merely to some
    # baseline — and to the exact operation the Association requested. BaselineId forms differ
    # between CFN's Ref and this read (short id vs qualified id), so compare on the trailing id
    # component.
    assert state["BaselineId"].endswith(patch_baseline_id.rsplit("/", 1)[-1]), (
        f"expected instance patch state bound to this stack's PatchBaseline "
        f"{patch_baseline_id!r}, got {state['BaselineId']!r}"
    )
    assert state["PatchGroup"] == patch_group, (
        f"expected instance patch state for patch group {patch_group!r}, "
        f"got {state['PatchGroup']!r}"
    )
    assert state["Operation"] == "Scan", (
        f"expected the AWS-RunPatchBaseline Scan operation (per the Association's "
        f"Parameters), got {state['Operation']!r}"
    )

    def _compliance_items() -> list[dict[str, Any]]:
        return ssm.list_compliance_items(
            ResourceIds=[instance_id],
            ResourceTypes=["ManagedInstance"],
            Filters=[{"Key": "ComplianceType", "Values": ["Patch"]}],
        )["ComplianceItems"]

    # The poll itself is the assertion here: ListComplianceItems is a distinct API surface
    # from DescribeInstancePatchStates above, and a target that fakes the latter without
    # actually wiring the compliance pipeline times out (raises) instead of scoring green.
    _poll_until(
        _compliance_items,
        lambda items: len(items) > 0,
        timeout_s=300.0,
        interval_s=10.0,
        description="patch compliance items reported for the instance",
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
