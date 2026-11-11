"""cfn-ssm-document-wrong-instance-tag-key-negative."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-document-wrong-instance-tag-key-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "ec2", "ssm"]


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An SSM Association targeting a tag KEY no instance carries resolves zero targets and never
    runs the document, while a sibling association in the same stack targeting the instance's real
    tag key executes on it (positive control)."""
    ami_id = _latest_al2_ami(ctx)
    real_key = "Sim2realRealKey"
    wrong_key = "Sim2realNoSuchKey"
    tag_value = ctx.unique_name("wrongkey-")
    template = json.dumps(_template(real_key, wrong_key, tag_value, ctx=ctx))
    deployed = _deploy_cfn(ctx, template, parameters={"AmiId": ami_id}, timeout_s=300)
    instance_id = deployed["outputs"]["InstanceId"]
    real_association_id = deployed["outputs"]["RealAssociationId"]
    wrong_key_association_id = deployed["outputs"]["WrongKeyAssociationId"]

    ssm = ctx.client("ssm")
    _poll_until(
        lambda: ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"],
        lambda lst: len(lst) == 1 and lst[0]["PingStatus"] == "Online",
        timeout_s=420.0,
        interval_s=15.0,
        description="SSM managed-instance registration",
    )

    # Positive control: the association keyed on the tag the instance actually has succeeds.
    real_overview = _poll_until(
        lambda: ssm.describe_association(AssociationId=real_association_id)[
            "AssociationDescription"
        ]["Overview"],
        lambda ov: ov.get("Status") in {"Success", "Failed"},
        timeout_s=600.0,
        interval_s=15.0,
        description="control association execution",
    )
    assert real_overview["Status"] == "Success"
    # Overview.Status == "Success" is NOT sufficient on its own: AWS reports the same "Success" for
    # the wrong-key association below, which resolves zero targets, so the positive control must
    # independently prove target resolution.
    real_executions = ssm.describe_association_executions(
        AssociationId=real_association_id
    ).get("AssociationExecutions", [])
    assert real_executions, "positive control association reports no executions at all"
    real_targets = ssm.describe_association_execution_targets(
        AssociationId=real_association_id,
        ExecutionId=real_executions[-1]["ExecutionId"],
    ).get("AssociationExecutionTargets", [])
    resolved_ids = {t.get("ResourceId") for t in real_targets}
    assert instance_id in resolved_ids, (
        f"positive control association never resolved the instance as an execution target: "
        f"targets={real_targets!r}"
    )

    # Negative: the association keyed on a tag KEY the instance doesn't have at all resolves
    # ZERO targets and never actually runs the document on anything, regardless of the trivial
    # top-level Status SSM reports for "nothing to do".
    wrong_key_executions = ssm.describe_association_executions(
        AssociationId=wrong_key_association_id
    ).get("AssociationExecutions", [])
    for execution in wrong_key_executions:
        targets = ssm.describe_association_execution_targets(
            AssociationId=wrong_key_association_id, ExecutionId=execution["ExecutionId"]
        ).get("AssociationExecutionTargets", [])
        assert targets == [], (
            f"wrong-key association unexpectedly resolved targets: {targets!r}"
        )
    wrong_key_overview = ssm.describe_association(
        AssociationId=wrong_key_association_id
    )["AssociationDescription"]["Overview"]
    assert wrong_key_overview.get("Status") != "Failed"

    # And the resolution mechanism itself confirms zero matches for the wrong key.
    resolved = ssm.describe_instance_information(
        Filters=[{"Key": f"tag:{wrong_key}", "Values": [tag_value]}]
    )["InstanceInformationList"]
    assert resolved == []


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


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
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
        timeout_s=180,
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
    timeout_s=600.0,
):
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    kwargs = {
        "StackName": name,
        "TemplateBody": template,
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


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _template(real_key: str, wrong_key: str, tag_value: str, *, ctx) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"AmiId": {"Type": "String"}},
        "Resources": {
            "SsmRole": {
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
            "SsmInstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {"Roles": [{"Ref": "SsmRole"}]},
            },
            "Instance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": {"Ref": "AmiId"},
                    "InstanceType": "t3.micro",
                    "IamInstanceProfile": {"Ref": "SsmInstanceProfile"},
                    "Tags": [
                        {"Key": "sim2real:managed", "Value": "true"},
                        {"Key": real_key, "Value": tag_value},
                    ],
                    "SubnetId": ctx.network().subnet_ids[0],
                },
            },
            "RealAssociation": {
                "Type": "AWS::SSM::Association",
                "Properties": {
                    "Name": "AWS-RunShellScript",
                    "Parameters": {
                        "commands": ["echo hello-from-real-key-association"]
                    },
                    "Targets": [{"Key": f"tag:{real_key}", "Values": [tag_value]}],
                },
            },
            "WrongKeyAssociation": {
                "Type": "AWS::SSM::Association",
                "Properties": {
                    "Name": "AWS-RunShellScript",
                    "Parameters": {"commands": ["echo should-never-run"]},
                    "Targets": [{"Key": f"tag:{wrong_key}", "Values": [tag_value]}],
                },
            },
        },
        "Outputs": {
            "InstanceId": {"Value": {"Ref": "Instance"}},
            "RealAssociationId": {
                "Value": {"Fn::GetAtt": ["RealAssociation", "AssociationId"]}
            },
            "WrongKeyAssociationId": {
                "Value": {"Fn::GetAtt": ["WrongKeyAssociation", "AssociationId"]}
            },
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
