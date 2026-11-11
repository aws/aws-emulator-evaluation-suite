"""cfn-deploy-ssm-document-association-ec2-positive."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-ssm-document-association-ec2-positive"
GROUP = "event-propagation"
SERVICES = ["cloudformation", "ec2", "ssm"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CFN-deployed AWS::SSM::Association targeting EC2 by tag runs AWS-RunShellScript on the
    tagged instance and reaches Success, confirmed via the command's own invocation record."""
    ami_id = _latest_al2_ami(ctx)
    tag_key = "Sim2realAssocTarget"
    tag_value = ctx.unique_name("assoc-")
    template = json.dumps(_association_template(tag_key, tag_value, ctx=ctx))
    deployed = _deploy_cfn(ctx, template, parameters={"AmiId": ami_id}, timeout_s=300)
    instance_id = deployed["outputs"]["InstanceId"]
    association_id = deployed["outputs"]["AssociationId"]

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

    overview = _poll_until(
        lambda: ssm.describe_association(AssociationId=association_id)[
            "AssociationDescription"
        ]["Overview"],
        lambda ov: ov.get("Status") in {"Success", "Failed"},
        timeout_s=600.0,
        interval_s=15.0,
        description="association execution",
    )
    assert overview["Status"] == "Success", (
        f"association {association_id} overview reached {overview!r}, not Success"
    )

    # Overview.Status alone is SSM's own aggregate judgement and does not by itself prove the
    # document actually ran on the instance. Follow the execution to the command it dispatched
    # and read that command's own invocation record — an independent read, through a third
    # operation, of the real side effect on the target host.
    executions = ssm.describe_association_executions(AssociationId=association_id)[
        "AssociationExecutions"
    ]
    assert executions, f"association {association_id} has no recorded executions"
    targets = _poll_until(
        lambda: ssm.describe_association_execution_targets(
            AssociationId=association_id, ExecutionId=executions[0]["ExecutionId"]
        )["AssociationExecutionTargets"],
        lambda ts: len(ts) >= 1,
        timeout_s=60.0,
        interval_s=5.0,
        description="association execution resolves its target",
    )
    assert [t["ResourceId"] for t in targets] == [instance_id], (
        f"association {association_id} resolved targets {targets!r}, expected only {instance_id!r}"
    )

    # AssociationExecutionTarget's OutputSource holds an S3 output location, not a command id
    # (OutputSourceId is absent without an S3 output bucket), so find the dispatched command by
    # listing this instance's invocations; the instance exists only for this check.
    def _invocations():
        found = []
        for page in ssm.get_paginator("list_command_invocations").paginate(
            InstanceId=instance_id, Details=True
        ):
            found += page["CommandInvocations"]
        return found

    # ListCommandInvocations is eventually consistent with the association's Success overview;
    # the dispatched command can be listed a little after it.
    invocations = _poll_until(
        _invocations,
        lambda found: len(found) >= 1,
        timeout_s=300.0,
        interval_s=10.0,
        description="association's command invocation listed",
    )
    assert len(invocations) == 1, (
        f"expected exactly one command invocation on {instance_id!r}, got {invocations!r}"
    )
    assert invocations[0]["DocumentName"] == "AWS-RunShellScript", invocations[0]
    command_id = invocations[0]["CommandId"]

    invocation = ssm.get_command_invocation(
        CommandId=command_id, InstanceId=instance_id
    )
    assert invocation["Status"] == "Success", (
        f"command invocation {command_id} on {instance_id} was {invocation['Status']!r}: "
        f"{invocation.get('StandardErrorContent')!r}"
    )
    assert invocation["ResponseCode"] == 0, (
        f"command invocation {command_id} ResponseCode was {invocation['ResponseCode']!r}"
    )
    assert invocation["StandardOutputContent"].strip() == "hello-from-association", (
        f"expected the instance to have actually run the association's script and printed "
        f"'hello-from-association'; stdout was {invocation['StandardOutputContent']!r}"
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


def _association_template(tag_key: str, tag_value: str, *, ctx) -> dict:
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
                        {"Key": tag_key, "Value": tag_value},
                    ],
                    "SubnetId": ctx.network().subnet_ids[0],
                },
            },
            "Association": {
                "Type": "AWS::SSM::Association",
                "Properties": {
                    "Name": "AWS-RunShellScript",
                    "Parameters": {"commands": ["echo hello-from-association"]},
                    "Targets": [{"Key": f"tag:{tag_key}", "Values": [tag_value]}],
                },
            },
        },
        "Outputs": {
            "InstanceId": {"Value": {"Ref": "Instance"}},
            "AssociationId": {
                "Value": {"Fn::GetAtt": ["Association", "AssociationId"]}
            },
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
