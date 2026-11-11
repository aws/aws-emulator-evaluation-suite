"""cfn-ssm-association-missing-target-tag-negative."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-association-missing-target-tag-negative"
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
    """An SSM Association whose tag target value matches no instance resolves zero targets and runs
    no command, while a sibling association in the same stack targeting the real tag value
    reaches Success (positive control)."""
    ami_id = _latest_al2_ami(ctx)
    tag_key = "Sim2realAssocTarget"
    real_value = ctx.unique_name("real-")
    bogus_value = ctx.unique_name("bogus-")
    template = json.dumps(_two_association_template(tag_key, real_value, bogus_value, ctx=ctx))
    deployed = _deploy_cfn(ctx, template, parameters={"AmiId": ami_id}, timeout_s=300)
    instance_id = deployed["outputs"]["InstanceId"]
    real_association_id = deployed["outputs"]["RealAssociationId"]
    bogus_association_id = deployed["outputs"]["BogusAssociationId"]

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

    # Positive control: the association targeting the tag value the instance actually has
    # reaches Success.
    real_overview = _poll_until(
        lambda: ssm.describe_association(AssociationId=real_association_id)[
            "AssociationDescription"
        ]["Overview"],
        lambda ov: ov.get("Status") in {"Success", "Failed"},
        timeout_s=600.0,
        interval_s=15.0,
        description="control association execution",
    )
    assert real_overview["Status"] == "Success", (
        f"positive control did not reach Success: {real_overview!r}"
    )

    # Negative: the association targeting a tag value no instance carries resolves ZERO targets
    # and never actually runs the document on anything — regardless of what trivial top-level
    # Status SSM reports for "nothing to do", the resolved target count must be zero and no
    # command invocation must exist for this association.
    bogus_executions = ssm.describe_association_executions(
        AssociationId=bogus_association_id
    ).get("AssociationExecutions", [])
    # The scheduler still logs an execution attempt even when it resolves nothing — if this were
    # ever empty the loop below would assert zero times and the check would pass vacuously.
    assert bogus_executions, (
        "expected at least one association execution attempt for the bogus association, got none"
    )
    for execution in bogus_executions:
        targets = ssm.describe_association_execution_targets(
            AssociationId=bogus_association_id, ExecutionId=execution["ExecutionId"]
        ).get("AssociationExecutionTargets", [])
        assert targets == [], (
            f"bogus association unexpectedly resolved targets: {targets!r}"
        )
    bogus_overview = ssm.describe_association(AssociationId=bogus_association_id)[
        "AssociationDescription"
    ]["Overview"]
    assert bogus_overview.get("Status") != "Failed", (
        f"bogus association should never reach Failed (nothing to run): {bogus_overview!r}"
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


def _two_association_template(tag_key: str, real_value: str, bogus_value: str, *, ctx) -> dict:
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
                        {"Key": tag_key, "Value": real_value},
                    ],
                    "SubnetId": ctx.network().subnet_ids[0],
                },
            },
            "RealAssociation": {
                "Type": "AWS::SSM::Association",
                "Properties": {
                    "Name": "AWS-RunShellScript",
                    "Parameters": {"commands": ["echo hello-from-real-association"]},
                    "Targets": [{"Key": f"tag:{tag_key}", "Values": [real_value]}],
                },
            },
            "BogusAssociation": {
                "Type": "AWS::SSM::Association",
                "Properties": {
                    "Name": "AWS-RunShellScript",
                    "Parameters": {"commands": ["echo should-never-run"]},
                    "Targets": [{"Key": f"tag:{tag_key}", "Values": [bogus_value]}],
                },
            },
        },
        "Outputs": {
            "InstanceId": {"Value": {"Ref": "Instance"}},
            "RealAssociationId": {
                "Value": {"Fn::GetAtt": ["RealAssociation", "AssociationId"]}
            },
            "BogusAssociationId": {
                "Value": {"Fn::GetAtt": ["BogusAssociation", "AssociationId"]}
            },
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
