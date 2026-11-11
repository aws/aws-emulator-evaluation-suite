"""cfn-ssm-parameter-referenced-in-ec2-userdata-positive."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-parameter-referenced-in-ec2-userdata-positive"
GROUP = "arn-resolution"
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
    """A template parameter of type AWS::SSM::Parameter::Value<String> resolves the parameter's
    current value at deploy time into the EC2 instance's UserData: the file the instance writes at
    boot, read back with a successful SSM Run Command, holds exactly that value."""
    ssm = ctx.client("ssm")
    ami_id = _latest_al2_ami(ctx)
    param_name = _xname(ctx, "marker-param")
    marker_value = ctx.unique_name("marker-value-")
    ssm.put_parameter(
        Name=param_name, Value=marker_value, Type="String", Tags=_xsvc_tags_kv()
    )
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))

    template = json.dumps(_userdata_template(ctx))
    deployed = _deploy_cfn(
        ctx,
        template,
        parameters={"AmiId": ami_id, "MarkerParam": param_name},
        timeout_s=600,
    )
    instance_id = deployed["outputs"]["InstanceId"]

    _poll_until(
        lambda: ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"],
        lambda lst: len(lst) == 1 and lst[0]["PingStatus"] == "Online",
        timeout_s=420.0,
        interval_s=15.0,
        description="SSM managed-instance registration",
    )

    def _run_cat_marker():
        send = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": ["cat /tmp/sim2real-marker.txt"]},
        )
        command_id = send["Command"]["CommandId"]

        def _get_invocation():
            try:
                return ssm.get_command_invocation(
                    CommandId=command_id, InstanceId=instance_id
                )
            except ClientError as e:
                if e.response["Error"]["Code"] == "InvocationDoesNotExist":
                    return {"Status": "Pending"}
                raise

        return _poll_until(
            _get_invocation,
            lambda inv: inv["Status"] in {"Success", "Failed", "Cancelled", "TimedOut"},
            timeout_s=120.0,
            interval_s=5.0,
            description="run-command completion",
        )

    # SSM agent registration (PingStatus=Online) races cloud-init's UserData execution: the
    # agent commonly comes up before the boot script has finished writing the marker file, so
    # the first read can legitimately return "Failed" (no such file) on a correct target. Retry
    # with fresh commands, bounded, rather than trusting the first attempt.
    invocation = _poll_until(
        _run_cat_marker,
        lambda inv: inv["Status"] == "Success",
        timeout_s=180.0,
        interval_s=10.0,
        description="UserData marker file written and readable via SSM Run Command",
    )
    assert invocation["Status"] == "Success", (
        f"expected the final run-command attempt to succeed, got status="
        f"{invocation['Status']!r} stderr={invocation.get('StandardErrorContent', '')!r}"
    )
    # The value written into UserData at boot is exactly what CFN resolved from SSM Parameter
    # Store at deploy time.
    actual = invocation["StandardOutputContent"].strip()
    assert actual == marker_value, (
        f"expected the marker file to contain the SSM parameter value {marker_value!r} "
        f"resolved by CFN at deploy time, got {actual!r}"
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


def _userdata_template(ctx) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "AmiId": {"Type": "String"},
            "MarkerParam": {
                "Type": "AWS::SSM::Parameter::Value<String>",
            },
        },
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
                    "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
                    "UserData": {
                        "Fn::Base64": {
                            "Fn::Sub": (
                                "#!/bin/bash\n"
                                "echo '${MarkerParam}' > /tmp/sim2real-marker.txt\n"
                            )
                        }
                    },
                    "SubnetId": ctx.network().subnet_ids[0],
                },
            },
        },
        "Outputs": {"InstanceId": {"Value": {"Ref": "Instance"}}},
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
