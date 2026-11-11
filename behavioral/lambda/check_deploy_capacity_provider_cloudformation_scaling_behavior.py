"""deploy-capacity-provider-cloudformation-scaling-behavior."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-capacity-provider-cloudformation-scaling-behavior"
GROUP = "deploy"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A stack with an AWS::Lambda::CapacityProvider and a Managed-Instances function reaches
    CREATE_COMPLETE, the provider is queryable and Active, its published version is listed Active by
    ListFunctionVersionsByCapacityProvider, and the provider is gone after stack deletion."""
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    stack_name = ctx.unique_name("sim2real-lambda-cfn-cp-")
    cp_name = ctx.unique_name("sim2real-lambda-cfn-cp-name-")

    handler_src = "def handler(event, context):\n    return {'ok': True}\n"
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {"CidrBlock": "10.91.0.0/16", "Tags": _managed_tags()},
            },
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.91.1.0/24",
                    "Tags": _managed_tags(),
                },
            },
            "Sg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real lambda managed instances cfn test",
                    "VpcId": {"Ref": "Vpc"},
                    "Tags": _managed_tags(),
                },
            },
            "OperatorRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": _lambda_trust_doc(),
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator"
                    ],
                    "Tags": _managed_tags(),
                },
            },
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": _lambda_trust_doc(),
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                    "Tags": _managed_tags(),
                },
            },
            "CapacityProvider": {
                "Type": "AWS::Lambda::CapacityProvider",
                "Properties": {
                    "CapacityProviderName": cp_name,
                    "VpcConfig": {
                        "SubnetIds": [{"Ref": "Subnet"}],
                        "SecurityGroupIds": [{"Ref": "Sg"}],
                    },
                    "PermissionsConfig": {
                        "CapacityProviderOperatorRoleArn": {"Fn::GetAtt": ["OperatorRole", "Arn"]}
                    },
                    "InstanceRequirements": {"Architectures": ["x86_64"]},
                    # 2 vCPUs passes request validation but the service rejects it as below
                    # its recommended minimum; 16 is accepted.
                    "CapacityProviderScalingConfig": {"MaxVCpuCount": 16},
                    "Tags": _managed_tags(),
                },
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.13",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "MemorySize": 2048,
                    "Timeout": 30,
                    "Code": {"ZipFile": handler_src},
                    "Architectures": ["x86_64"],
                    "CapacityProviderConfig": {
                        "LambdaManagedInstancesCapacityProviderConfig": {
                            "CapacityProviderArn": {"Fn::GetAtt": ["CapacityProvider", "Arn"]}
                        }
                    },
                },
            },
        },
        "Outputs": {
            "FunctionName": {"Value": {"Ref": "Fn"}},
            "CapacityProviderArn": {"Value": {"Fn::GetAtt": ["CapacityProvider", "Arn"]}},
        },
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name, timeout_s=900.0))

    stack = _wait_for_stack_status(
        ctx, stack_name, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}, timeout_s=900.0
    )
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack ended in {stack['StackStatus']} ({stack.get('StackStatusReason')}); "
        f"failed resources: {_failed_resource_reasons(cfn, stack_name)}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    function_name = outputs["FunctionName"]
    cp_arn = outputs["CapacityProviderArn"]

    # Queryable immediately after CREATE_COMPLETE, not just a green stack event.
    cp = lam.get_capacity_provider(CapacityProviderName=cp_name)["CapacityProvider"]
    assert cp["CapacityProviderArn"] == cp_arn, (
        f"expected {cp_arn!r}, got {cp['CapacityProviderArn']!r}"
    )
    settled = _poll_until(
        lambda: lam.get_capacity_provider(CapacityProviderName=cp_name)["CapacityProvider"],
        lambda c: c["State"] not in ("Pending", "Updating"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert settled["State"] == "Active", f"capacity provider settled in {settled['State']!r}"

    lam.publish_version(FunctionName=function_name)

    def _versions():
        return lam.list_function_versions_by_capacity_provider(CapacityProviderName=cp_name)[
            "FunctionVersions"
        ]

    versions = _poll_until(
        _versions,
        lambda vs: any(v["FunctionArn"].endswith(":1") and v["State"] != "Pending" for v in vs),
        timeout_s=600.0,
        interval_s=15.0,
    )
    matching = [v for v in versions if v["FunctionArn"].endswith(":1")]
    assert len(matching) == 1, versions
    assert matching[0]["State"] == "Active", matching[0]

    # The stack (and the capacity provider it owns) is torn down here, on the check's own
    # budget, rather than left entirely to the best-effort ctx.on_cleanup safety net below --
    # so a stack that never actually deletes is a check failure, not a silent leak.
    cfn.delete_stack(StackName=stack_name)
    _wait_for_stack_deleted(ctx, stack_name, timeout_s=900.0, interval_s=10.0)

    deleted_code, deleted_msg = _client_error(
        lambda: lam.get_capacity_provider(CapacityProviderName=cp_name)
    )
    assert deleted_code == "ResourceNotFoundException", (
        f"capacity provider still resolves after stack deletion: {deleted_code!r}"
    )
    assert deleted_msg == (
        f"Capacity provider not found: {cp_arn}. Check that the ARN is correct and the "
        "capacity provider exists in this Region."
    ), f"unexpected GetCapacityProvider message: {deleted_msg!r}"



def _lambda_trust_doc():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _managed_tags():
    return [{"Key": "sim2real:managed", "Value": "true"}]


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected a ClientError but the call succeeded")


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _failed_resource_reasons(cfn, stack_name):
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    except Exception as exc:  # noqa: BLE001 - this is diagnostic detail, not the assertion itself
        return f"<could not fetch stack events: {exc}>"
    return [
        f"{e['LogicalResourceId']} {e['ResourceStatus']}: {e.get('ResourceStatusReason')}"
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]


def _wait_for_stack_status(ctx, stack_name, terminal_statuses, timeout_s=300.0, interval_s=10.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        if last["StackStatus"] in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached a terminal status; last={last!r}")


def _wait_for_stack_deleted(ctx, stack_name, timeout_s=900.0, interval_s=10.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except Exception:
            return  # no longer describable at all -- fully gone
        if not stacks:
            return
        last_status = stacks[0]["StackStatus"]
        if last_status == "DELETE_COMPLETE":
            return
        if last_status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} entered DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not reach DELETE_COMPLETE within {timeout_s}s; last status={last_status!r}"
    )


def _delete_stack_and_wait(ctx, stack_name, timeout_s=900.0, interval_s=10.0):
    """Best-effort safety net for ctx.on_cleanup: the check body already deletes and verifies
    the stack on its own budget, so this only fires when an earlier assertion raised first."""
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise
        return
    try:
        _wait_for_stack_deleted(ctx, stack_name, timeout_s=timeout_s, interval_s=interval_s)
    except AssertionError:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
