"""cfn-sqs-esm-scaling-config-below-minimum-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sqs-esm-scaling-config-below-minimum-rejected"
GROUP = "deploy-esm"
SERVICES = ["cloudformation", "lambda", "sqs"]

_LAMBDA_CODE = "def handler(event, context):\n    return {'processed': len(event.get('Records', []))}\n"

_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _template(max_concurrency: int) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "SourceQueue": {"Type": "AWS::SQS::Queue"},
                "LambdaExecRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": _LAMBDA_TRUST,
                        "Policies": [
                            {
                                "PolicyName": "AllowQueueReadAndLogs",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "sqs:ReceiveMessage",
                                                "sqs:DeleteMessage",
                                                "sqs:GetQueueAttributes",
                                            ],
                                            "Resource": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "logs:CreateLogGroup",
                                                "logs:CreateLogStream",
                                                "logs:PutLogEvents",
                                            ],
                                            "Resource": "*",
                                        },
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Function": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                        "Timeout": 30,
                        "Code": {"ZipFile": _LAMBDA_CODE},
                    },
                },
                "Mapping": {
                    "Type": "AWS::Lambda::EventSourceMapping",
                    "Properties": {
                        "EventSourceArn": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                        "FunctionName": {"Ref": "Function"},
                        "ScalingConfig": {"MaximumConcurrency": max_concurrency},
                    },
                },
            },
            "Outputs": {
                "QueueName": {"Value": {"Fn::GetAtt": ["SourceQueue", "QueueName"]}},
                "FunctionName": {"Value": {"Ref": "Function"}},
                "MappingId": {"Value": {"Ref": "Mapping"}},
            },
        }
    )


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack declaring an EventSourceMapping with ScalingConfig.MaximumConcurrency 1, below the
    minimum of 2, rolls back with the exact constraint violation and creates no mapping, while the
    same template with MaximumConcurrency 2 deploys and round-trips that value.
    """
    lam = ctx.client("lambda")
    cfn = ctx.client("cloudformation")

    bad_stack = ctx.unique_name("sim2real-xsvc-stk-badscale-")
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(1),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, bad_stack))
    stack = _wait_terminal(cfn, bad_stack, timeout_s=600.0)
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"MaximumConcurrency=1 (below the minimum of 2): expected ROLLBACK_COMPLETE, got {stack['StackStatus']!r}"
    )
    reason = _resource_failure_reason(cfn, bad_stack, "Mapping")
    assert reason is not None, "expected the Mapping resource to carry a failure reason"
    prefix, sep, rest = reason.partition("RequestToken: ")
    request_token, sep2, suffix = rest.partition(", HandlerErrorCode: InvalidRequest)")
    assert prefix == (
        'Resource handler returned message: "Model validation failed '
        '(#/ScalingConfig/MaximumConcurrency: failed validation constraint for keyword '
        '[minimum])" ('
    ), f"expected the schema-validation message, got {reason!r}"
    assert sep and sep2 and suffix == "", f"expected the reason to end at HandlerErrorCode, got {reason!r}"
    assert request_token, f"expected a non-blank RequestToken, got {reason!r}"
    function_name = _outputs_from_template_params(cfn, bad_stack)

    # --- effect absent: the rolled-back stack created no function to carry a stray mapping ------
    code, message = _error(lambda: lam.get_function(FunctionName=function_name))
    assert code == "ResourceNotFoundException", (
        f"expected the rolled-back stack's function to not exist, got {code!r}"
    )
    assert message == f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{function_name}", (
        f"unexpected not-found message: {message!r}"
    )

    # --- positive control: the identical template with MaximumConcurrency=2 deploys cleanly ------
    good_stack = ctx.unique_name("sim2real-xsvc-stk-goodscale-")
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(2),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, good_stack))
    stack = _wait_terminal(cfn, good_stack, timeout_s=300.0)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the positive control (MaximumConcurrency=2): expected CREATE_COMPLETE, got {stack['StackStatus']!r}"
    )
    good_mapping_uuid = cfn.describe_stack_resource(StackName=good_stack, LogicalResourceId="Mapping")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    esm = _poll_until(
        lambda: lam.get_event_source_mapping(UUID=good_mapping_uuid),
        lambda m: m["State"] not in {"Creating", "Enabling"},
        timeout_s=180.0,
        description=f"ESM {good_mapping_uuid} to leave Creating/Enabling",
    )
    assert esm["ScalingConfig"]["MaximumConcurrency"] == 2, (
        f"expected the positive control to round-trip MaximumConcurrency=2, got {esm.get('ScalingConfig')!r}"
    )


# ===== helpers =====

def _error(fn):
    """The (Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _outputs_from_template_params(cfn, stack_name: str) -> str:
    """The function name a FAILED stack never produced an Output for; recovered from the
    function's own logical resource, which CloudFormation still tracks for a rolled-back create."""
    try:
        detail = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Function")[
            "StackResourceDetail"
        ]
    except ClientError:
        raise AssertionError(f"stack {stack_name} never attempted the Function resource")
    physical_id = detail.get("PhysicalResourceId")
    assert physical_id, f"expected the Function resource to have been attempted, got {detail!r}"
    return physical_id


def _resource_failure_reason(cfn, stack_name: str, logical_id: str):
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    for e in events:
        if e["LogicalResourceId"] == logical_id and e.get("ResourceStatusReason"):
            return e["ResourceStatusReason"]
    return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0):
    terminal = {
        "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
        "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    }
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        last = stacks[0]
        if last["StackStatus"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _delete_stack_and_wait(cfn, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        if not status.endswith("IN_PROGRESS"):
            break
        time.sleep(interval_s)
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} entered DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
