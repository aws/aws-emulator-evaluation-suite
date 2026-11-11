"""cfn-sqs-esm-create-list-delete-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sqs-esm-create-list-delete-lifecycle"
GROUP = "deploy-esm"
SERVICES = ["cloudformation", "lambda", "sqs"]

_FILTER_PATTERN = json.dumps({"body": {"kind": ["order"]}})


def _template() -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "QueueNameParam": {"Type": "String"},
            "RoleNameParam": {"Type": "String"},
            "FunctionNameParam": {"Type": "String"},
        },
        "Resources": {
            "SourceQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "QueueNameParam"}, "VisibilityTimeout": 30},
            },
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "RoleNameParam"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole",
                    ],
                },
            },
            "ConsumerFn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": {"Ref": "FunctionNameParam"},
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": (
                        "def handler(event, context):\n"
                        "    return {'processed': len(event.get('Records', []))}\n"
                    )},
                },
            },
            "Esm": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {
                    "EventSourceArn": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                    "FunctionName": {"Ref": "ConsumerFn"},
                    "BatchSize": 5,
                    "Enabled": True,
                    "MaximumBatchingWindowInSeconds": 5,
                    "FilterCriteria": {"Filters": [{"Pattern": _FILTER_PATTERN}]},
                    "ScalingConfig": {"MaximumConcurrency": 5},
                },
            },
        },
        "Outputs": {
            "SourceQueueArn": {"Value": {"Fn::GetAtt": ["SourceQueue", "Arn"]}},
            "FunctionArn": {"Value": {"Fn::GetAtt": ["ConsumerFn", "Arn"]}},
            "EventSourceMappingId": {"Value": {"Ref": "Esm"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:eventing",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-created SQS EventSourceMapping carries the declared properties, is listed by Lambda's
    own ListEventSourceMappings, and is actually removed, not orphaned, when the stack is deleted.
    """
    lam = ctx.client("lambda")

    names = {
        "QueueNameParam": _xname(ctx, "esm-src"),
        "RoleNameParam": _xname(ctx, "esm-role"),
        "FunctionNameParam": _xname(ctx, "esm-fn"),
    }
    result = _deploy_cfn(ctx, _template(), parameters=names)
    stack_name = result["stack_name"]
    esm_uuid = result["outputs"]["EventSourceMappingId"]
    function_name = names["FunctionNameParam"]
    queue_arn = result["outputs"]["SourceQueueArn"]
    function_arn = result["outputs"]["FunctionArn"]

    # The declared properties actually took effect.
    mapping = lam.get_event_source_mapping(UUID=esm_uuid)
    assert mapping["MaximumBatchingWindowInSeconds"] == 5, (
        f"expected MaximumBatchingWindowInSeconds=5, got {mapping.get('MaximumBatchingWindowInSeconds')!r}"
    )
    filters = mapping["FilterCriteria"]["Filters"]
    assert [f["Pattern"] for f in filters] == [_FILTER_PATTERN], (
        f"expected FilterCriteria pattern {_FILTER_PATTERN!r}, got {filters!r}"
    )
    assert mapping["ScalingConfig"]["MaximumConcurrency"] == 5, (
        f"expected ScalingConfig.MaximumConcurrency=5, got {mapping.get('ScalingConfig')!r}"
    )

    # The CFN-created mapping is visible through Lambda's own list.
    found = False
    paginator = lam.get_paginator("list_event_source_mappings")
    for page in paginator.paginate(FunctionName=function_name):
        for m in page["EventSourceMappings"]:
            if m["UUID"] == esm_uuid:
                found = True
                assert m["FunctionArn"] == function_arn, (
                    f"listed mapping's FunctionArn {m['FunctionArn']!r} != {function_arn!r}"
                )
                assert m["EventSourceArn"] == queue_arn, (
                    f"listed mapping's EventSourceArn {m['EventSourceArn']!r} != {queue_arn!r}"
                )
    assert found, f"ESM {esm_uuid!r} created by stack {stack_name!r} not found in ListEventSourceMappings"

    # Deleting the stack deletes the mapping, not merely the stack.
    _delete_stack_and_wait(ctx, stack_name)
    try:
        lam.get_event_source_mapping(UUID=esm_uuid)
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
        want = ("ResourceNotFoundException", "The resource you requested does not exist.")
        assert got == want, (
            f"expected {want!r} for the ESM after stack delete, got {got!r}"
        )
    else:
        raise AssertionError(
            f"ESM {esm_uuid!r} must be gone after the owning stack was deleted, but it still resolves"
        )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}, {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as err:
            if "does not exist" in str(err):
                return "GONE"
            raise

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template: str, *, parameters: dict[str, str], timeout_s: float = 300.0) -> dict[str, Any]:
    cfn = ctx.client("cloudformation")
    name = _xname(ctx, "stk")
    stack_id = cfn.create_stack(
        StackName=name,
        TemplateBody=template,
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
