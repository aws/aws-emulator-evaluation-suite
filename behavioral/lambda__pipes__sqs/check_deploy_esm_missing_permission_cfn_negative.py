"""deploy-esm-missing-permission-cfn-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-esm-missing-permission-cfn-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "pipes", "sqs"]

_LAMBDA_CODE = (
    "import json, os, boto3\n"
    "sqs = boto3.client('sqs')\n"
    "def handler(event, context):\n"
    "    queue_url = os.environ['RESULT_QUEUE_URL']\n"
    "    for rec in event.get('Records', []):\n"
    "        sqs.send_message(QueueUrl=queue_url, MessageBody=rec.get('body', ''))\n"
    "    return {'processed': len(event.get('Records', []))}\n"
)

_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _build_good_template() -> str:
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SourceQueueGood": {"Type": "AWS::SQS::Queue"},
            "ResultQueueGood": {"Type": "AWS::SQS::Queue"},
            "LambdaExecRoleGood": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": _LAMBDA_TRUST,
                    "Policies": [
                        {
                            "PolicyName": "AllowPollAndSend",
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
                                        "Resource": {"Fn::GetAtt": ["SourceQueueGood", "Arn"]},
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": "sqs:SendMessage",
                                        "Resource": {"Fn::GetAtt": ["ResultQueueGood", "Arn"]},
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                                        "Resource": "*",
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "ForwarderFunctionGood": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaExecRoleGood", "Arn"]},
                    "Timeout": 30,
                    "Environment": {"Variables": {"RESULT_QUEUE_URL": {"Ref": "ResultQueueGood"}}},
                    "Code": {"ZipFile": _LAMBDA_CODE},
                },
            },
            "MappingGood": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {
                    "EventSourceArn": {"Fn::GetAtt": ["SourceQueueGood", "Arn"]},
                    "FunctionName": {"Ref": "ForwarderFunctionGood"},
                    "BatchSize": 1,
                    "Enabled": True,
                },
            },
        },
        "Outputs": {
            "SourceQueueGoodUrl": {"Value": {"Ref": "SourceQueueGood"}},
            "ResultQueueGoodUrl": {"Value": {"Ref": "ResultQueueGood"}},
        },
    }
    return json.dumps(template)


def _build_bad_template() -> str:
    # Deliberately lacks sqs:ReceiveMessage/DeleteMessage/GetQueueAttributes on the
    # source queue — only logging and send-to-result permissions are granted. AWS Lambda's
    # CreateEventSourceMapping validates that the execution role can poll the source queue
    # *synchronously*, so this is expected to fail stack creation outright rather than
    # silently reach State=Enabled with no invocations.
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SourceQueueBad": {"Type": "AWS::SQS::Queue"},
            "ResultQueueBad": {"Type": "AWS::SQS::Queue"},
            "LambdaExecRoleBad": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": _LAMBDA_TRUST,
                    "Policies": [
                        {
                            "PolicyName": "AllowSendAndLogsOnly",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "sqs:SendMessage",
                                        "Resource": {"Fn::GetAtt": ["ResultQueueBad", "Arn"]},
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                                        "Resource": "*",
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "ForwarderFunctionBad": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaExecRoleBad", "Arn"]},
                    "Timeout": 30,
                    "Environment": {"Variables": {"RESULT_QUEUE_URL": {"Ref": "ResultQueueBad"}}},
                    "Code": {"ZipFile": _LAMBDA_CODE},
                },
            },
            "MappingBad": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {
                    "EventSourceArn": {"Fn::GetAtt": ["SourceQueueBad", "Arn"]},
                    "FunctionName": {"Ref": "ForwarderFunctionBad"},
                    "BatchSize": 1,
                    "Enabled": True,
                },
            },
        },
        "Outputs": {
            "SourceQueueBadUrl": {"Value": {"Ref": "SourceQueueBad"}},
            "ResultQueueBadUrl": {"Value": {"Ref": "ResultQueueBad"}},
        },
    }
    return json.dumps(template)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation stack whose SQS event source mapping's role lacks the queue's poll permissions
    fails and rolls back on the mapping with a permission reason, while a stack with a correctly
    scoped role deploys and delivers the message to the function."""
    sqs = ctx.client("sqs")
    ctx.client("lambda")

    # --- positive control: correctly-scoped role deploys and delivers ---
    good = _deploy_cfn(ctx, _build_good_template(), timeout_s=300.0)
    good_outputs = good["outputs"]

    good_marker = ctx.unique_name("esm-good-")
    sqs.send_message(
        QueueUrl=good_outputs["SourceQueueGoodUrl"], MessageBody=json.dumps({"marker": good_marker})
    )
    good_body = _poll_until(
        lambda: _drain_for_marker(sqs, good_outputs["ResultQueueGoodUrl"], good_marker),
        lambda body: body is not None,
        timeout_s=120.0,
        interval_s=5.0,
        description="positive-control ESM delivery",
    )
    assert good_body["marker"] == good_marker, (
        f"expected positive-control delivery to carry marker {good_marker}, got {good_body}"
    )

    # --- negative: mapping backed by an under-permissioned execution role never comes up ---
    bad = _deploy_cfn(ctx, _build_bad_template(), timeout_s=600.0, expect_failure=True)
    assert bad["stack_status"] in {
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
    }, f"expected the under-permissioned stack to fail creation, got {bad['stack_status']}"

    # The stack-level status alone would also go this way for an unrelated failure (a bad
    # runtime, a quota limit) — pin the failure to the specific resource and reason so the check
    # actually exercises the missing-permission defect, not "something in this stack failed".
    events = ctx.client("cloudformation").describe_stack_events(StackName=bad["stack_name"])[
        "StackEvents"
    ]
    mapping_failure = next(
        (
            e
            for e in events
            if e.get("LogicalResourceId") == "MappingBad" and e.get("ResourceStatus") == "CREATE_FAILED"
        ),
        None,
    )
    assert mapping_failure is not None, (
        "expected a CREATE_FAILED event for the MappingBad EventSourceMapping resource, got "
        f"events: {[(e.get('LogicalResourceId'), e.get('ResourceStatus')) for e in events]}"
    )
    reason = mapping_failure.get("ResourceStatusReason", "")
    assert (
        "ReceiveMessage" in reason or "permission" in reason.lower() or "sqs" in reason.lower()
    ), f"expected the EventSourceMapping failure to cite the missing SQS permission, got: {reason!r}"


def _drain_for_marker(sqs, queue_url: str, marker: str) -> dict[str, Any] | None:
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        try:
            body = json.loads(msg["Body"])
        except (json.JSONDecodeError, ValueError):
            continue
        if body.get("marker") == marker:
            return body
    return None


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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
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
    expect_failure=False,
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
            in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    status = stack["StackStatus"]
    if expect_failure:
        if status == "CREATE_COMPLETE":
            raise AssertionError(f"expected stack {name} to fail creation but it reached CREATE_COMPLETE")
        return {"stack_name": name, "stack_id": stack_id, "outputs": {}, "stack_status": status}
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {status}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs, "stack_status": status}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
