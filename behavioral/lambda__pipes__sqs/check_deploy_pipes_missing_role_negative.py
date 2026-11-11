"""deploy-pipes-missing-role-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-pipes-missing-role-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "pipes", "sqs"]

_LAMBDA_CODE = (
    "import json, os, boto3\n"
    "sqs = boto3.client('sqs')\n"
    "def handler(event, context):\n"
    "    queue_url = os.environ['RESULT_QUEUE_URL']\n"
    "    records = event if isinstance(event, list) else event.get('Records', [])\n"
    "    for rec in records:\n"
    "        sqs.send_message(QueueUrl=queue_url, MessageBody=rec.get('body', ''))\n"
    "    return {'processed': len(records)}\n"
)

_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

_PIPES_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _lambda_role_props() -> dict[str, Any]:
    return {
        "AssumeRolePolicyDocument": _LAMBDA_TRUST,
        "Policies": [
            {
                "PolicyName": "AllowSendResultsAndLogs",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sqs:SendMessage",
                            "Resource": [
                                {"Fn::GetAtt": ["ResultQueueGood", "Arn"]},
                                {"Fn::GetAtt": ["ResultQueueBad", "Arn"]},
                            ],
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
    }


def _lambda_function_props(role_logical_id: str, result_queue_logical_id: str) -> dict[str, Any]:
    return {
        "Runtime": "python3.12",
        "Handler": "index.handler",
        "Role": {"Fn::GetAtt": [role_logical_id, "Arn"]},
        "Timeout": 30,
        "Environment": {"Variables": {"RESULT_QUEUE_URL": {"Ref": result_queue_logical_id}}},
        "Code": {"ZipFile": _LAMBDA_CODE},
    }


def _build_template() -> str:
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SourceQueueGood": {"Type": "AWS::SQS::Queue"},
            "SourceQueueBad": {"Type": "AWS::SQS::Queue"},
            "ResultQueueGood": {"Type": "AWS::SQS::Queue"},
            "ResultQueueBad": {"Type": "AWS::SQS::Queue"},
            "LambdaExecRole": {"Type": "AWS::IAM::Role", "Properties": _lambda_role_props()},
            "ForwarderFunctionGood": {
                "Type": "AWS::Lambda::Function",
                "Properties": _lambda_function_props("LambdaExecRole", "ResultQueueGood"),
            },
            "ForwarderFunctionBad": {
                "Type": "AWS::Lambda::Function",
                "Properties": _lambda_function_props("LambdaExecRole", "ResultQueueBad"),
            },
            "PipeRoleGood": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": _PIPES_TRUST,
                    "Policies": [
                        {
                            "PolicyName": "PipeAccessGood",
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
                                        "Action": "lambda:InvokeFunction",
                                        "Resource": {"Fn::GetAtt": ["ForwarderFunctionGood", "Arn"]},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            # Deliberately missing sqs:ReceiveMessage (and DeleteMessage) on the source queue —
            # only GetQueueAttributes is granted — so the pipe can never actually poll it.
            "PipeRoleBad": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": _PIPES_TRUST,
                    "Policies": [
                        {
                            "PolicyName": "PipeAccessBad",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "sqs:GetQueueAttributes",
                                        "Resource": {"Fn::GetAtt": ["SourceQueueBad", "Arn"]},
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": "lambda:InvokeFunction",
                                        "Resource": {"Fn::GetAtt": ["ForwarderFunctionBad", "Arn"]},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "PipeGood": {
                "Type": "AWS::Pipes::Pipe",
                "Properties": {
                    "RoleArn": {"Fn::GetAtt": ["PipeRoleGood", "Arn"]},
                    "Source": {"Fn::GetAtt": ["SourceQueueGood", "Arn"]},
                    "SourceParameters": {"SqsQueueParameters": {"BatchSize": 1}},
                    "Target": {"Fn::GetAtt": ["ForwarderFunctionGood", "Arn"]},
                    "TargetParameters": {
                        "LambdaFunctionParameters": {"InvocationType": "REQUEST_RESPONSE"}
                    },
                },
            },
        },
        "Outputs": {
            "SourceQueueGoodUrl": {"Value": {"Ref": "SourceQueueGood"}},
            "SourceQueueBadUrl": {"Value": {"Ref": "SourceQueueBad"}},
            "SourceQueueBadArn": {"Value": {"Fn::GetAtt": ["SourceQueueBad", "Arn"]}},
            "ResultQueueGoodUrl": {"Value": {"Ref": "ResultQueueGood"}},
            "ResultQueueBadUrl": {"Value": {"Ref": "ResultQueueBad"}},
            "PipeRoleBadArn": {"Value": {"Fn::GetAtt": ["PipeRoleBad", "Arn"]}},
            "ForwarderFunctionBadArn": {"Value": {"Fn::GetAtt": ["ForwarderFunctionBad", "Arn"]}},
        },
    }
    return json.dumps(template)


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipe whose role lacks the source queue's poll permissions can still report RUNNING but never
    delivers its message, which stays on the queue, while a pipe in the same stack with a correctly
    scoped role delivers."""
    deployed = _deploy_cfn(ctx, _build_template(), timeout_s=420.0)
    outputs = deployed["outputs"]
    sqs = ctx.client("sqs")
    pipes = ctx.client("pipes")

    # --- positive control: the correctly-permissioned pipe delivers end to end ---
    good_marker = ctx.unique_name("pipe-good-")
    sqs.send_message(
        QueueUrl=outputs["SourceQueueGoodUrl"], MessageBody=json.dumps({"marker": good_marker})
    )
    good_body = _poll_until(
        lambda: _drain_for_marker(sqs, outputs["ResultQueueGoodUrl"], good_marker),
        lambda body: body is not None,
        timeout_s=150.0,
        interval_s=5.0,
        description="positive-control pipe delivery",
    )
    assert good_body["marker"] == good_marker, (
        f"positive-control delivery carried the wrong marker: expected {good_marker!r}, "
        f"got {good_body['marker']!r}"
    )

    # --- negative: create the under-permissioned pipe directly via the SDK so we control its
    # lifecycle precisely (it is not declared in the template to avoid depending on whatever
    # stabilization behavior the CFN resource provider applies to a pipe that can't start) ---
    pipe_name = ctx.unique_name("pipe-bad-")
    pipes.create_pipe(
        Name=pipe_name,
        RoleArn=outputs["PipeRoleBadArn"],
        Source=outputs["SourceQueueBadArn"],
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=outputs["ForwarderFunctionBadArn"],
        TargetParameters={"LambdaFunctionParameters": {"InvocationType": "REQUEST_RESPONSE"}},
        Tags=_xsvc_resource_tags(),
    )
    ctx.on_cleanup(lambda: pipes.delete_pipe(Name=pipe_name))

    final_state = _poll_until(
        lambda: pipes.describe_pipe(Name=pipe_name)["CurrentState"],
        lambda s: s in {"RUNNING", "START_FAILED", "CREATE_FAILED"},
        timeout_s=150.0,
        interval_s=5.0,
        description=f"pipe {pipe_name} to reach a terminal startup state",
    )
    # Pipes (unlike Lambda's CreateEventSourceMapping) does not synchronously validate that the
    # role can actually poll the source queue — a pipe with only sqs:GetQueueAttributes on the
    # source can still reach CurrentState=RUNNING. The missing sqs:ReceiveMessage/DeleteMessage
    # permission instead manifests as a silent runtime failure: the pipe never pulls a message
    # off the queue, so nothing is ever forwarded to the Lambda target.
    assert final_state in {"RUNNING", "START_FAILED", "CREATE_FAILED"}, (
        f"pipe {pipe_name} never reached a terminal startup state, got {final_state!r}"
    )

    bad_marker = ctx.unique_name("pipe-bad-msg-")
    sqs.send_message(
        QueueUrl=outputs["SourceQueueBadUrl"], MessageBody=json.dumps({"marker": bad_marker})
    )

    seen: set[str] = set()
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=outputs["ResultQueueBadUrl"], MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=outputs["ResultQueueBadUrl"], ReceiptHandle=msg["ReceiptHandle"])
            try:
                seen.add(json.loads(msg["Body"]).get("marker"))
            except (json.JSONDecodeError, ValueError):
                pass
    assert bad_marker not in seen, "message was delivered despite the pipe lacking receive permission"

    attrs = sqs.get_queue_attributes(
        QueueUrl=outputs["SourceQueueBadUrl"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert int(attrs["ApproximateNumberOfMessages"]) >= 1, "message unexpectedly left the source queue"


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
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
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
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
