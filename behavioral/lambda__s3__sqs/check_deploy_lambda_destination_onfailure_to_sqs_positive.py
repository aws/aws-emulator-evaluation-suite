"""deploy-lambda-destination-onfailure-to-sqs-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-lambda-destination-onfailure-to-sqs-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "s3", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed CFN stack wiring a Lambda async OnFailure destination to an SQS queue
    delivers the failure invocation record to that queue after the function raises."""
    fn_name = ctx.unique_name("sim2real-xsvc-fn-fail-")
    template = _build_template(fn_name)
    stack = _deploy_cfn(ctx, template)
    dest_queue_url = stack["outputs"]["DestQueueUrl"]
    function_name = stack["outputs"]["FunctionName"]

    lam = ctx.client("lambda")
    lam.invoke(
        FunctionName=function_name,
        InvocationType="Event",
        Payload=json.dumps({"id": "trial-1"}).encode(),
    )

    sqs = ctx.client("sqs")
    record = _poll_until(
        lambda: _receive_one(sqs, dest_queue_url),
        lambda m: m is not None,
        timeout_s=90,
        interval_s=3.0,
        description="OnFailure destination message on the SQS queue",
    )
    body = json.loads(record["Body"])
    condition = body["requestContext"]["condition"]
    assert condition == "RetriesExhausted", (
        f"OnFailure destination record condition wrong: {condition!r} (expected RetriesExhausted)"
    )
    function_error = body["responseContext"]["functionError"]
    assert function_error == "Unhandled", (
        f"OnFailure destination record responseContext.functionError wrong: {function_error!r} "
        "(expected Unhandled)"
    )
    error_message = body["responsePayload"]["errorMessage"]
    assert "trial-1" in error_message, (
        f"OnFailure destination record lost the invocation payload: errorMessage={error_message!r}"
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


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
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
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
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


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0):
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
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
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _receive_one(sqs, queue_url):
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
    msgs = resp.get("Messages", [])
    if not msgs:
        return None
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
    return msgs[0]


def _build_template(fn_name: str) -> str:
    fail_code = (
        "def handler(event, context):\n"
        "    raise Exception('boom-' + event.get('id', ''))\n"
    )
    doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "DestQueue": {"Type": "AWS::SQS::Queue"},
            "LambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "exec",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogGroup",
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                        ],
                                        "Resource": "*",
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": "sqs:SendMessage",
                                        "Resource": {"Fn::GetAtt": ["DestQueue", "Arn"]},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "FailingFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": fn_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Timeout": 10,
                    "Code": {"ZipFile": fail_code},
                },
            },
            "OnFailureConfig": {
                "Type": "AWS::Lambda::EventInvokeConfig",
                "Properties": {
                    "FunctionName": {"Ref": "FailingFunction"},
                    "Qualifier": "$LATEST",
                    "MaximumRetryAttempts": 0,
                    "DestinationConfig": {
                        "OnFailure": {"Destination": {"Fn::GetAtt": ["DestQueue", "Arn"]}}
                    },
                },
            },
        },
        "Outputs": {
            "DestQueueUrl": {"Value": {"Ref": "DestQueue"}},
            "FunctionName": {"Value": {"Ref": "FailingFunction"}},
        },
    }
    return json.dumps(doc)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
