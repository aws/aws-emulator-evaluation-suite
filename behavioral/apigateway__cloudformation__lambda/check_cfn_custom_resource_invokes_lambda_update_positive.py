"""cfn-custom-resource-invokes-lambda-update-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-custom-resource-invokes-lambda-update-positive"
GROUP = "resource-binding"
SERVICES = ["apigateway", "cloudformation", "lambda"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN stack update triggers the custom resource Lambda with RequestType=Update, carrying
    both OldResourceProperties and the new properties — verified via the CFN attribute path and
    an independent SQS side-channel the Lambda writes to on every real invocation."""
    queue_url, queue_arn = _create_queue(ctx)
    template = json.dumps(_template())

    created = _deploy_cfn(
        ctx, template, parameters={"QueueArn": queue_arn, "QueueUrl": queue_url, "ResourceValue": "v1"}
    )
    assert created["outputs"]["RequestType"] == "Create"
    # Drain the Create-time side-channel message so the Update one below is unambiguous.
    _drain_queue(ctx, queue_url)

    updated = _update_stack_and_wait(
        ctx,
        created["stack_name"],
        parameters={
            "QueueArn": queue_arn,
            "QueueUrl": queue_url,
            "ResourceValue": "v2",
        },
    )
    assert updated["outputs"]["RequestType"] == "Update"
    assert updated["outputs"]["NewValue"] == "v2"

    body = _receive_one_message(ctx, queue_url, timeout_s=60.0)
    assert body["RequestType"] == "Update"
    assert body["OldValue"] == "v1"
    assert body["NewValue"] == "v2"


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "QueueArn": {"Type": "String"},
            "QueueUrl": {"Type": "String"},
            "ResourceValue": {"Type": "String", "Default": "v1"},
        },
        "Resources": {
            "ExecRole": {
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
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "AllowSendToQueue",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "sqs:SendMessage",
                                        "Resource": {"Ref": "QueueArn"},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "ProviderFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Handler": "index.handler",
                    "Runtime": "python3.12",
                    "Timeout": 30,
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Code": {"ZipFile": {"Fn::Join": ["\n", _provider_code_lines()]}},
                },
            },
            "MyResource": {
                "Type": "Custom::Sim2RealTest",
                "Properties": {
                    "ServiceToken": {"Fn::GetAtt": ["ProviderFunction", "Arn"]},
                    "QueueUrl": {"Ref": "QueueUrl"},
                    "Value": {"Ref": "ResourceValue"},
                },
            },
        },
        "Outputs": {
            "RequestType": {"Value": {"Fn::GetAtt": ["MyResource", "RequestType"]}},
            "NewValue": {"Value": {"Fn::GetAtt": ["MyResource", "NewValue"]}},
        },
    }


def _provider_code_lines() -> list[str]:
    return [
        "import json",
        "import boto3",
        "import cfnresponse",
        "",
        "def handler(event, context):",
        "    props = event.get('ResourceProperties') or {}",
        "    old_props = event.get('OldResourceProperties') or {}",
        "    request_type = event['RequestType']",
        "    queue_url = props.get('QueueUrl') or old_props.get('QueueUrl')",
        "    if queue_url:",
        "        boto3.client('sqs').send_message(",
        "            QueueUrl=queue_url,",
        "            MessageBody=json.dumps({",
        "                'RequestType': request_type,",
        "                'OldValue': old_props.get('Value'),",
        "                'NewValue': props.get('Value'),",
        "            }),",
        "        )",
        "    if props.get('ForceFail') == 'true':",
        "        cfnresponse.send(event, context, cfnresponse.FAILED, {}, 'sim2real-cr-fixed')",
        "        return",
        "    data = {'RequestType': request_type, 'NewValue': str(props.get('Value', ''))}",
        "    cfnresponse.send(event, context, cfnresponse.SUCCESS, data, 'sim2real-cr-fixed')",
    ]


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


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, "q"), tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _drain_queue(ctx, queue_url: str) -> None:
    sqs = ctx.client("sqs")
    for _ in range(10):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        msgs = resp.get("Messages", [])
        if not msgs:
            return
        for m in msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])


def _receive_one_message(ctx, queue_url: str, *, timeout_s: float) -> dict[str, Any]:
    sqs = ctx.client("sqs")

    def _probe():
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        return resp.get("Messages", [])

    messages = _poll_until(
        _probe, lambda m: bool(m), timeout_s=timeout_s, interval_s=2.0,
        description="sqs side-channel message from custom resource lambda",
    )
    msg = messages[0]
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return json.loads(msg["Body"])


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
    kwargs: dict[str, Any] = {
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
            s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
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


def _update_stack_and_wait(
    ctx, stack_name: str, *, parameters: dict[str, str], timeout_s: float = 300.0
) -> dict[str, Any]:
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack update {stack_name}",
    )
    if status != "UPDATE_COMPLETE":
        raise AssertionError(f"Stack update {stack_name} ended in {status}")
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": stack_name, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
