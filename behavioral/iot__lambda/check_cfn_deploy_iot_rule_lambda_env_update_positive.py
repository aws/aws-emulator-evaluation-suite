"""cfn-deploy-iot-rule-lambda-env-update-positive."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-iot-rule-lambda-env-update-positive"
GROUP = "deployment-order"
SERVICES = ["iot", "lambda"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Updating a deployed stack's Lambda environment variable (which references the IoT
    topic ARN) redeploys correctly and the NEXT invocation reflects the new value."""
    rule_name = _xname(ctx, "rule").replace("-", "_")
    topic = f"sim2real/xsvc/{ctx.unique_name('t-')}"
    topic_arn_v1 = f"arn:aws:iot:{ctx.region}:*:topic/{topic}#v1"
    topic_arn_v2 = f"arn:aws:iot:{ctx.region}:*:topic/{topic}#v2"

    result = _deploy_cfn(
        ctx, json.dumps(_stack_template(rule_name, topic, topic_arn_v1))
    )
    stack_name = result["stack_name"]
    queue_url = result["outputs"]["QueueUrl"]

    marker1 = ctx.unique_name("marker-")
    _publish(ctx, topic, {"marker": marker1})
    msg1 = _poll_until(
        lambda: _receive_and_delete(ctx, queue_url),
        lambda msgs: len(msgs) > 0,
        timeout_s=90.0,
        interval_s=3.0,
        description="pre-update invocation delivered",
    )[0]
    assert msg1["marker"] == marker1, (
        f"expected pre-update marker {marker1!r}, got {msg1['marker']!r}"
    )
    assert msg1["topic_arn"] == topic_arn_v1, (
        f"expected pre-update invocation to see TOPIC_ARN={topic_arn_v1!r}, got {msg1['topic_arn']!r}"
    )

    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_stack_template(rule_name, topic, topic_arn_v2)),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED"},
        timeout_s=180.0,
        interval_s=5.0,
        description=f"CFN stack {stack_name} update",
    )
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "UPDATE_COMPLETE", f"update ended in {status}"

    marker2 = ctx.unique_name("marker-")
    _publish(ctx, topic, {"marker": marker2})
    msg2 = _poll_until(
        lambda: _receive_and_delete(ctx, queue_url),
        lambda msgs: len(msgs) > 0,
        timeout_s=90.0,
        interval_s=3.0,
        description="post-update invocation delivered",
    )[0]
    assert msg2["marker"] == marker2, (
        f"expected post-update marker {marker2!r}, got {msg2['marker']!r}"
    )
    assert msg2["topic_arn"] == topic_arn_v2, (
        f"expected post-update invocation to see TOPIC_ARN={topic_arn_v2!r}, got {msg2['topic_arn']!r}"
    )


def _stack_template(rule_name: str, topic: str, topic_arn: str) -> dict[str, Any]:
    handler_code = (
        "import json\n"
        "import os\n"
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    sqs = boto3.client('sqs')\n"
        "    body = dict(event)\n"
        "    body['topic_arn'] = os.environ.get('TOPIC_ARN', 'unset')\n"
        "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(body))\n"
        "    return {'ok': True}\n"
    )
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ResultQueue": {"Type": "AWS::SQS::Queue"},
            "LambdaExecutionRole": {
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
                            "PolicyName": "inline",
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
                                        "Resource": {
                                            "Fn::GetAtt": ["ResultQueue", "Arn"]
                                        },
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "HandlerFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaExecutionRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": handler_code},
                    "Environment": {
                        "Variables": {
                            "QUEUE_URL": {"Ref": "ResultQueue"},
                            "TOPIC_ARN": topic_arn,
                        }
                    },
                },
            },
            "IotRule": {
                "Type": "AWS::IoT::TopicRule",
                "Properties": {
                    "RuleName": rule_name,
                    "TopicRulePayload": {
                        "Sql": f"SELECT * FROM '{topic}'",
                        "RuleDisabled": False,
                        "Actions": [
                            {
                                "Lambda": {
                                    "FunctionArn": {
                                        "Fn::GetAtt": ["HandlerFunction", "Arn"]
                                    }
                                }
                            }
                        ],
                    },
                },
            },
            "RulePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "HandlerFunction"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "iot.amazonaws.com",
                    "SourceArn": {
                        "Fn::Sub": f"arn:aws:iot:${{AWS::Region}}:${{AWS::AccountId}}:rule/{rule_name}"
                    },
                },
            },
        },
        "Outputs": {"QueueUrl": {"Value": {"Ref": "ResultQueue"}}},
    }


_XSVC_PREFIX = "sim2real-xsvc-"


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


def _xsvc_resource_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


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
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

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


def _iot_data_client(ctx):
    iot = ctx.client("iot")
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return ctx.client("iot-data", endpoint_url=ctx.endpoint_url(endpoint))


def _publish(ctx, topic: str, payload: dict[str, Any]) -> None:
    client = _iot_data_client(ctx)
    client.publish(topic=topic, qos=0, payload=json.dumps(payload).encode("utf-8"))


def _receive_and_delete(ctx, queue_url: str) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2
    )
    out = []
    for msg in resp.get("Messages", []):
        try:
            out.append(json.loads(msg["Body"]))
        except (json.JSONDecodeError, ValueError):
            out.append({"raw": msg["Body"]})
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
