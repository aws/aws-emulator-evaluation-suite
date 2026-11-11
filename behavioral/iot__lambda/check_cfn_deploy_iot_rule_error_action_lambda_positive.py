"""cfn-deploy-iot-rule-error-action-lambda-positive."""
from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-iot-rule-error-action-lambda-positive"
GROUP = "deployment-order"
SERVICES = ["iot", "lambda"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed stack wiring a topic rule's errorAction to a secondary Lambda invokes
    that fallback function when the primary Lambda action fails (nonexistent target)."""
    rule_name = _xname(ctx, "rule").replace("-", "_")
    topic = f"sim2real/xsvc/{ctx.unique_name('t-')}"
    nonexistent_fn_name = ctx.unique_name("sim2real-xsvc-nonexistent-")

    result = _deploy_cfn(ctx, json.dumps(_stack_template(rule_name, topic, nonexistent_fn_name)))
    fallback_queue_url = result["outputs"]["FallbackQueueUrl"]

    marker = ctx.unique_name("marker-")
    payload_bytes = json.dumps({"marker": marker}).encode("utf-8")
    _publish(ctx, topic, payload_bytes)

    body = _poll_until(
        lambda: _receive_and_delete(ctx, fallback_queue_url),
        lambda msgs: len(msgs) > 0,
        timeout_s=90.0,
        interval_s=3.0,
        description="fallback errorAction invocation delivered",
    )
    error_msg = body[0]
    assert error_msg["ruleName"] == rule_name, error_msg
    assert error_msg["topic"] == topic, error_msg
    assert base64.b64decode(error_msg["base64OriginalPayload"]) == payload_bytes, error_msg
    failures = error_msg["failures"]
    assert isinstance(failures, list) and len(failures) >= 1, error_msg
    assert failures[0]["errorMessage"], error_msg


def _stack_template(rule_name: str, topic: str, nonexistent_fn_name: str) -> dict[str, Any]:
    handler_code = (
        "import json\n"
        "import os\n"
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    sqs = boto3.client('sqs')\n"
        "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(event))\n"
        "    return {'ok': True}\n"
    )
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "FallbackQueue": {"Type": "AWS::SQS::Queue"},
            "FallbackRole": {
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
                                        "Resource": {"Fn::GetAtt": ["FallbackQueue", "Arn"]},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "FallbackFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["FallbackRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": handler_code},
                    "Environment": {"Variables": {"QUEUE_URL": {"Ref": "FallbackQueue"}}},
                },
            },
            "FallbackPermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "FallbackFunction"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "iot.amazonaws.com",
                    "SourceArn": {
                        "Fn::Sub": f"arn:aws:iot:${{AWS::Region}}:${{AWS::AccountId}}:rule/{rule_name}"
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
                                        "Fn::Sub": (
                                            "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}"
                                            f":function:{nonexistent_fn_name}"
                                        )
                                    }
                                }
                            }
                        ],
                        "ErrorAction": {
                            "Lambda": {"FunctionArn": {"Fn::GetAtt": ["FallbackFunction", "Arn"]}}
                        },
                    },
                },
            },
        },
        "Outputs": {"FallbackQueueUrl": {"Value": {"Ref": "FallbackQueue"}}},
    }


_XSVC_PREFIX = "sim2real-xsvc-"


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


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
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


def _iot_data_client(ctx):
    iot = ctx.client("iot")
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    client = ctx.client("iot-data", endpoint_url=ctx.endpoint_url(endpoint))
    _wait_for_iot_data_ready(client)
    return client


def _wait_for_iot_data_ready(iot_data, timeout_s=180.0, interval_s=5.0):
    """The per-account IoT data-ATS endpoint can take a short time to become
    reachable (DNS/cert propagation) right after being (re)provisioned; retry a
    harmless publish until the endpoint answers without a connectivity error."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            iot_data.publish(topic="sim2real/warmup/probe", qos=0, payload=b"{}")
            return
        except Exception as e:  # noqa: BLE001 - any transient error, keep retrying
            last_exc = e
            time.sleep(interval_s)
    raise AssertionError(f"iot-data endpoint never became reachable: {last_exc!r}")


def _publish(ctx, topic: str, payload_bytes: bytes) -> None:
    client = _iot_data_client(ctx)
    client.publish(topic=topic, qos=0, payload=payload_bytes)


def _receive_and_delete(ctx, queue_url: str) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
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
