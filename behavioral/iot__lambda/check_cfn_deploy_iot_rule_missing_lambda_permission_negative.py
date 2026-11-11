"""cfn-deploy-iot-rule-missing-lambda-permission-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-iot-rule-missing-lambda-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["iot", "lambda"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stacked IoT rule Lambda action without AWS::Lambda::Permission gets zero invocations from matching
    traffic, while a correctly wired sibling rule in the same stack delivers its marker."""
    good_rule = _xname(ctx, "rule-good").replace("-", "_")
    bad_rule = _xname(ctx, "rule-bad").replace("-", "_")
    good_topic = f"sim2real/xsvc/{ctx.unique_name('tgood-')}"
    bad_topic = f"sim2real/xsvc/{ctx.unique_name('tbad-')}"

    result = _deploy_cfn(ctx, json.dumps(_stack_template(good_rule, bad_rule, good_topic, bad_topic)))
    good_queue_url = result["outputs"]["GoodQueueUrl"]
    bad_queue_url = result["outputs"]["BadQueueUrl"]

    good_marker = ctx.unique_name("marker-")
    good_start = time.monotonic()
    _publish(ctx, good_topic, {"marker": good_marker})
    good_body = _poll_until(
        lambda: _receive_and_delete(ctx, good_queue_url),
        lambda msgs: len(msgs) > 0,
        timeout_s=90.0,
        interval_s=3.0,
        description="positive-control invocation delivered",
    )
    good_latency_s = time.monotonic() - good_start
    assert good_body[0]["marker"] == good_marker, (
        f"expected marker {good_marker!r} on positive-control queue, got {good_body[0]!r}"
    )

    bad_marker = ctx.unique_name("marker-")
    _publish(ctx, bad_topic, {"marker": bad_marker})
    # Bounded generous poll for an absence: real AWS gives no promptness SLA either way, so we
    # hold for at least 2x the positive control's own measured delivery latency (calibrated in
    # this same run) before asserting nothing arrived -- long enough that a genuine but slower
    # delivery would have shown up. Capped so a slow positive control cannot push this check
    # past the suite's own wall-clock budget.
    window_s = min(max(15.0, 2.0 * good_latency_s), 75.0)
    deadline = time.monotonic() + window_s
    received: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        received.extend(_receive_and_delete(ctx, bad_queue_url))
        if received:
            break
        time.sleep(3.0)
    assert received == [], f"expected zero invocations without Lambda::Permission, got {received}"

    # Second independent observable: the queue's own reported depth must agree with the empty
    # receive above.
    sqs = ctx.client("sqs")
    approx = sqs.get_queue_attributes(
        QueueUrl=bad_queue_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert approx == "0", f"expected ApproximateNumberOfMessages=0 on bad queue, got {approx!r}"


def _stack_template(good_rule: str, bad_rule: str, good_topic: str, bad_topic: str) -> dict[str, Any]:
    handler_code = (
        "import json\n"
        "import os\n"
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    sqs = boto3.client('sqs')\n"
        "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(event))\n"
        "    return {'ok': True}\n"
    )

    def _role(policy_resource_ref: str) -> dict[str, Any]:
        return {
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
                                    "Resource": {"Fn::GetAtt": [policy_resource_ref, "Arn"]},
                                },
                            ],
                        },
                    }
                ],
            },
        }

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "GoodQueue": {"Type": "AWS::SQS::Queue"},
            "BadQueue": {"Type": "AWS::SQS::Queue"},
            "GoodRole": _role("GoodQueue"),
            "BadRole": _role("BadQueue"),
            "GoodFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["GoodRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": handler_code},
                    "Environment": {"Variables": {"QUEUE_URL": {"Ref": "GoodQueue"}}},
                },
            },
            "BadFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["BadRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": handler_code},
                    "Environment": {"Variables": {"QUEUE_URL": {"Ref": "BadQueue"}}},
                },
            },
            # GoodFunction: has a matching Lambda::Permission -> should be invoked.
            "GoodPermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "GoodFunction"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "iot.amazonaws.com",
                    "SourceArn": {
                        "Fn::Sub": f"arn:aws:iot:${{AWS::Region}}:${{AWS::AccountId}}:rule/{good_rule}"
                    },
                },
            },
            # BadFunction: deliberately NO Lambda::Permission resource.
            "GoodRuleRes": {
                "Type": "AWS::IoT::TopicRule",
                "Properties": {
                    "RuleName": good_rule,
                    "TopicRulePayload": {
                        "Sql": f"SELECT * FROM '{good_topic}'",
                        "RuleDisabled": False,
                        "Actions": [
                            {"Lambda": {"FunctionArn": {"Fn::GetAtt": ["GoodFunction", "Arn"]}}}
                        ],
                    },
                },
            },
            "BadRuleRes": {
                "Type": "AWS::IoT::TopicRule",
                "Properties": {
                    "RuleName": bad_rule,
                    "TopicRulePayload": {
                        "Sql": f"SELECT * FROM '{bad_topic}'",
                        "RuleDisabled": False,
                        "Actions": [
                            {"Lambda": {"FunctionArn": {"Fn::GetAtt": ["BadFunction", "Arn"]}}}
                        ],
                    },
                },
            },
        },
        "Outputs": {
            "GoodQueueUrl": {"Value": {"Ref": "GoodQueue"}},
            "BadQueueUrl": {"Value": {"Ref": "BadQueue"}},
        },
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
    return ctx.client("iot-data", endpoint_url=ctx.endpoint_url(endpoint))


def _publish(ctx, topic: str, payload: dict[str, Any]) -> None:
    client = _iot_data_client(ctx)
    client.publish(topic=topic, qos=0, payload=json.dumps(payload).encode("utf-8"))


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
