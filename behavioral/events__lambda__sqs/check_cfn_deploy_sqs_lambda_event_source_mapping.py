"""cfn-deploy-sqs-lambda-event-source-mapping."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sqs-lambda-event-source-mapping"
GROUP = "deployment-order"
SERVICES = ["events", "lambda", "sqs"]

_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {
        "SourceQueueName": {"Type": "String"},
        "ResultsQueueName": {"Type": "String"},
        "RoleNameParam": {"Type": "String"},
        "FunctionNameParam": {"Type": "String"},
    },
    "Resources": {
        "SourceQueue": {
            "Type": "AWS::SQS::Queue",
            "Properties": {"QueueName": {"Ref": "SourceQueueName"}, "VisibilityTimeout": 30},
        },
        "ResultsQueue": {
            "Type": "AWS::SQS::Queue",
            "Properties": {"QueueName": {"Ref": "ResultsQueueName"}},
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
                "Policies": [{
                    "PolicyName": "SendToResults",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": "sqs:SendMessage",
                            "Resource": {"Fn::GetAtt": ["ResultsQueue", "Arn"]},
                        }],
                    },
                }],
            },
        },
        "ForwarderFn": {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "FunctionName": {"Ref": "FunctionNameParam"},
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                "Timeout": 30,
                "Environment": {
                    "Variables": {"RESULTS_QUEUE_URL": {"Ref": "ResultsQueue"}}
                },
                "Code": {
                    "ZipFile": (
                        "import json, os, boto3\n"
                        "sqs = boto3.client('sqs')\n"
                        "def handler(event, context):\n"
                        "    url = os.environ['RESULTS_QUEUE_URL']\n"
                        "    for record in event['Records']:\n"
                        "        sqs.send_message(QueueUrl=url, MessageBody=record['body'])\n"
                        "    return {'processed': len(event['Records'])}\n"
                    )
                },
            },
        },
        "Esm": {
            "Type": "AWS::Lambda::EventSourceMapping",
            "Properties": {
                "EventSourceArn": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                "FunctionName": {"Ref": "ForwarderFn"},
                "BatchSize": 1,
                "Enabled": True,
            },
        },
    },
    "Outputs": {
        "SourceQueueUrl": {"Value": {"Ref": "SourceQueue"}},
        "ResultsQueueUrl": {"Value": {"Ref": "ResultsQueue"}},
        "FunctionArn": {"Value": {"Fn::GetAtt": ["ForwarderFn", "Arn"]}},
        "EventSourceMappingId": {"Value": {"Ref": "Esm"}},
    },
})


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed AWS::Lambda::EventSourceMapping on an SQS queue results in a real
    invocation: a message sent to the source queue is forwarded by the function into a
    results queue, proving the mapping actually polls and delivers, not merely CREATE_COMPLETE."""
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    names = {
        "SourceQueueName": _xname(ctx, "esm-src"),
        "ResultsQueueName": _xname(ctx, "esm-res"),
        "RoleNameParam": _xname(ctx, "esm-role"),
        "FunctionNameParam": _xname(ctx, "esm-fn"),
    }
    result = _deploy_cfn(ctx, _TEMPLATE, parameters=names)
    source_url = result["outputs"]["SourceQueueUrl"]
    results_url = result["outputs"]["ResultsQueueUrl"]
    mapping_uuid = result["outputs"]["EventSourceMappingId"]

    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=mapping_uuid)["State"],
        lambda s: s == "Enabled",
        timeout_s=120,
        interval_s=3.0,
        description=f"event source mapping {mapping_uuid} Enabled",
    )

    marker = ctx.unique_name("esm-payload-")
    sqs.send_message(QueueUrl=source_url, MessageBody=marker)

    delivered = _poll_for_message(ctx, results_url, marker, timeout_s=90)
    assert delivered == marker, (
        f"expected marker {marker!r} forwarded to results queue {results_url} "
        f"within 90s, got {delivered!r}"
    )

    remaining = _wait_counters_zero(ctx, sqs, source_url, ["ApproximateNumberOfMessages"])
    # Successfully processed messages are deleted from the source queue by the mapping.
    assert int(remaining["ApproximateNumberOfMessages"]) == 0, (
        f"expected source queue {source_url} to be drained by the event source "
        f"mapping, found {remaining['ApproximateNumberOfMessages']} remaining"
    )


def _poll_for_message(ctx, queue_url: str, expected_body: str, *, timeout_s: float) -> str | None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=5, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if msg["Body"] == expected_body:
                return msg["Body"]
        time.sleep(1)
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_counters_zero(ctx, sqs, queue_url, names, *, cap_s=90.0, interval_s=3.0):
    """Read the queue's *names* counters until each is "0" or cap_s ends; return the last read.

    SQS documents these counters as eventually consistent: they "may not achieve consistency until
    at least 1 minute after the producers stop sending messages" (GetQueueAttributes). A stop forced
    by the runner's budget, short of cap_s, is no verdict.
    """
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    deadline = start + budget_s
    while True:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=list(names))["Attributes"]
        if all(attrs.get(n) == "0" for n in names):
            return attrs
        if time.monotonic() >= deadline:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {cap_s}s wait ended (last={attrs!r}); not graded"
                )
            return attrs
        time.sleep(interval_s)


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
    template_body = template.read_text() if hasattr(template, "read_text") else template
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
