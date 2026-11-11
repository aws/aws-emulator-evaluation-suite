"""deploy-cfn-eventbridge-rule-cloudfront-invalidation-lambda."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-eventbridge-rule-cloudfront-invalidation-lambda"
GROUP = "deployment-order"
SERVICES = ["cloudfront", "events"]

_LAMBDA_CODE = (
    "import json\n"
    "import os\n"
    "import boto3\n"
    "\n"
    "def handler(event, context):\n"
    "    sqs = boto3.client('sqs')\n"
    "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(event))\n"
    "    return {'ok': True}\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """CFN-deployed EventBridge rule matching CloudTrail CloudFront API calls invokes its
    Lambda target when a matching event is emitted, end-to-end through the queue the Lambda
    writes to."""
    template = json.dumps(_build_template(include_permission=True))
    result = _deploy_cfn(ctx, template)
    queue_url = result["outputs"]["QueueUrl"]
    rule_arn = result["outputs"]["RuleArn"]

    events = ctx.client("events")
    lam = ctx.client("lambda")
    function_name = result["outputs"]["FunctionName"]

    # A freshly-created Lambda execution role's inline policy (sqs:SendMessage) is not
    # guaranteed to be visible to the Lambda service the instant CFN reports
    # CREATE_COMPLETE. If we fire the real EventBridge event before IAM has propagated,
    # the async Lambda invocation fails internally (AccessDenied calling SQS) and the
    # platform's built-in async retry backs off for minutes — well past any reasonable
    # poll window. Warm the role up with a direct synchronous invoke first, retrying
    # until the handler itself reports success.
    def _warm_invoke():
        resp = lam.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps({"warmup": True}).encode(),
        )
        if resp.get("FunctionError"):
            return False
        payload = json.loads(resp["Payload"].read())
        return bool(payload.get("ok"))

    _poll_until(
        _warm_invoke,
        lambda ok: ok,
        timeout_s=60.0,
        interval_s=3.0,
        description="lambda execution role can send to SQS (IAM propagation)",
    )

    sqs = ctx.client("sqs")
    # Drain the warm-up message(s) so they can't be mistaken for the real marker.
    while True:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        msgs = resp.get("Messages", [])
        if not msgs:
            break
        for msg in msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])

    marker = ctx.unique_name("sim2real-marker-")

    # NOTE: EventBridge PutEvents cannot be used to *inject* a synthetic event whose Source
    # starts with the reserved "aws." namespace (real CloudTrail-authored "aws.cloudfront"
    # events can only originate from CloudTrail itself, which takes minutes to propagate).
    # So the deployed rule's EventPattern below matches a CloudFront-shaped detail on a
    # customer-namespaced source — this still exercises the exact CFN-provisioned
    # Rule -> Lambda-target -> Permission wiring under test, just via an injectable event.
    def _build_entry():
        return {
            "Source": "sim2real.cloudfront.audit",
            "DetailType": "CloudFront API Call (Simulated CloudTrail)",
            "Detail": json.dumps(
                {
                    "eventSource": "cloudfront.amazonaws.com",
                    "eventName": "CreateInvalidation",
                    "awsRegion": ctx.region,
                    "marker": marker,
                }
            ),
        }

    def _probe():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            if body.get("detail", {}).get("marker") == marker:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                return body
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        return None

    delivered = _put_events_and_await(
        events,
        _build_entry,
        _probe,
        total_timeout=120.0,
        resend_every=20.0,
        description="marker event delivered to lambda via EventBridge rule",
    )
    assert delivered["source"] == "sim2real.cloudfront.audit", (
        f"expected source sim2real.cloudfront.audit, got {delivered['source']!r}"
    )
    assert delivered["detail-type"] == "CloudFront API Call (Simulated CloudTrail)", (
        f"expected detail-type 'CloudFront API Call (Simulated CloudTrail)', got {delivered['detail-type']!r}"
    )
    assert delivered["resources"] == [], (
        f"expected an empty resources list on an injected event, got {delivered['resources']!r}"
    )

    # Independent read at EventBridge itself (a different op than the CFN describe_stacks
    # that already confirmed CREATE_COMPLETE) — proves the rule CFN reported creating is the
    # SAME rule that just matched and invoked the target, not merely a truthy Output string.
    rule_name = result["outputs"]["RuleName"]
    rule = events.describe_rule(Name=rule_name)
    assert rule["Arn"] == rule_arn, (
        f"describe_rule Arn {rule['Arn']!r} != CFN output RuleArn {rule_arn!r}"
    )
    assert rule["State"] == "ENABLED", f"expected rule {rule_name} ENABLED, got {rule['State']!r}"


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


def _put_events_and_await(
    events_client,
    build_entry,
    probe,
    *,
    total_timeout=90.0,
    resend_every=20.0,
    description="condition",
):
    """Poll `probe` for delivery, periodically re-sending the event.

    A single put_events attempt can be silently dropped by EventBridge if a
    just-created IAM/resource permission hasn't fully propagated yet; a fresh
    permission error is not retried by EventBridge itself. Re-emitting the
    (idempotent, marker-keyed) event a few times across the window absorbs that
    propagation lag without producing false negatives.
    """
    deadline = time.monotonic() + total_timeout
    next_send = time.monotonic()
    last = None
    while time.monotonic() < deadline:
        if time.monotonic() >= next_send:
            events_client.put_events(Entries=[build_entry()])
            next_send = time.monotonic() + resend_every
        last = probe()
        if last is not None:
            return last
        time.sleep(3.0)
    raise AssertionError(f"{description} not met within {total_timeout}s. Last result: {last!r}")


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


def _build_template(include_permission: bool) -> dict:
    resources: dict[str, Any] = {
        "TestQueue": {"Type": "AWS::SQS::Queue"},
        "LambdaExecRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                    ],
                },
                "Policies": [
                    {
                        "PolicyName": "sqs-send",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                                    "Resource": "*",
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": "sqs:SendMessage",
                                    "Resource": {"Fn::GetAtt": ["TestQueue", "Arn"]},
                                },
                            ],
                        },
                    }
                ],
            },
        },
        "MarkerFunction": {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "Handler": "index.handler",
                "Runtime": "python3.12",
                "Timeout": 30,
                "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                "Environment": {"Variables": {"QUEUE_URL": {"Ref": "TestQueue"}}},
                "Code": {"ZipFile": _LAMBDA_CODE},
            },
        },
        "CloudFrontApiRule": {
            "Type": "AWS::Events::Rule",
            "Properties": {
                "EventPattern": {
                    "source": ["sim2real.cloudfront.audit"],
                    "detail-type": ["CloudFront API Call (Simulated CloudTrail)"],
                    "detail": {"eventSource": ["cloudfront.amazonaws.com"]},
                },
                "Targets": [{"Id": "marker-target", "Arn": {"Fn::GetAtt": ["MarkerFunction", "Arn"]}}],
            },
        },
    }
    if include_permission:
        resources["InvokePermission"] = {
            "Type": "AWS::Lambda::Permission",
            "Properties": {
                "Action": "lambda:InvokeFunction",
                "FunctionName": {"Ref": "MarkerFunction"},
                "Principal": "events.amazonaws.com",
                "SourceArn": {"Fn::GetAtt": ["CloudFrontApiRule", "Arn"]},
            },
        }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "TestQueue"}},
            "FunctionName": {"Value": {"Ref": "MarkerFunction"}},
            "RuleName": {"Value": {"Ref": "CloudFrontApiRule"}},
            "RuleArn": {"Value": {"Fn::GetAtt": ["CloudFrontApiRule", "Arn"]}},
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
