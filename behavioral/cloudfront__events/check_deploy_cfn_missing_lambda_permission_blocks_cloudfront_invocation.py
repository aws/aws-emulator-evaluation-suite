"""deploy-cfn-missing-lambda-permission-blocks-cloudfront-invocation."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-missing-lambda-permission-blocks-cloudfront-invocation"
GROUP = "overly-permissive"
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


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule a CFN stack wires to a Lambda target without an AWS::Lambda::Permission never invokes the
    function; once that permission is added for the same rule and function, the event carrying the new marker is
    delivered."""
    template = json.dumps(_build_template(include_permission=False))
    result = _deploy_cfn(ctx, template)
    queue_url = result["outputs"]["QueueUrl"]
    function_name = result["outputs"]["FunctionName"]
    rule_name = result["outputs"]["RuleName"]
    rule_arn = result["outputs"]["RuleArn"]

    # Both resources genuinely exist — the gap is purely the missing invoke permission.
    lam = ctx.client("lambda")
    events = ctx.client("events")
    lam.get_function(FunctionName=function_name)
    events.describe_rule(Name=rule_name)

    sqs = ctx.client("sqs")

    def _drain_marker(marker: str) -> dict | None:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        found = None
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            if body.get("detail", {}).get("marker") == marker and found is None:
                found = body
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        return found

    marker_blocked = ctx.unique_name("sim2real-blocked-")
    # NOTE: EventBridge PutEvents cannot inject an event whose Source starts with the
    # reserved "aws." namespace (genuine "aws.cloudfront" CloudTrail events can only
    # originate from CloudTrail, which takes minutes to propagate) — so the rule matches a
    # CloudFront-shaped detail on a customer-namespaced source. This still exercises exactly
    # the CFN-provisioned Rule -> Lambda-target -> (missing) Permission wiring under test.
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfront.audit",
                "DetailType": "CloudFront API Call (Simulated CloudTrail)",
                "Detail": json.dumps(
                    {
                        "eventSource": "cloudfront.amazonaws.com",
                        "eventName": "CreateInvalidation",
                        "marker": marker_blocked,
                    }
                ),
            }
        ]
    )

    # Bounded poll for absence: a real invocation (if it happened) would land within seconds,
    # so a generous window with no message is a reliable negative signal, not a race.
    deadline = time.monotonic() + 45.0
    seen = None
    while time.monotonic() < deadline and seen is None:
        seen = _drain_marker(marker_blocked)
        if seen is None:
            time.sleep(3.0)
    assert seen is None, "message was delivered despite missing Lambda invoke permission"

    # Positive control: grant the missing permission directly against the SAME rule/function,
    # then confirm delivery succeeds. A new resource policy can take a moment to reach EventBridge,
    # which does not retry a permission failure, so the marker event is re-sent across the wait window.
    lam.add_permission(
        FunctionName=function_name,
        StatementId="AllowEventBridgeInvokeAfterFix",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(
            FunctionName=function_name, StatementId="AllowEventBridgeInvokeAfterFix"
        )
    )

    marker_fixed = ctx.unique_name("sim2real-fixed-")

    def _build_fixed_entry():
        return {
            "Source": "sim2real.cloudfront.audit",
            "DetailType": "CloudFront API Call (Simulated CloudTrail)",
            "Detail": json.dumps(
                {
                    "eventSource": "cloudfront.amazonaws.com",
                    "eventName": "CreateInvalidation",
                    "marker": marker_fixed,
                }
            ),
        }

    delivered = _put_events_and_await(
        events,
        _build_fixed_entry,
        lambda: _drain_marker(marker_fixed),
        total_timeout=120.0,
        resend_every=20.0,
        description="marker event delivered after adding the missing permission",
    )
    assert delivered["detail"]["marker"] == marker_fixed, (
        f"expected marker {marker_fixed!r} after adding the missing permission, "
        f"got {delivered['detail'].get('marker')!r}"
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
