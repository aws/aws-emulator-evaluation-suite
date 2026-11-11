"""cfn-deploy-eventbridge-rule-missing-permission-not-invoked."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-rule-missing-permission-not-invoked"
GROUP = "deployment-order"
SERVICES = ["cloudfront", "events"]

_LAMBDA_CODE = (
    "import json\n"
    "import os\n"
    "import boto3\n"
    "\n"
    "sqs = boto3.client('sqs')\n"
    "\n"
    "def handler(event, context):\n"
    "    sqs.send_message(\n"
    "        QueueUrl=os.environ['QUEUE_URL'],\n"
    "        MessageBody=json.dumps({'target': os.environ['TARGET_LABEL'], 'detail': event.get('detail', {})}),\n"
    "    )\n"
    "    return {'ok': True}\n"
)

_SOURCE = "sim2real.cloudfront.oac"
_DETAIL_TYPE = "CloudFront API Call (Simulated CloudTrail)"


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """One matching event on a CFN-deployed rule with two Lambda targets invokes only the target
    that has the events.amazonaws.com AWS::Lambda::Permission; the unpermitted sibling is never
    invoked and the relay queue's message counters settle to 0."""
    template = json.dumps(_build_template())
    deployed = _deploy_cfn(ctx, template, timeout_s=300.0)
    fn_allowed = deployed["outputs"]["FunctionAllowedName"]
    fn_blocked = deployed["outputs"]["FunctionBlockedName"]
    queue_url = deployed["outputs"]["QueueUrl"]

    sqs = ctx.client("sqs")
    nonce = ctx.unique_name("sim2real-oac-")
    detail = {
        "eventSource": "cloudfront.amazonaws.com",
        "eventName": "CreateOriginAccessControl",
        "requestParameters": {"originAccessControlConfig": {"name": nonce}},
    }

    # Every relayed message for this nonce is kept under its target label, so a "blocked" message
    # read while polling for "allowed" still counts toward the blocked-absence assertion.
    hits: dict[str, list[dict[str, Any]]] = {"allowed": [], "blocked": []}

    def _drain_matching(target_label: str) -> list[dict[str, Any]]:
        while True:
            resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
            msgs = resp.get("Messages", [])
            if not msgs:
                return list(hits[target_label])
            for m in msgs:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
                body = json.loads(m["Body"])
                oac_name = (
                    body.get("detail", {})
                    .get("requestParameters", {})
                    .get("originAccessControlConfig", {})
                    .get("name")
                )
                if oac_name == nonce:
                    hits.setdefault(body.get("target"), []).append(body)

    trigger_started = time.monotonic()
    ctx.client("events").put_events(
        Entries=[{"Source": _SOURCE, "DetailType": _DETAIL_TYPE, "Detail": json.dumps(detail)}]
    )

    allowed_hits = _poll_until(
        lambda: _drain_matching("allowed"),
        lambda found: len(found) > 0,
        timeout_s=120.0,
        interval_s=3.0,
        description=f"permitted target {fn_allowed} relayed the triggering event",
    )
    assert len(allowed_hits) >= 1, f"permitted target {fn_allowed} never relayed the triggering event"
    latency_l = time.monotonic() - trigger_started

    # Twin control, same rule, same instant: the permitted target already proved the event pipeline
    # delivered at time L, so hold the blocked target's absence for >= 3L (floor 15s) -- a window
    # shorter than the observed positive latency would score a merely slower target as blocked.
    absence_window_s = max(3.0 * latency_l, 15.0)
    deadline = time.monotonic() + absence_window_s
    blocked_hits: list[dict[str, Any]] = list(hits["blocked"])
    while time.monotonic() < deadline:
        blocked_hits = _drain_matching("blocked")
        if blocked_hits:
            break
        time.sleep(3.0)
    assert blocked_hits == [], (
        f"blocked target {fn_blocked} was invoked despite missing permission: {blocked_hits}"
    )

    # Second, independent observable beyond "no matching message arrived": the relay queue is
    # entirely empty -- nothing from either target is unclaimed or still in flight.
    attrs = _wait_counters_zero(
        ctx, sqs, queue_url,
        ["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"relay queue still holds unclaimed messages after drain: {attrs}"
    )
    assert attrs["ApproximateNumberOfMessagesNotVisible"] == "0", (
        f"relay queue still holds in-flight messages after drain: {attrs}"
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_counters_zero(ctx, sqs, queue_url, names, *, cap_s=90.0, interval_s=3.0):
    """Read the queue's *names* counters until each is "0" or cap_s ends; return the last read.

    SQS documents these counters as eventually consistent: they "may not achieve consistency until
    at least 1 minute after the producers stop sending messages" (GetQueueAttributes).
    """
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    deadline = start + min(cap_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=list(names))["Attributes"]
        if all(attrs.get(n) == "0" for n in names):
            return attrs
        if time.monotonic() >= deadline:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {cap_s}s wait for the queue counters to settle ended (last={attrs!r}); "
                    "not graded"
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
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _build_template() -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RelayQueue": {"Type": "AWS::SQS::Queue"},
            "LambdaExecRole": {
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
                            "PolicyName": "relay",
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
                                        "Resource": {"Fn::GetAtt": ["RelayQueue", "Arn"]},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "FunctionAllowed": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                    "Timeout": 10,
                    "Environment": {
                        "Variables": {"QUEUE_URL": {"Ref": "RelayQueue"}, "TARGET_LABEL": "allowed"}
                    },
                    "Code": {"ZipFile": _LAMBDA_CODE},
                },
            },
            "FunctionBlocked": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                    "Timeout": 10,
                    "Environment": {
                        "Variables": {"QUEUE_URL": {"Ref": "RelayQueue"}, "TARGET_LABEL": "blocked"}
                    },
                    "Code": {"ZipFile": _LAMBDA_CODE},
                },
            },
            "Rule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "EventPattern": {
                        "source": [_SOURCE],
                        "detail-type": [_DETAIL_TYPE],
                        "detail": {
                            "eventSource": ["cloudfront.amazonaws.com"],
                            "eventName": ["CreateOriginAccessControl"],
                        },
                    },
                    "State": "ENABLED",
                    "Targets": [
                        {
                            "Id": "allowed-target",
                            "Arn": {"Fn::GetAtt": ["FunctionAllowed", "Arn"]},
                        },
                        {
                            "Id": "blocked-target",
                            "Arn": {"Fn::GetAtt": ["FunctionBlocked", "Arn"]},
                        },
                    ],
                },
            },
            # Only FunctionAllowed gets a resource policy permitting EventBridge to invoke it.
            # FunctionBlocked deliberately has NO AWS::Lambda::Permission.
            "PermissionAllowed": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "FunctionAllowed"},
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["Rule", "Arn"]},
                },
            },
        },
        "Outputs": {
            "FunctionAllowedName": {"Value": {"Ref": "FunctionAllowed"}},
            "FunctionBlockedName": {"Value": {"Ref": "FunctionBlocked"}},
            "QueueUrl": {"Value": {"Ref": "RelayQueue"}},
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
