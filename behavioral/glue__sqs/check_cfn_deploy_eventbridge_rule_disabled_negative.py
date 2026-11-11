"""cfn-deploy-eventbridge-rule-disabled-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-rule-disabled-negative"
GROUP = "overly-permissive"
SERVICES = ["glue", "sqs"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed EventBridge rule in state DISABLED delivers no matching Glue job
    event to its SQS target; after enabling it, the same event arrives with its jobName.
    """
    job_name = _xname(ctx, "job")
    template = json.dumps(_template())
    stack = _deploy_cfn(ctx, template, parameters={"JobName": job_name})
    queue_url = stack["outputs"]["QueueUrl"]
    rule_name = stack["outputs"]["RuleName"]

    events = ctx.client("events")
    rule = events.describe_rule(Name=rule_name)
    assert rule["State"] == "DISABLED", (
        f"expected rule {rule_name} deployed via CFN to be DISABLED, got {rule['State']!r}"
    )

    def _detail(run_id: str) -> dict[str, str]:
        return {
            "jobName": job_name,
            "severity": "INFO",
            "state": "SUCCEEDED",
            "jobRunId": run_id,
            "message": "Job run succeeded",
        }

    resp = events.put_events(
        Entries=[
            {
                "Source": "sim2real.glue.job",
                "DetailType": "Glue Job State Change",
                "Detail": json.dumps(_detail("jr_disabled_" + ctx.unique_name(""))),
            }
        ]
    )
    assert resp.get("FailedEntryCount", 0) == 0, f"put_events failed: {resp}"
    _assert_no_message_arrives(ctx, queue_url, timeout_s=45.0)

    # Fix the one broken thing: enable the rule.
    events.enable_rule(Name=rule_name)
    _poll_until(
        lambda: events.describe_rule(Name=rule_name)["State"],
        lambda s: s == "ENABLED",
        timeout_s=30.0,
        interval_s=2.0,
        description=f"rule {rule_name} become ENABLED",
    )

    positive_run_id = "jr_enabled_" + ctx.unique_name("")
    resp2 = events.put_events(
        Entries=[
            {
                "Source": "sim2real.glue.job",
                "DetailType": "Glue Job State Change",
                "Detail": json.dumps(_detail(positive_run_id)),
            }
        ]
    )
    assert resp2.get("FailedEntryCount", 0) == 0, f"put_events failed: {resp2}"
    message = _wait_for_matching_message(
        ctx,
        queue_url,
        lambda body: isinstance(body, dict)
        and body.get("detail", {}).get("jobRunId") == positive_run_id,
        timeout_s=60.0,
    )
    assert message["detail"]["jobName"] == job_name, (
        f"expected delivered detail.jobName == {job_name!r}, got {message['detail'].get('jobName')!r}"
    )


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"JobName": {"Type": "String"}},
        "Resources": {
            "EventQueue": {"Type": "AWS::SQS::Queue"},
            "EventRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "EventPattern": {
                        "source": ["sim2real.glue.job"],
                        "detail-type": ["Glue Job State Change"],
                        "detail": {"jobName": [{"Ref": "JobName"}]},
                    },
                    "State": "DISABLED",
                    "Targets": [
                        {"Id": "sqs-target", "Arn": {"Fn::GetAtt": ["EventQueue", "Arn"]}}
                    ],
                },
            },
            "EventQueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "EventQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["EventQueue", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {
                                        "aws:SourceArn": {"Fn::GetAtt": ["EventRule", "Arn"]}
                                    }
                                },
                            }
                        ],
                    },
                },
            },
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "EventQueue"}},
            "RuleName": {"Value": {"Ref": "EventRule"}},
            "RuleArn": {"Value": {"Fn::GetAtt": ["EventRule", "Arn"]}},
        },
    }


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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
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


def _wait_for_matching_message(ctx, queue_url, predicate, *, timeout_s=60.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    seen: list[Any] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = m["Body"]
            seen.append(body)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if predicate(body):
                return body
    raise AssertionError(f"no message matched within {timeout_s}s; saw {len(seen)}: {seen!r}")


def _assert_no_message_arrives(ctx, queue_url, *, timeout_s=45.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=min(10, remaining)
        )
        msgs = resp.get("Messages", [])
        if msgs:
            raise AssertionError(
                f"expected no message while rule disabled, got {len(msgs)}: "
                f"{[m['Body'] for m in msgs]}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
