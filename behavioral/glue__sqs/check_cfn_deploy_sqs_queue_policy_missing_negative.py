"""cfn-deploy-sqs-queue-policy-missing-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sqs-queue-policy-missing-negative"
GROUP = "overly-permissive"
SERVICES = ["glue", "sqs"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule with two SQS targets delivers a put "Glue Job State Change" event (state
    SUCCEEDED) only to the queue whose policy grants events.amazonaws.com sqs:SendMessage; the
    queue without a policy receives nothing within 45 s.
    """
    job_name = _xname(ctx, "job")
    template = json.dumps(_template())
    stack = _deploy_cfn(ctx, template, parameters={"JobName": job_name})
    good_url = stack["outputs"]["GoodQueueUrl"]
    bad_url = stack["outputs"]["BadQueueUrl"]

    events = ctx.client("events")
    detail = {
        "jobName": job_name,
        "severity": "INFO",
        "state": "SUCCEEDED",
        "jobRunId": "jr_" + ctx.unique_name(""),
        "message": "Job run succeeded",
    }
    resp = events.put_events(
        Entries=[
            {
                "Source": "sim2real.glue.job",
                "DetailType": "Glue Job State Change",
                "Detail": json.dumps(detail),
            }
        ]
    )
    assert resp.get("FailedEntryCount", 0) == 0, f"put_events failed: {resp}"

    # Positive control: the correctly-policied queue receives the event.
    good_message = _wait_for_matching_message(
        ctx,
        good_url,
        lambda body: isinstance(body, dict)
        and body.get("detail", {}).get("jobName") == job_name,
        timeout_s=60.0,
    )
    assert good_message["detail"]["state"] == "SUCCEEDED", (
        f"expected SUCCEEDED on the policied queue, got: {good_message!r}"
    )

    # Negative: the target with no queue policy never gets the same event.
    _assert_no_message_arrives(ctx, bad_url, timeout_s=45.0)


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"JobName": {"Type": "String"}},
        "Resources": {
            "GoodQueue": {"Type": "AWS::SQS::Queue"},
            "BadQueue": {"Type": "AWS::SQS::Queue"},
            "EventRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "EventPattern": {
                        "source": ["sim2real.glue.job"],
                        "detail-type": ["Glue Job State Change"],
                        "detail": {"jobName": [{"Ref": "JobName"}]},
                    },
                    "State": "ENABLED",
                    "Targets": [
                        {"Id": "good-target", "Arn": {"Fn::GetAtt": ["GoodQueue", "Arn"]}},
                        {"Id": "bad-target", "Arn": {"Fn::GetAtt": ["BadQueue", "Arn"]}},
                    ],
                },
            },
            "GoodQueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "GoodQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["GoodQueue", "Arn"]},
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
            # BadQueue intentionally has NO AWS::SQS::QueuePolicy resource.
        },
        "Outputs": {
            "GoodQueueUrl": {"Value": {"Ref": "GoodQueue"}},
            "BadQueueUrl": {"Value": {"Ref": "BadQueue"}},
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
                f"expected no message on unpolicied queue, got {len(msgs)}: "
                f"{[m['Body'] for m in msgs]}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
