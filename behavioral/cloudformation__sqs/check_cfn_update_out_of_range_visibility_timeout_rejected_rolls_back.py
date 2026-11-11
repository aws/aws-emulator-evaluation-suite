"""cfn-update-out-of-range-visibility-timeout-rejected-rolls-back."""

from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-update-out-of-range-visibility-timeout-rejected-rolls-back"

GROUP = "deploy-update-rollback"

SERVICES = ["cloudformation", "sqs"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """An update pushing a queue's VisibilityTimeout past SQS's 43200 s limit rolls back and leaves
    the queue's attribute, URL and queued message intact; a valid update of the parameter applies.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    stack_name = ctx.unique_name("sim2real-xsvc-cfnrb-stk-")
    queue_name = ctx.unique_name("sim2real-xsvc-cfnrb-q-")
    body = json.dumps(_TEMPLATE)

    cfn.create_stack(
        StackName=stack_name, TemplateBody=body,
        Parameters=_params(queue_name, "30"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    status = _wait_terminal(cfn, stack_name, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"stack create ended in {status!r}"

    queue_url = _output(cfn, stack_name, "QueueUrl")
    physical_before = _physical_id(cfn, stack_name)
    assert _visibility_timeout(sqs, queue_url) == "30", (
        f"VisibilityTimeout after create is {_visibility_timeout(sqs, queue_url)!r}, expected '30'"
    )
    sent = sqs.send_message(QueueUrl=queue_url, MessageBody="before-bad-update")

    # The parameter has no MinValue/MaxValue, so UpdateStack is accepted and the refusal comes
    # from the SQS resource during the update.
    cfn.update_stack(StackName=stack_name, TemplateBody=body,
                     Parameters=_params(queue_name, "50000"))
    status = _wait_terminal(cfn, stack_name, timeout_s=900.0)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"an update setting VisibilityTimeout=50000 ended in {status!r}, expected "
        "'UPDATE_ROLLBACK_COMPLETE' (SQS caps VisibilityTimeout at 43200)"
    )
    failed = [
        e for e in _events(cfn, stack_name)
        if e["LogicalResourceId"] == "Queue" and e["ResourceStatus"] == "UPDATE_FAILED"
    ]
    assert len(failed) >= 1, (
        f"no UPDATE_FAILED event for logical id 'Queue'; the rollback must be caused by the "
        f"queue resource. Queue events: "
        f"{[(e['ResourceStatus'], e.get('ResourceStatusReason')) for e in _events(cfn, stack_name) if e['LogicalResourceId'] == 'Queue']!r}"
    )

    # ---- the effect is absent: same queue, old attribute, message intact ----
    assert _physical_id(cfn, stack_name) == physical_before, (
        f"the queue's physical id changed across a rolled-back update: {physical_before!r} -> "
        f"{_physical_id(cfn, stack_name)!r}"
    )
    assert sqs.get_queue_url(QueueName=queue_name)["QueueUrl"] == queue_url, (
        "the queue no longer resolves to its original URL after the rollback"
    )
    assert _visibility_timeout(sqs, queue_url) == "30", (
        f"VisibilityTimeout is {_visibility_timeout(sqs, queue_url)!r} after a rolled-back "
        "update; it must still be '30'"
    )
    params = {p["ParameterKey"]: p["ParameterValue"]
              for p in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Parameters"]}
    assert params["VisibilityTimeout"] == "30", (
        f"stack parameter VisibilityTimeout is {params['VisibilityTimeout']!r} after rollback, "
        "expected the pre-update '30'"
    )
    received = _receive_id(sqs, queue_url, sent["MessageId"])
    assert received["Body"] == "before-bad-update", (
        f"message sent before the rejected update came back as {received['Body']!r}"
    )

    # ---- positive control: an in-range update of the SAME parameter applies ----
    cfn.update_stack(StackName=stack_name, TemplateBody=body,
                     Parameters=_params(queue_name, "45"))
    status = _wait_terminal(cfn, stack_name, timeout_s=900.0)
    assert status == "UPDATE_COMPLETE", (
        f"a valid VisibilityTimeout=45 update ended in {status!r}, expected 'UPDATE_COMPLETE'"
    )
    assert _visibility_timeout(sqs, queue_url) == "45", (
        f"VisibilityTimeout is {_visibility_timeout(sqs, queue_url)!r} after the valid update, "
        "expected '45'"
    )
    assert _physical_id(cfn, stack_name) == physical_before, (
        "a VisibilityTimeout update replaced the queue; it is an in-place property"
    )


_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "sim2real-xsvc rollback probe: one SQS queue",
    "Parameters": {
        "QueueName": {"Type": "String"},
        "VisibilityTimeout": {"Type": "Number"},
    },
    "Resources": {
        "Queue": {
            "Type": "AWS::SQS::Queue",
            "Properties": {
                "QueueName": {"Ref": "QueueName"},
                "VisibilityTimeout": {"Ref": "VisibilityTimeout"},
            },
        }
    },
    "Outputs": {"QueueUrl": {"Value": {"Ref": "Queue"}}},
}

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _params(queue_name: str, visibility_timeout: str) -> list[dict]:
    return [
        {"ParameterKey": "QueueName", "ParameterValue": queue_name},
        {"ParameterKey": "VisibilityTimeout", "ParameterValue": visibility_timeout},
    ]


def _wait_terminal(cfn, stack_name: str, *, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} not terminal after {timeout_s}s (last {status!r})")


def _events(cfn, stack_name: str) -> list[dict]:
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        out.extend(page["StackEvents"])
    return out


def _output(cfn, stack_name: str, key: str) -> str:
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    assert key in outputs, f"stack output {key!r} missing; outputs are {outputs!r}"
    return outputs[key]


def _physical_id(cfn, stack_name: str) -> str:
    return cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId="Queue"
    )["StackResourceDetail"]["PhysicalResourceId"]


def _visibility_timeout(sqs, queue_url: str) -> str:
    return sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"]
    )["Attributes"]["VisibilityTimeout"]


def _receive_id(sqs, queue_url: str, message_id: str) -> dict:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=5).get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if m["MessageId"] == message_id:
                return m
    raise AssertionError(f"message {message_id!r} was never received from {queue_url!r}")


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: delete the stack (and with it the queue) and wait for it to be gone."""
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError:
            return
        if status == "DELETE_FAILED":
            break
        time.sleep(5)
    raise RuntimeError(f"CloudFormation stack {stack_name} was not deleted")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
