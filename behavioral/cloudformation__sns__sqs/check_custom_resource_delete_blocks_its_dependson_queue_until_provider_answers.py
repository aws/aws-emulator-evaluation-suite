"""custom-resource-delete-blocks-its-dependson-queue-until-provider-answers."""

from __future__ import annotations

import json
import time
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-resource-delete-blocks-its-dependson-queue-until-provider-answers"
GROUP = "deploy-custom-resource"
SERVICES = ["cloudformation", "sns", "sqs"]

_NO_SUCH_QUEUE = ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.")

_STACK_TIMEOUT_S = 240.0
_REQUEST_TIMEOUT_S = 150.0
_QUEUE_GONE_TIMEOUT_S = 180.0


def _template(topic_arn: str) -> str:
    """A queue a Custom::Probe DependsOn and Refs: the probe cannot create or delete first."""
    return json.dumps({
        "Parameters": {"DepName": {"Type": "String"}},
        "Resources": {
            "Dependency": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "DepName"}},
            },
            "Probe": {
                "Type": "Custom::Probe",
                "DependsOn": "Dependency",
                "Properties": {
                    "ServiceToken": topic_arn,
                    "DependencyQueueUrl": {"Ref": "Dependency"},
                },
            },
        },
        "Outputs": {
            "DependencyQueueUrl": {"Value": {"Ref": "Dependency"}},
        },
    })


def _provider_channel(ctx, sns, sqs) -> tuple[str, str]:
    """An SNS topic feeding an SQS queue, wired the way a custom resource provider listens."""
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-cr-order-t-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    inbox_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-cr-order-inbox-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=inbox_url))

    inbox_arn = sqs.get_queue_attributes(
        QueueUrl=inbox_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(
        QueueUrl=inbox_url,
        Attributes={"Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": inbox_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }],
        })},
    )
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=inbox_arn,
        Attributes={"RawMessageDelivery": "true"}, ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: _drop_subscription(sns, sub_arn))
    return topic_arn, inbox_url


def _drop_subscription(sns, sub_arn: str) -> None:
    try:
        sns.unsubscribe(SubscriptionArn=sub_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("NotFound", "InvalidParameter"):
            raise


def _drain(sqs, queue_url: str) -> list[dict[str, Any]]:
    """Every provider request currently sitting on the queue, removed as it is read."""
    found = []
    page = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    for msg in page.get("Messages", []):
        found.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return found


def _await_request(ctx, sqs, queue_url: str, stack_id: str, request_type: str,
                    timeout_s: float = _REQUEST_TIMEOUT_S) -> dict[str, Any]:
    """Poll the inbox until a provider request of ``request_type`` for ``stack_id`` arrives."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while time.monotonic() < deadline:
        for req in _drain(sqs, queue_url):
            if req.get("StackId") == stack_id and req.get("RequestType") == request_type:
                return req
        time.sleep(1.0)
    raise AssertionError(
        f"no {request_type} request for stack {stack_id!r} arrived within {timeout_s}s"
    )


def _answer(ctx, request: dict[str, Any], status: str, physical_id: str) -> int:
    """PUT a provider response to the request's presigned S3 ResponseURL; returns the HTTP status."""
    body = json.dumps({
        "Status": status,
        "PhysicalResourceId": physical_id,
        "StackId": request["StackId"],
        "RequestId": request["RequestId"],
        "LogicalResourceId": request["LogicalResourceId"],
    }).encode()
    target, headers = ctx.endpoint_route(request["ResponseURL"])
    put = urllib.request.Request(
        target, data=body, method="PUT", headers={**headers, "Content-Type": ""}
    )
    with urllib.request.urlopen(put, timeout=30) as resp:
        return resp.status


def _poll_stack_status(ctx, cfn, stack_id: str, terminal: set[str],
                       timeout_s: float = _STACK_TIMEOUT_S) -> str:
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(3.0)
    raise AssertionError(f"stack {stack_id!r} still {last!r} after {timeout_s}s")


def _resource_status(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId=logical_id
    )["StackResourceDetail"]["ResourceStatus"]


def _ordered_events(cfn, stack_id: str) -> list[dict[str, Any]]:
    """Every stack event, oldest first."""
    events: list[dict[str, Any]] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _queue_reachable(sqs, queue_url: str) -> bool:
    try:
        sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
        return True
    except ClientError:
        return False


def _await_queue_not_found(ctx, sqs, queue_url: str,
                           timeout_s: float = _QUEUE_GONE_TIMEOUT_S) -> tuple[str, str]:
    """Poll GetQueueAttributes until it raises; returns (Code, Message)."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while time.monotonic() < deadline:
        try:
            sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        time.sleep(3.0)
    raise AssertionError(f"queue {queue_url!r} still resolved after {timeout_s}s")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:eventing",
      "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """DeleteStack holds a DependsOn+Ref'd queue alive while its SNS-backed custom resource's
    own Delete is still pending, and only starts deleting the queue once the provider answers.
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn, inbox_url = _provider_channel(ctx, sns, sqs)

    stack_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-behav-cr-order-"),
        TemplateBody=_template(topic_arn),
        Parameters=[{"ParameterKey": "DepName", "ParameterValue": ctx.unique_name("sim2real-behav-cr-order-q-")}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _finish_stack(ctx, cfn, sqs, inbox_url, stack_id))

    probe_pid = ctx.unique_name("sim2real-cr-probe-pid-")
    creq = _await_request(ctx, sqs, inbox_url, stack_id, "Create")
    assert creq["LogicalResourceId"] == "Probe", f"create request for {creq['LogicalResourceId']!r}, expected Probe"
    assert _answer(ctx, creq, "SUCCESS", probe_pid) == 200, "PUT of the Create response failed"

    created = _poll_stack_status(ctx, cfn, stack_id, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})
    assert created == "CREATE_COMPLETE", f"stack ended {created!r} before the delete phase could run"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]
    }
    dep_url = outputs["DependencyQueueUrl"]
    assert _queue_reachable(sqs, dep_url), f"Dependency queue {dep_url!r} unreachable right after CREATE_COMPLETE"

    # --- DeleteStack: Probe's own Delete must be pending before Dependency is touched -----------
    cfn.delete_stack(StackName=stack_id)
    dreq = _await_request(ctx, sqs, inbox_url, stack_id, "Delete")
    assert dreq["LogicalResourceId"] == "Probe", f"delete request for {dreq['LogicalResourceId']!r}, expected Probe"
    assert dreq["PhysicalResourceId"] == probe_pid, (
        f"Delete request PhysicalResourceId: expected {probe_pid!r}, got {dreq.get('PhysicalResourceId')!r}"
    )

    # 1. the queue is untouched while Probe's delete is still pending
    assert _queue_reachable(sqs, dep_url), (
        f"Dependency queue {dep_url!r} became unreachable before Probe's Delete was answered"
    )
    # 2. Probe is mid-delete, Dependency is not
    probe_mid = _resource_status(cfn, stack_id, "Probe")
    assert probe_mid == "DELETE_IN_PROGRESS", f"Probe status before the answer: expected DELETE_IN_PROGRESS, got {probe_mid!r}"
    dep_mid = _resource_status(cfn, stack_id, "Dependency")
    assert dep_mid == "CREATE_COMPLETE", f"Dependency status before Probe's delete finished: expected CREATE_COMPLETE, got {dep_mid!r}"
    # 3. no DELETE_IN_PROGRESS event for Dependency exists yet
    pending_events = _ordered_events(cfn, stack_id)
    early_dep_delete = [
        e for e in pending_events
        if e["LogicalResourceId"] == "Dependency" and e["ResourceStatus"] == "DELETE_IN_PROGRESS"
    ]
    assert early_dep_delete == [], (
        f"a Dependency DELETE_IN_PROGRESS event already exists before Probe's delete was answered: {early_dep_delete!r}"
    )

    assert _answer(ctx, dreq, "SUCCESS", probe_pid) == 200, "PUT of the Delete response failed"

    deleted = _poll_stack_status(ctx, cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert deleted == "DELETE_COMPLETE", f"stack ended {deleted!r} after the Delete was answered"

    # 4. Probe's DELETE_COMPLETE precedes Dependency's DELETE_IN_PROGRESS in the event stream
    events = _ordered_events(cfn, stack_id)
    probe_done_idx = [
        i for i, e in enumerate(events)
        if e["LogicalResourceId"] == "Probe" and e["ResourceStatus"] == "DELETE_COMPLETE"
    ]
    dep_start_idx = [
        i for i, e in enumerate(events)
        if e["LogicalResourceId"] == "Dependency" and e["ResourceStatus"] == "DELETE_IN_PROGRESS"
    ]
    assert len(probe_done_idx) == 1, f"expected exactly one Probe DELETE_COMPLETE event, got {len(probe_done_idx)}"
    assert len(dep_start_idx) == 1, f"expected exactly one Dependency DELETE_IN_PROGRESS event, got {len(dep_start_idx)}"
    assert probe_done_idx[0] < dep_start_idx[0], (
        f"Probe DELETE_COMPLETE was event #{probe_done_idx[0]}, Dependency DELETE_IN_PROGRESS was "
        f"event #{dep_start_idx[0]}; the dependent's delete must finish first"
    )

    # 5. the queue is really gone, not merely unordered in the response
    code = _await_queue_not_found(ctx, sqs, dep_url)
    assert code == _NO_SUCH_QUEUE, f"GetQueueAttributes on the deleted queue returned {code!r}, expected {_NO_SUCH_QUEUE!r}"


def _finish_stack(ctx, cfn, sqs, inbox_url: str, stack_id: str) -> None:
    """Delete the stack, answering SUCCESS to any provider request still outstanding."""
    deadline = time.monotonic() + 200.0
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if not status.endswith("_IN_PROGRESS"):
            cfn.delete_stack(StackName=stack_id)
        for req in _drain(sqs, inbox_url):
            _answer(ctx, req, "SUCCESS", req.get("PhysicalResourceId") or "sim2real-cleanup")
        time.sleep(2.0)
    raise AssertionError(f"stack {stack_id!r} not DELETE_COMPLETE within the cleanup budget")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
