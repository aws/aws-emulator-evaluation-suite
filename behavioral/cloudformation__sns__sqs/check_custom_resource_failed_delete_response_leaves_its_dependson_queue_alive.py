"""custom-resource-failed-delete-response-leaves-its-dependson-queue-alive."""

from __future__ import annotations

import json
import time
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-resource-failed-delete-response-leaves-its-dependson-queue-alive"
GROUP = "deploy-custom-resource"
SERVICES = ["cloudformation", "sns", "sqs"]

_STACK_TIMEOUT_S = 240.0
_REQUEST_TIMEOUT_S = 150.0
_QUEUE_GONE_TIMEOUT_S = 180.0


def _template(topic_arn: str) -> str:
    """A queue a Custom::Probe DependsOn and Refs: a stuck Probe delete must not reach it."""
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
        Name=ctx.unique_name("sim2real-behav-cr-fail-t-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    inbox_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-cr-fail-inbox-"),
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
                    seen_request_ids: set[str], timeout_s: float = _REQUEST_TIMEOUT_S) -> dict[str, Any]:
    """Poll the inbox for a NEW ``request_type`` request for ``stack_id`` (unseen RequestId)."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while time.monotonic() < deadline:
        for req in _drain(sqs, queue_url):
            if (req.get("StackId") == stack_id and req.get("RequestType") == request_type
                    and req.get("RequestId") not in seen_request_ids):
                seen_request_ids.add(req["RequestId"])
                return req
        time.sleep(1.0)
    raise AssertionError(
        f"no new {request_type} request for stack {stack_id!r} arrived within {timeout_s}s"
    )


def _answer(ctx, request: dict[str, Any], status: str, physical_id: str, *, reason: str | None = None) -> int:
    """PUT a provider response to the request's presigned S3 ResponseURL; returns the HTTP status."""
    body: dict[str, Any] = {
        "Status": status,
        "PhysicalResourceId": physical_id,
        "StackId": request["StackId"],
        "RequestId": request["RequestId"],
        "LogicalResourceId": request["LogicalResourceId"],
    }
    if reason is not None:
        body["Reason"] = reason
    target, headers = ctx.endpoint_route(request["ResponseURL"])
    put = urllib.request.Request(
        target, data=json.dumps(body).encode(), method="PUT", headers={**headers, "Content-Type": ""}
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


def _resource_status(cfn, stack_id: str, logical_id: str) -> dict[str, Any]:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)["StackResourceDetail"]


def _queue_reachable(sqs, queue_url: str) -> bool:
    try:
        sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
        return True
    except ClientError:
        return False


def _await_queue_not_found(ctx, sqs, queue_url: str,
                           timeout_s: float = _QUEUE_GONE_TIMEOUT_S) -> tuple[str, str]:
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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:eventing",
      "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A FAILED Delete response for a custom resource leaves the stack DELETE_FAILED and never
    starts deleting the queue it DependsOn and Refs; answering SUCCESS afterwards deletes both.
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn, inbox_url = _provider_channel(ctx, sns, sqs)
    seen_request_ids: set[str] = set()

    stack_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-behav-cr-fail-"),
        TemplateBody=_template(topic_arn),
        Parameters=[{"ParameterKey": "DepName", "ParameterValue": ctx.unique_name("sim2real-behav-cr-fail-q-")}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _finish_stack(ctx, cfn, sqs, inbox_url, stack_id))

    probe_pid = ctx.unique_name("sim2real-cr-probe-pid-")

    # --- positive control: the provider answers the Create normally -----------------------------
    creq = _await_request(ctx, sqs, inbox_url, stack_id, "Create", seen_request_ids)
    assert _answer(ctx, creq, "SUCCESS", probe_pid) == 200, "PUT of the Create response failed"
    created = _poll_stack_status(ctx, cfn, stack_id, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})
    assert created == "CREATE_COMPLETE", f"stack ended {created!r} before the delete phase could run"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]
    }
    dep_url = outputs["DependencyQueueUrl"]
    assert _queue_reachable(sqs, dep_url), f"Dependency queue {dep_url!r} unreachable right after CREATE_COMPLETE"

    # --- break exactly one thing: the provider FAILS the Delete ----------------------------------
    cfn.delete_stack(StackName=stack_id)
    dreq = _await_request(ctx, sqs, inbox_url, stack_id, "Delete", seen_request_ids)
    reason = ctx.unique_name("sim2real deliberate provider failure ")
    assert _answer(ctx, dreq, "FAILED", probe_pid, reason=reason) == 200, "PUT of the FAILED response failed"

    failed = _poll_stack_status(ctx, cfn, stack_id, {"DELETE_FAILED", "DELETE_COMPLETE"})
    assert failed == "DELETE_FAILED", f"a FAILED provider response must leave the stack DELETE_FAILED, got {failed!r}"

    # the specific error, built only from values this check knows
    probe_detail = _resource_status(cfn, stack_id, "Probe")
    assert probe_detail["ResourceStatus"] == "DELETE_FAILED", (
        f"Probe status: expected DELETE_FAILED, got {probe_detail['ResourceStatus']!r}"
    )
    want_reason = (
        f"Received response status [FAILED] from custom resource. Message returned: {reason} "
        f"(RequestId: {dreq['RequestId']})"
    )
    assert probe_detail.get("ResourceStatusReason") == want_reason, (
        f"Probe DELETE_FAILED reason: expected {want_reason!r}, got {probe_detail.get('ResourceStatusReason')!r}"
    )

    # effect absent: the dependent queue was never touched
    dep_detail = _resource_status(cfn, stack_id, "Dependency")
    assert dep_detail["ResourceStatus"] == "CREATE_COMPLETE", (
        f"Dependency status after Probe's delete failed: expected CREATE_COMPLETE, got {dep_detail['ResourceStatus']!r}"
    )
    assert _queue_reachable(sqs, dep_url), (
        f"Dependency queue {dep_url!r} became unreachable even though its DependsOn parent never finished deleting"
    )

    # --- restore: the identical DeleteStack call, answered SUCCESS, now succeeds -----------------
    cfn.delete_stack(StackName=stack_id)
    dreq2 = _await_request(ctx, sqs, inbox_url, stack_id, "Delete", seen_request_ids)
    assert dreq2["PhysicalResourceId"] == probe_pid, (
        f"retried Delete request PhysicalResourceId: expected {probe_pid!r}, got {dreq2.get('PhysicalResourceId')!r}"
    )
    assert _answer(ctx, dreq2, "SUCCESS", probe_pid) == 200, "PUT of the restored SUCCESS response failed"

    deleted = _poll_stack_status(ctx, cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert deleted == "DELETE_COMPLETE", f"stack ended {deleted!r} after the retried Delete was answered SUCCESS"
    code = _await_queue_not_found(ctx, sqs, dep_url)
    assert code == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
        f"GetQueueAttributes on the deleted queue returned {code!r}"
    )


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
