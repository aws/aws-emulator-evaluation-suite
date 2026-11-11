"""custom-resource-service-timeout-fails-create."""
from __future__ import annotations

import json
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-resource-service-timeout-fails-create"
GROUP = "deploy-custom-resource"
SERVICES = ["cloudformation", "sns", "sqs"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_SERVICE_TIMEOUT = 5
_DEADLINE_S = 240.0


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudformation-customresource.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:eventing",
      "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A custom resource whose provider never answers fails once its ServiceTimeout elapses, with the
    exact no-response reason naming the Create request, and the rollback sends a Delete for it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudformation-customresource.html
    """
    cf = ctx.client("cloudformation")
    topic_arn, box = _provider(ctx)
    stacks: list[str] = []
    ctx.on_cleanup(lambda: _delete_stacks(ctx, cf, box, stacks))

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Slow": {"Type": "Custom::Slow", "Properties": {
            "ServiceToken": topic_arn, "ServiceTimeout": str(_SERVICE_TIMEOUT)}}},
    })
    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-xsvc-crtimeout-"), TemplateBody=template,
                               Tags=_TAGS)["StackId"]
    stacks.append(stack_id)

    create = box.get(lambda r: r["StackId"] == stack_id and r["RequestType"] == "Create", why="Create request")
    assert create["ResourceProperties"] == {"ServiceToken": topic_arn, "ServiceTimeout": str(_SERVICE_TIMEOUT)}, (
        f"Create ResourceProperties: {create['ResourceProperties']!r}"
    )

    # Never answer the Create; answer the rollback's Delete so the stack can settle.
    delete = box.get(lambda r: r["StackId"] == stack_id and r["RequestType"] == "Delete", why="rollback Delete")
    assert delete["LogicalResourceId"] == "Slow", f"rollback Delete LogicalResourceId: {delete['LogicalResourceId']!r}"
    assert _respond(ctx, delete, "SUCCESS", physical_id=delete["PhysicalResourceId"]) == 200, "Delete PUT failed"

    final = _settle_answering(ctx, cf, box, stack_id)
    assert final["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"an unanswered custom resource must roll the create back; got {final['StackStatus']!r}"
    )
    events = _events(cf, stack_id)
    failed = [e for e in events if e["LogicalResourceId"] == "Slow" and e["ResourceStatus"] == "CREATE_FAILED"]
    reasons = [e.get("ResourceStatusReason") for e in failed]
    assert reasons == [
        "CloudFormation did not receive a response from your Custom Resource. Please check your logs for "
        f"requestId [{create['RequestId']}]. If you are using the Python cfn-response module, you may need to "
        "update your Lambda function code so that CloudFormation can attach the updated version."
    ], f"the timeout reason differs: {reasons!r}"
    started = [e["Timestamp"] for e in events
               if e["LogicalResourceId"] == "Slow" and e["ResourceStatus"] == "CREATE_IN_PROGRESS"]
    waited = (failed[0]["Timestamp"] - min(started)).total_seconds()
    assert waited >= _SERVICE_TIMEOUT, (
        f"the resource failed {waited:.1f}s after it started, before its {_SERVICE_TIMEOUT}s ServiceTimeout"
    )


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, except the named not-found codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _provider(ctx):
    """An SNS topic delivering raw custom-resource requests to an SQS queue the check reads."""
    sns, sqs = ctx.client("sns"), ctx.client("sqs")
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-cr-t-"), Tags=_TAGS)["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=topic_arn), "NotFound"))
    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-cr-q-"),
                                 tags={"sim2real-check": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=queue_url), "AWS.SimpleQueueService.NonExistentQueue"))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage",
            "Resource": queue_arn, "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    })})
    sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
                        Attributes={"RawMessageDelivery": "true"}, ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(_teardown(lambda: sns.unsubscribe(SubscriptionArn=sub), "NotFound"))
    return topic_arn, _Mailbox(sqs, queue_url)


class _Mailbox:
    """Provider-request inbox: requests that do not match the current wait are kept, not dropped."""

    def __init__(self, sqs, queue_url: str):
        self.sqs, self.queue_url, self.pending, self.answered = sqs, queue_url, [], []

    def pull(self) -> None:
        resp = self.sqs.receive_message(QueueUrl=self.queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            self.pending.append(json.loads(msg["Body"]))
            self.sqs.delete_message(QueueUrl=self.queue_url, ReceiptHandle=msg["ReceiptHandle"])

    def get(self, pred, *, why: str, timeout_s: float = _DEADLINE_S):
        deadline = time.monotonic() + timeout_s
        while True:
            for i, req in enumerate(self.pending):
                if pred(req):
                    return self.pending.pop(i)
            if time.monotonic() > deadline:
                raise AssertionError(f"no provider request [{why}] within {timeout_s}s; pending {self.pending!r}")
            self.pull()


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _respond(ctx, req: dict, status: str, *, physical_id: str, data: dict | None = None) -> int:
    """PUT a provider response to the request's presigned ResponseURL; returns the HTTP status."""
    body = {"Status": status, "PhysicalResourceId": physical_id, "StackId": req["StackId"],
            "RequestId": req["RequestId"], "LogicalResourceId": req["LogicalResourceId"]}
    if data is not None:
        body["Data"] = data
    target, route = ctx.endpoint_route(req["ResponseURL"])
    put = urllib.request.Request(target, data=json.dumps(body).encode(), method="PUT",
                                 headers={"Content-Type": "", **route})
    with urllib.request.urlopen(put, timeout=30, context=_ssl_context(ctx.http_verify)) as resp:
        return resp.status


def _settle_answering(ctx, cf, box: _Mailbox, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until not *_IN_PROGRESS, answering SUCCESS to every request for
    ``stack_id`` meanwhile and keeping each in box.answered."""
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"{stack_id} still {stack['StackStatus']!r} after {_DEADLINE_S}s")
        box.pull()
        for req in [r for r in box.pending if r["StackId"] == stack_id]:
            box.pending.remove(req)
            box.answered.append(req)
            _respond(ctx, req, "SUCCESS", physical_id=req.get("PhysicalResourceId") or req["RequestId"])


def _events(cf, stack_id: str) -> list:
    return [e for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
            for e in page["StackEvents"]]


def _delete_stacks(ctx, cf, box: _Mailbox, stacks: list[str]) -> None:
    """Delete every stack, answering SUCCESS to each provider request; raises unless all DELETE_COMPLETE."""
    deadline = time.monotonic() + _DEADLINE_S
    remaining = list(stacks)
    for sid in remaining:
        if not cf.describe_stacks(StackName=sid)["Stacks"][0]["StackStatus"].endswith("_IN_PROGRESS"):
            cf.delete_stack(StackName=sid)
    while remaining:
        for sid in list(remaining):
            status = cf.describe_stacks(StackName=sid)["Stacks"][0]["StackStatus"]
            if status == "DELETE_COMPLETE":
                remaining.remove(sid)
            elif status == "DELETE_FAILED":
                raise AssertionError(f"stack {sid} is DELETE_FAILED")
            elif not status.endswith("_IN_PROGRESS"):
                cf.delete_stack(StackName=sid)
        box.pull()
        while box.pending:
            req = box.pending.pop()
            _respond(ctx, req, "SUCCESS", physical_id=req.get("PhysicalResourceId") or req["RequestId"])
        if remaining and time.monotonic() > deadline:
            raise AssertionError(f"stacks not deleted within {_DEADLINE_S}s: {remaining!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
