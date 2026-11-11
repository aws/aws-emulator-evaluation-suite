"""custom-resource-response-over-4096-bytes-fails."""
from __future__ import annotations

import json
import re
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-resource-response-over-4096-bytes-fails"
GROUP = "deploy-custom-resource"
SERVICES = ["cloudformation", "sns", "sqs"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0
_LIMIT = 4096


def _sized(req: dict, physical_id: str, size: int) -> dict:
    """Response Data padded so the serialised response body is exactly ``size`` bytes."""
    body = {"Status": "SUCCESS", "PhysicalResourceId": physical_id, "StackId": req["StackId"],
            "RequestId": req["RequestId"], "LogicalResourceId": req["LogicalResourceId"], "Data": {"Pad": ""}}
    body["Data"]["Pad"] = "p" * (size - len(json.dumps(body).encode()))
    assert len(json.dumps(body).encode()) == size, "the padded response is not the requested size"
    return body["Data"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:eventing",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A provider response of exactly 4,096 bytes completes its custom resource; one of 4,097 bytes
    fails the next resource with the exact too-long reason, and the rollback deletes it under
    CloudFormation's own id before deleting the one it depended on.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref.html
    """
    cf = ctx.client("cloudformation")
    topic_arn, box = _provider(ctx)
    stacks: list[str] = []
    ctx.on_cleanup(lambda: _delete_stacks(ctx, cf, box, stacks))

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Fits": {"Type": "Custom::Sized", "Properties": {"ServiceToken": topic_arn, "ServiceTimeout": "120"}},
            "Overflows": {"Type": "Custom::Sized", "DependsOn": "Fits",
                          "Properties": {"ServiceToken": topic_arn, "ServiceTimeout": "120"}},
        },
    })
    stack_name = ctx.unique_name("sim2real-xsvc-crsize-")
    stack_id = cf.create_stack(StackName=stack_name, TemplateBody=template, Tags=_TAGS)["StackId"]
    stacks.append(stack_id)

    fits = box.get(lambda r: r["StackId"] == stack_id and r["LogicalResourceId"] == "Fits"
                   and r["RequestType"] == "Create", why="Fits Create")
    fits_id = ctx.unique_name("sim2real-cr-fits-")
    data = _sized(fits, fits_id, _LIMIT)
    assert _respond(ctx, fits, "SUCCESS", physical_id=fits_id, data=data) == 200, "Fits PUT failed"
    _await_status(cf, stack_id, "Fits", "CREATE_COMPLETE")

    over = box.get(lambda r: r["StackId"] == stack_id and r["LogicalResourceId"] == "Overflows"
                   and r["RequestType"] == "Create", why="Overflows Create")
    over_id = ctx.unique_name("sim2real-cr-over-")
    assert _respond(ctx, over, "SUCCESS", physical_id=over_id, data=_sized(over, over_id, _LIMIT + 1)) == 200, (
        "the PUT of the oversized response was refused by the presigned URL itself"
    )

    # The response was too long for CloudFormation to read a PhysicalResourceId from, so the
    # rollback still asks the provider to delete Overflows itself, under a CloudFormation-assigned
    # id, before it will move on to Fits.
    over_delete = box.get(lambda r: r["StackId"] == stack_id and r["LogicalResourceId"] == "Overflows"
                          and r["RequestType"] == "Delete", why="Overflows rollback Delete")
    early = [r["LogicalResourceId"] for r in box.pending
             if r["StackId"] == stack_id and r["LogicalResourceId"] == "Fits" and r["RequestType"] == "Delete"]
    assert early == [], f"the rollback asked to delete Fits before Overflows was deleted: {early!r}"
    over_delete_id = over_delete["PhysicalResourceId"]
    assert re.fullmatch(rf"{re.escape(stack_name)}-Overflows-[A-Z0-9]+", over_delete_id), (
        f"rollback Delete PhysicalResourceId is not a CloudFormation-assigned id: {over_delete_id!r}"
    )
    assert _respond(ctx, over_delete, "SUCCESS", physical_id=over_delete_id) == 200, (
        "Overflows rollback Delete PUT failed"
    )

    # The rollback deletes Fits next; answer that Delete so the stack can settle.
    delete = box.get(lambda r: r["StackId"] == stack_id and r["LogicalResourceId"] == "Fits"
                     and r["RequestType"] == "Delete", why="Fits rollback Delete")
    assert delete["PhysicalResourceId"] == fits_id, f"rollback Delete PhysicalResourceId: {delete!r}"
    assert _respond(ctx, delete, "SUCCESS", physical_id=fits_id) == 200, "Delete PUT failed"
    final = _settle_answering(ctx, cf, box, stack_id)
    assert final["StackStatus"] == "ROLLBACK_COMPLETE", f"an oversized response must roll back; got {final['StackStatus']!r}"
    reasons = [e.get("ResourceStatusReason") for e in _events(cf, stack_id)
               if e["LogicalResourceId"] == "Overflows" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert reasons == ["Response object is too long."], f"the oversized-response reason differs: {reasons!r}"


def _await_status(cf, stack_id: str, logical_id: str, status: str) -> None:
    """Poll DescribeStackResource until ``logical_id`` reaches ``status``."""
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        got = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)["StackResourceDetail"]
        if got["ResourceStatus"] == status:
            return
        if time.monotonic() > deadline or got["ResourceStatus"].endswith("_FAILED"):
            raise AssertionError(f"{logical_id} is {got['ResourceStatus']!r}: {got.get('ResourceStatusReason')!r}")
        time.sleep(2.0)


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
