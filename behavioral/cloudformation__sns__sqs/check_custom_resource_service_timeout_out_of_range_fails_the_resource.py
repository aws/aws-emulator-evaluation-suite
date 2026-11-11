"""custom-resource-service-timeout-out-of-range-fails-the-resource."""
from __future__ import annotations

import json
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-resource-service-timeout-out-of-range-fails-the-resource"
GROUP = "deploy-custom-resource"
SERVICES = ["cloudformation", "sns", "sqs"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:eventing",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """ServiceTimeout outside 1-14400 fails the custom resource with an exact reason before any request
    reaches the provider, while the boundary value 14400 is sent and completes when answered.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudformation-customresource.html
    """
    cf = ctx.client("cloudformation")
    topic_arn, box = _provider(ctx)
    stacks: list[str] = []
    ctx.on_cleanup(lambda: _delete_stacks(ctx, cf, box, stacks))

    def create(timeout: str) -> str:
        template = json.dumps({
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Thing": {"Type": "Custom::Bounded", "Properties": {
                "ServiceToken": topic_arn, "ServiceTimeout": timeout}}},
        })
        stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-xsvc-crrange-"), TemplateBody=template,
                                   Tags=_TAGS)["StackId"]
        stacks.append(stack_id)
        return stack_id

    control = create("14400")
    bad = {value: create(value) for value in ("0", "14401")}

    req = box.get(lambda r: r["StackId"] == control and r["RequestType"] == "Create", why="control Create")
    assert _respond(ctx, req, "SUCCESS", physical_id=ctx.unique_name("sim2real-cr-")) == 200, "control PUT failed"
    done = _settle(cf, control)
    assert done["StackStatus"] == "CREATE_COMPLETE", f"ServiceTimeout 14400 must deploy; got {done['StackStatus']!r}"

    for value, stack_id in bad.items():
        final = _settle_answering(ctx, cf, box, stack_id)
        assert final["StackStatus"] == "ROLLBACK_COMPLETE", (
            f"ServiceTimeout {value!r} must fail the create; got {final['StackStatus']!r}"
        )
        reasons = [e.get("ResourceStatusReason") for e in _events(cf, stack_id)
                   if e["LogicalResourceId"] == "Thing" and e["ResourceStatus"] == "CREATE_FAILED"]
        assert reasons == [
            "ServiceTimeout must be an integer between 1 and 14400 seconds"
        ], f"ServiceTimeout {value!r}: the failure reason differs: {reasons!r}"

    # The control's request arrived through the same topic, so a request for a refused stack would be here too.
    box.pull()
    leaked = [(r["RequestType"], r["StackId"]) for r in box.pending + box.answered if r["StackId"] in bad.values()]
    assert leaked == [], f"an out-of-range ServiceTimeout still reached the provider: {leaked!r}"


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


def _settle(cf, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"{stack_id} still {stack['StackStatus']!r} after {_DEADLINE_S}s")
        time.sleep(3.0)


def _settle_answering(ctx, cf, box: _Mailbox, stack_id: str) -> dict:
    """``_settle`` that answers SUCCESS to every request for ``stack_id`` meanwhile, keeping each in box.answered."""
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
