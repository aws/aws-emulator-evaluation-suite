"""custom-resource-getatt-missing-data-key-fails."""
from __future__ import annotations

import json
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-resource-getatt-missing-data-key-fails"
GROUP = "deploy-custom-resource"
SERVICES = ["cloudformation", "sns", "sqs"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:eventing",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Fn::GetAtt on a key the provider's Data lacks fails the consuming resource with the exact
    attribute error, while GetAtt on a key it returned is delivered to the consumer's request.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref.html
    """
    cf = ctx.client("cloudformation")
    topic_arn, box = _provider(ctx)
    stacks: list[str] = []
    ctx.on_cleanup(lambda: _delete_stacks(ctx, cf, box, stacks))
    value = ctx.unique_name("v-")

    def create(attribute: str) -> str:
        template = json.dumps({
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Provider": {"Type": "Custom::Source", "Properties": {"ServiceToken": topic_arn}},
                "Consumer": {"Type": "Custom::Sink", "Properties": {
                    "ServiceToken": topic_arn, "Value": {"Fn::GetAtt": ["Provider", attribute]}}},
            },
        })
        stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-xsvc-crattr-"), TemplateBody=template,
                                   Tags=_TAGS)["StackId"]
        stacks.append(stack_id)
        return stack_id

    missing_attr = "Missing"
    good, bad = create("Present"), create(missing_attr)
    provider_requests = {}
    for stack_id in (good, bad):
        req = box.get(lambda r, s=stack_id: r["StackId"] == s and r["LogicalResourceId"] == "Provider"
                      and r["RequestType"] == "Create", why="Provider Create")
        provider_requests[stack_id] = req
        assert _respond(ctx, req, "SUCCESS", physical_id=ctx.unique_name("sim2real-cr-src-"),
                        data={"Present": value}) == 200, "Provider PUT failed"

    sink = box.get(lambda r: r["StackId"] == good and r["LogicalResourceId"] == "Consumer"
                   and r["RequestType"] == "Create", why="Consumer Create")
    assert sink["ResourceProperties"] == {"ServiceToken": topic_arn, "Value": value}, (
        f"GetAtt Provider.Present must deliver the provider's Data: {sink['ResourceProperties']!r}"
    )
    assert _respond(ctx, sink, "SUCCESS", physical_id=ctx.unique_name("sim2real-cr-sink-")) == 200, "Consumer PUT failed"
    done = _settle(cf, good)
    assert done["StackStatus"] == "CREATE_COMPLETE", f"the control stack: {done['StackStatus']!r}"

    delete = box.get(lambda r: r["StackId"] == bad and r["LogicalResourceId"] == "Provider"
                     and r["RequestType"] == "Delete", why="Provider rollback Delete")
    assert _respond(ctx, delete, "SUCCESS", physical_id=delete["PhysicalResourceId"]) == 200, "Delete PUT failed"
    final = _settle_answering(ctx, cf, box, bad)
    assert final["StackStatus"] == "ROLLBACK_COMPLETE", f"a missing Data key must roll back; got {final['StackStatus']!r}"
    reasons = [e.get("ResourceStatusReason") for e in _events(cf, bad)
               if e["LogicalResourceId"] == "Consumer" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(reasons) == 1, f"Consumer must fail exactly once; reasons {reasons!r}"
    request_id = provider_requests[bad]["RequestId"]
    want_reason = (
        f"CustomResource attribute error: Vendor response doesn't contain {missing_attr} attribute "
        f"in object {bad}|Provider|{request_id}"
    )
    assert reasons[0] == want_reason, f"the attribute error differs: expected {want_reason!r}, got {reasons[0]!r}"
    leaked = [r for r in box.pending + box.answered if r["StackId"] == bad and r["LogicalResourceId"] == "Consumer"]
    assert leaked == [], f"a consumer whose GetAtt failed must not be sent a request: {leaked!r}"


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
