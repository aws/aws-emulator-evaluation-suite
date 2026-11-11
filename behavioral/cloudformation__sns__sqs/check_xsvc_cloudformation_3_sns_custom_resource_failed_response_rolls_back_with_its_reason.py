"""xsvc-cloudformation-3-sns-custom-resource-failed-response-rolls-back-with-its-reason."""
from __future__ import annotations

import json
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "xsvc-cloudformation-3-sns-custom-resource-failed-response-rolls-back-with-its-reason"
GROUP = "deploy-custom-resource"
SERVICES = ["cloudformation", "sns", "sqs"]

STACK_TIMEOUT_S = 240.0
REQUEST_TIMEOUT_S = 150.0


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:eventing",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A provider that answers FAILED with a Reason makes the resource CREATE_FAILED with that
    reason, rolls the stack back, and the rollback sends Delete for the id the provider returned;
    a control stack answered SUCCESS reaches CREATE_COMPLETE, so only the Status field differs.
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn, queue_url = _wire_topic_queue(ctx, sns, sqs)
    box = _Mailbox(sqs, queue_url)
    stacks: list[str] = []
    ctx.on_cleanup(lambda: _teardown(ctx, cfn, box, stacks))

    template = json.dumps(
        {
            "Resources": {
                "Thing": {
                    "Type": "Custom::Verdict",
                    "Properties": {"ServiceToken": topic_arn, "Marker": ctx.unique_name("m-")},
                }
            },
            "Outputs": {"Greeting": {"Value": {"Fn::GetAtt": ["Thing", "Greeting"]}}},
        }
    )
    stack_tags = [{"Key": "sim2real-check", "Value": CHECK}]
    control_id = cfn.create_stack(StackName=ctx.unique_name("sim2real-xsvc-cfn3-ok-"), TemplateBody=template, Tags=stack_tags)["StackId"]
    stacks.append(control_id)
    failed_id = cfn.create_stack(StackName=ctx.unique_name("sim2real-xsvc-cfn3-fail-"), TemplateBody=template, Tags=stack_tags)["StackId"]
    stacks.append(failed_id)

    reason = ctx.unique_name("sim2real deliberate provider failure ")
    failed_pid = ctx.unique_name("sim2real-cr-failed-pid-")
    greeting = ctx.unique_name("hello-")

    creq = box.get(lambda r: r["StackId"] == control_id and r["RequestType"] == "Create", why="control Create")
    freq = box.get(lambda r: r["StackId"] == failed_id and r["RequestType"] == "Create", why="subject Create")
    assert _respond(ctx, creq, "SUCCESS", physical_id=ctx.unique_name("sim2real-cr-ok-pid-"), data={"Greeting": greeting}) == 200, (
        "PUT of the control's SUCCESS response failed"
    )
    assert _respond(ctx, freq, "FAILED", physical_id=failed_pid, reason=reason) == 200, (
        "PUT of the subject's FAILED response failed"
    )

    # --- Positive control: same template, same topic, answered SUCCESS ---------------------------
    status = _poll_status(cfn, control_id, why="control create")
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    outs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=control_id)["Stacks"][0]["Outputs"]}
    assert outs == {"Greeting": greeting}, f"control stack outputs: expected {{'Greeting': {greeting!r}}}, got {outs!r}"

    # --- The rollback must ask the provider to delete what it said it had made -------------------
    dreq = box.get(lambda r: r["StackId"] == failed_id and r["RequestType"] == "Delete", why="rollback Delete")
    assert dreq["PhysicalResourceId"] == failed_pid, (
        f"rollback Delete PhysicalResourceId: expected the id returned with FAILED ({failed_pid!r}), "
        f"got {dreq.get('PhysicalResourceId')!r}"
    )
    rolling = cfn.describe_stacks(StackName=failed_id)["Stacks"][0]["StackStatus"]
    assert rolling == "ROLLBACK_IN_PROGRESS", f"before the rollback Delete is answered: expected ROLLBACK_IN_PROGRESS, got {rolling!r}"
    assert _respond(ctx, dreq, "SUCCESS", physical_id=failed_pid) == 200, "PUT of the rollback Delete response failed"

    status = _poll_status(cfn, failed_id, why="subject rollback")
    assert status == "ROLLBACK_COMPLETE", f"a FAILED provider response must roll the stack back; got {status!r}"
    failed_stack = cfn.describe_stacks(StackName=failed_id)["Stacks"][0]
    assert not failed_stack.get("Outputs"), f"a rolled-back stack resolves no outputs; got {failed_stack.get('Outputs')!r}"

    events = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=failed_id):
        events.extend(page["StackEvents"])
    create_failed = [e for e in events if e["LogicalResourceId"] == "Thing" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(create_failed) == 1, f"expected exactly one CREATE_FAILED event for Thing, got {len(create_failed)}"
    want_reason = (
        f"Received response status [FAILED] from custom resource. Message returned: {reason} "
        f"(RequestId: {freq['RequestId']})"
    )
    assert create_failed[0].get("ResourceStatusReason") == want_reason, (
        f"CREATE_FAILED reason: expected {want_reason!r}, got {create_failed[0].get('ResourceStatusReason')!r}"
    )
    assert create_failed[0].get("PhysicalResourceId") == failed_pid, (
        f"CREATE_FAILED PhysicalResourceId: expected {failed_pid!r}, got {create_failed[0].get('PhysicalResourceId')!r}"
    )
    rollback_start = [e for e in events if e["LogicalResourceId"] == failed_stack["StackName"] and e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS"]
    assert rollback_start and rollback_start[0].get("ResourceStatusReason") == (
        "The following resource(s) failed to create: [Thing]. Rollback requested by user."
    ), f"stack ROLLBACK_IN_PROGRESS reason: got {[e.get('ResourceStatusReason') for e in rollback_start]!r}"
    deleted = [e for e in events if e["LogicalResourceId"] == "Thing" and e["ResourceStatus"] == "DELETE_COMPLETE"]
    assert deleted, "the rollback never recorded Thing DELETE_COMPLETE"


# ===== helpers =====


def _wire_topic_queue(ctx, sns, sqs):
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-cfn3-t-"), Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-cfn3-q-"), tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                        }
                    ],
                }
            )
        },
    )
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"}, ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: sns.unsubscribe(SubscriptionArn=sub_arn)))
    return topic_arn, queue_url


class _Mailbox:
    """Provider-request inbox: requests that do not match the current wait are kept, not dropped."""

    def __init__(self, sqs, queue_url: str):
        self.sqs, self.queue_url, self.backlog = sqs, queue_url, []

    def pull(self) -> None:
        resp = self.sqs.receive_message(QueueUrl=self.queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            self.backlog.append(json.loads(msg["Body"]))
            self.sqs.delete_message(QueueUrl=self.queue_url, ReceiptHandle=msg["ReceiptHandle"])

    def take(self, pred):
        for i, req in enumerate(self.backlog):
            if pred(req):
                return self.backlog.pop(i)
        return None

    def get(self, pred, *, why: str, timeout_s: float = REQUEST_TIMEOUT_S):
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            hit = self.take(pred)
            if hit is not None:
                return hit
            self.pull()
        raise AssertionError(
            f"no provider request [{why}] arrived within {timeout_s}s; backlog held "
            f"{[(r.get('RequestType'), r.get('LogicalResourceId')) for r in self.backlog]!r}"
        )


def _respond(ctx, req: dict, status: str, *, physical_id: str, data: dict | None = None, reason: str | None = None) -> int:
    body = {
        "Status": status,
        "PhysicalResourceId": physical_id,
        "StackId": req["StackId"],
        "RequestId": req["RequestId"],
        "LogicalResourceId": req["LogicalResourceId"],
    }
    if data is not None:
        body["Data"] = data
    if reason is not None:
        body["Reason"] = reason
    put = _routed_request(ctx,
        req["ResponseURL"], data=json.dumps(body).encode(), method="PUT", headers={"Content-Type": ""}
    )
    with urllib.request.urlopen(put, timeout=30) as resp:
        return resp.status


def _poll_status(cfn, stack_id: str, *, why: str) -> str:
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if not last.endswith("_IN_PROGRESS"):
            return last
        time.sleep(3.0)
    raise AssertionError(f"stack {stack_id!r} still {last!r} after {STACK_TIMEOUT_S}s [{why}]")


def _teardown(ctx, cfn, box: _Mailbox, stacks: list[str]) -> None:
    """Delete every stack, answering SUCCESS to any provider request so none waits an hour."""
    deadline = time.monotonic() + 200.0
    remaining = list(stacks)
    errors: list[str] = []
    while remaining and time.monotonic() < deadline:
        for sid in list(remaining):
            status = cfn.describe_stacks(StackName=sid)["Stacks"][0]["StackStatus"]
            if status == "DELETE_COMPLETE":
                remaining.remove(sid)
            elif not status.endswith("_IN_PROGRESS"):
                cfn.delete_stack(StackName=sid)
        box.pull()
        while box.backlog:
            req = box.backlog.pop()
            try:
                _respond(ctx, req, "SUCCESS", physical_id=req.get("PhysicalResourceId") or "sim2real-cleanup")
            except OSError as exc:  # URLError/HTTPError: keep answering the rest, report at the end
                errors.append(f"could not answer {req.get('RequestType')} for {req.get('StackId')}: {exc}")
    if remaining or errors:
        raise RuntimeError(f"stacks not deleted within the teardown budget: {remaining!r}; answer errors: {errors!r}")


def _ignore_missing(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in {"NotFound", "InvalidParameter"}:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
