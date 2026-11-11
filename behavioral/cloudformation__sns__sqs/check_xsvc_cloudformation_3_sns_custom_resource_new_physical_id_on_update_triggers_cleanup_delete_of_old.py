"""xsvc-cloudformation-3-sns-custom-resource-new-physical-id-on-update-triggers-cleanup-delete-of-old."""
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


CHECK = "xsvc-cloudformation-3-sns-custom-resource-new-physical-id-on-update-triggers-cleanup-delete-of-old"
GROUP = "deploy-custom-resource"
SERVICES = ["cloudformation", "sns", "sqs"]

STACK_TIMEOUT_S = 240.0
REQUEST_TIMEOUT_S = 150.0


def _template(topic_arn: str, name: str) -> str:
    return json.dumps(
        {
            "Resources": {
                "Thing": {"Type": "Custom::Versioned", "Properties": {"ServiceToken": topic_arn, "Name": name}}
            },
            "Outputs": {
                "Version": {"Value": {"Fn::GetAtt": ["Thing", "Version"]}},
                "Pid": {"Value": {"Ref": "Thing"}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:eventing",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A provider's Update response decides replacement: a NEW PhysicalResourceId makes
    CloudFormation send a cleanup Delete for the old id with the old properties; the same id
    sends no Delete.
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn, queue_url = _wire_topic_queue(ctx, sns, sqs)
    box = _Mailbox(sqs, queue_url)
    stacks: list[str] = []
    ctx.on_cleanup(lambda: _teardown(ctx, cfn, box, stacks))

    name1, name2, name3 = (ctx.unique_name(f"v{i}-") for i in (1, 2, 3))
    pid1, pid2 = ctx.unique_name("sim2real-cr-pid1-"), ctx.unique_name("sim2real-cr-pid2-")
    stack_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-xsvc-cfn3-repl-"),
        TemplateBody=_template(topic_arn, name1),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    stacks.append(stack_id)
    creq = box.get(lambda r: r["StackId"] == stack_id and r["RequestType"] == "Create", why="Create")
    assert _respond(ctx, creq, "SUCCESS", physical_id=pid1, data={"Version": "1"}) == 200, "Create response PUT failed"
    status = _poll_status(cfn, stack_id, why="create")
    assert status == "CREATE_COMPLETE", f"create: expected CREATE_COMPLETE, got {status!r}"

    # --- Update 1: provider answers with a NEW physical id -> replacement ------------------------
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(topic_arn, name2))
    ureq = box.get(lambda r: r["StackId"] == stack_id and r["RequestType"] == "Update", why="first Update")
    assert ureq["PhysicalResourceId"] == pid1, f"Update request PhysicalResourceId: expected {pid1!r}, got {ureq.get('PhysicalResourceId')!r}"
    assert ureq["ResourceProperties"] == {"ServiceToken": topic_arn, "Name": name2}, (
        f"Update ResourceProperties must be the NEW properties; got {ureq['ResourceProperties']!r}"
    )
    assert ureq["OldResourceProperties"] == {"ServiceToken": topic_arn, "Name": name1}, (
        f"Update OldResourceProperties must be the previous properties; got {ureq.get('OldResourceProperties')!r}"
    )
    assert _respond(ctx, ureq, "SUCCESS", physical_id=pid2, data={"Version": "2"}) == 200, "Update response PUT failed"

    dreq = box.get(lambda r: r["StackId"] == stack_id and r["RequestType"] == "Delete", why="cleanup Delete of the replaced id")
    assert dreq["PhysicalResourceId"] == pid1, (
        f"cleanup Delete must target the REPLACED id {pid1!r}; got {dreq.get('PhysicalResourceId')!r}"
    )
    assert dreq["ResourceProperties"] == {"ServiceToken": topic_arn, "Name": name1}, (
        f"cleanup Delete must carry the OLD properties; got {dreq['ResourceProperties']!r}"
    )
    cleanup_status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert cleanup_status == "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", (
        f"the old id is deleted during cleanup; stack status was {cleanup_status!r}"
    )
    assert _respond(ctx, dreq, "SUCCESS", physical_id=pid1) == 200, "cleanup Delete response PUT failed"
    status = _poll_status(cfn, stack_id, why="replacing update")
    assert status == "UPDATE_COMPLETE", f"replacing update: expected UPDATE_COMPLETE, got {status!r}"
    outs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    assert outs == {"Version": "2", "Pid": pid2}, f"after replacement outputs must follow the new response; got {outs!r}"

    # --- Update 2: provider keeps the id -> in place, no cleanup Delete --------------------------
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(topic_arn, name3))
    u2 = box.get(lambda r: r["StackId"] == stack_id and r["RequestType"] == "Update", why="second Update")
    assert u2["PhysicalResourceId"] == pid2, f"second Update PhysicalResourceId: expected {pid2!r}, got {u2.get('PhysicalResourceId')!r}"
    assert _respond(ctx, u2, "SUCCESS", physical_id=pid2, data={"Version": "3"}) == 200, "second Update response PUT failed"
    status = _poll_status(cfn, stack_id, why="in-place update")
    assert status == "UPDATE_COMPLETE", f"in-place update: expected UPDATE_COMPLETE, got {status!r}"
    # UPDATE_COMPLETE cannot be reached while a cleanup Delete is outstanding, so it is the barrier.
    box.pull()
    stray = [r for r in box.backlog if r["StackId"] == stack_id and r["RequestType"] == "Delete"]
    assert not stray, (
        f"an Update answered with the SAME physical id is in place and must not trigger a Delete; got "
        f"{[r.get('PhysicalResourceId') for r in stray]!r}"
    )
    outs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    assert outs == {"Version": "3", "Pid": pid2}, f"after the in-place update: got {outs!r}"


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
