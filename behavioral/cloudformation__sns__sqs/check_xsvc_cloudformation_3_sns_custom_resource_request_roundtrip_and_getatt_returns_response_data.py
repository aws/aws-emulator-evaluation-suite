"""xsvc-cloudformation-3-sns-custom-resource-request-roundtrip-and-getatt-returns-response-data."""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "xsvc-cloudformation-3-sns-custom-resource-request-roundtrip-and-getatt-returns-response-data"
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
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An SNS-backed custom resource: CloudFormation publishes the request with stringified
    properties and waits; the PUT response's Data becomes Fn::GetAtt and its PhysicalResourceId
    becomes Ref; DeleteStack sends a Delete carrying that id and blocks on its answer.
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn, queue_url = _wire_topic_queue(ctx, sns, sqs)
    box = _Mailbox(sqs, queue_url)
    stacks: list[str] = []
    ctx.on_cleanup(lambda: _teardown(ctx, cfn, box, stacks))

    marker = ctx.unique_name("n-")
    greeting = ctx.unique_name("hello-")
    physical_id = ctx.unique_name("sim2real-cr-pid-")
    template = json.dumps(
        {
            "Resources": {
                "Thing": {
                    "Type": "Custom::Greeter",
                    "Properties": {
                        "ServiceToken": topic_arn,
                        "Name": marker,
                        "Count": 3,
                        "Flag": True,
                        "Nested": {"a": [1, "x"]},
                    },
                }
            },
            "Outputs": {
                "Greeting": {"Value": {"Fn::GetAtt": ["Thing", "Greeting"]}},
                "Second": {"Value": {"Fn::GetAtt": ["Thing", "Second"]}},
                "Pid": {"Value": {"Ref": "Thing"}},
            },
        }
    )
    stack_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-xsvc-cfn3-cr-"),
        TemplateBody=template,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    stacks.append(stack_id)

    # --- The Create request, read at the far end --------------------------------------------------
    req = box.get(lambda r: r["StackId"] == stack_id and r["RequestType"] == "Create", why="Create request")
    assert req["ServiceToken"] == topic_arn, f"request ServiceToken: expected {topic_arn!r}, got {req['ServiceToken']!r}"
    assert req["LogicalResourceId"] == "Thing", f"request LogicalResourceId: got {req['LogicalResourceId']!r}"
    assert req["ResourceType"] == "Custom::Greeter", f"request ResourceType: got {req['ResourceType']!r}"
    assert "PhysicalResourceId" not in req, (
        f"a Create request has no physical id yet; got {req.get('PhysicalResourceId')!r}"
    )
    want_props = {
        "ServiceToken": topic_arn,
        "Name": marker,
        "Count": "3",
        "Flag": "true",
        "Nested": {"a": ["1", "x"]},
    }
    assert req["ResourceProperties"] == want_props, (
        f"ResourceProperties must round-trip with every scalar stringified; expected {want_props!r}, "
        f"got {req['ResourceProperties']!r}"
    )
    url = urllib.parse.urlsplit(req["ResponseURL"])
    assert not (p := ctx.published_url_mismatch(req["ResponseURL"])), p
    assert urllib.parse.parse_qs(url.query), f"ResponseURL carries no presigning query: {req['ResponseURL'][:120]!r}"

    pending = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert pending == "CREATE_IN_PROGRESS", (
        f"until the provider answers the stack must wait in CREATE_IN_PROGRESS; got {pending!r}"
    )

    status_code = _respond(ctx, req, "SUCCESS", physical_id=physical_id, data={"Greeting": greeting, "Second": "two"})
    assert status_code == 200, f"PUT to ResponseURL returned HTTP {status_code!r}"

    status = _poll_status(cfn, stack_id, why="create")
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE after a SUCCESS response, got {status!r}"
    outputs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    assert outputs.get("Greeting") == greeting, (
        f"Fn::GetAtt Thing.Greeting must equal the response Data; expected {greeting!r}, got {outputs!r}"
    )
    assert outputs.get("Second") == "two", f"Fn::GetAtt Thing.Second: expected 'two', got {outputs!r}"
    assert outputs.get("Pid") == physical_id, (
        f"Ref Thing must equal the PhysicalResourceId the provider returned ({physical_id!r}); got {outputs!r}"
    )
    resource = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Thing")["StackResourceDetail"]
    assert resource["PhysicalResourceId"] == physical_id, (
        f"DescribeStackResource PhysicalResourceId: expected {physical_id!r}, got {resource['PhysicalResourceId']!r}"
    )

    # --- DeleteStack sends Delete with the provider's own physical id, and waits for it ----------
    cfn.delete_stack(StackName=stack_id)
    dreq = box.get(lambda r: r["StackId"] == stack_id and r["RequestType"] == "Delete", why="Delete request")
    assert dreq["PhysicalResourceId"] == physical_id, (
        f"Delete request PhysicalResourceId: expected {physical_id!r}, got {dreq.get('PhysicalResourceId')!r}"
    )
    assert dreq["ResourceProperties"] == want_props, (
        f"Delete request ResourceProperties: expected {want_props!r}, got {dreq['ResourceProperties']!r}"
    )
    assert dreq["RequestId"] != req["RequestId"], "Delete and Create requests reused one RequestId"
    waiting = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert waiting == "DELETE_IN_PROGRESS", f"before the Delete is answered the stack must be DELETE_IN_PROGRESS; got {waiting!r}"
    assert _respond(ctx, dreq, "SUCCESS", physical_id=physical_id) == 200, "PUT of the Delete response failed"
    status = _poll_status(cfn, stack_id, why="delete")
    assert status == "DELETE_COMPLETE", f"expected DELETE_COMPLETE after the Delete was answered, got {status!r}"


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
