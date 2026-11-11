"""cfn-deployed-subscription-without-queue-policy-delivery-blocked."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deployed-subscription-without-queue-policy-delivery-blocked"

GROUP = "deploy_functional"

SERVICES = ["cloudformation", "cloudwatch", "s3", "sns", "sqs"]

_ROUNDS = 4


def _template(topic_name: str, control_name: str, broken_name: str) -> str:
    """One topic fanning to two queues that differ in EXACTLY one thing: the control queue has an
    AWS::SQS::QueuePolicy allowing the SNS service principal, the broken queue has none.

    Both subscriptions are otherwise identical, both RawMessageDelivery, both created by the same
    stack in the same operation. That is what makes the control a barrier rather than a second
    experiment.
    """
    return json.dumps({
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": topic_name}},
            "ControlQueue": {"Type": "AWS::SQS::Queue",
                             "Properties": {"QueueName": control_name, "VisibilityTimeout": 30}},
            "BrokenQueue": {"Type": "AWS::SQS::Queue",
                            "Properties": {"QueueName": broken_name, "VisibilityTimeout": 30}},
            "ControlQueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "ControlQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "AllowThisTopic", "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": {"Fn::GetAtt": ["ControlQueue", "Arn"]},
                            "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}},
                        }],
                    },
                },
            },
            "ControlSubscription": {
                "Type": "AWS::SNS::Subscription", "DependsOn": "ControlQueuePolicy",
                "Properties": {"Protocol": "sqs", "TopicArn": {"Ref": "Topic"},
                               "Endpoint": {"Fn::GetAtt": ["ControlQueue", "Arn"]},
                               "RawMessageDelivery": True},
            },
            "BrokenSubscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {"Protocol": "sqs", "TopicArn": {"Ref": "Topic"},
                               "Endpoint": {"Fn::GetAtt": ["BrokenQueue", "Arn"]},
                               "RawMessageDelivery": True},
            },
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "ControlQueueUrl": {"Value": {"Ref": "ControlQueue"}},
            "BrokenQueueUrl": {"Value": {"Ref": "BrokenQueue"}},
            "BrokenQueueArn": {"Value": {"Fn::GetAtt": ["BrokenQueue", "Arn"]}},
        },
    })


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e",
      "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A confirmed SNS subscription to a queue CloudFormation deployed without a queue policy receives
    nothing while a control queue with the policy receives every publish of the same fan-out; once the
    policy is added, the same queue receives the next message."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_name = _xname(ctx, "nopol-t")
    control_name = _xname(ctx, "nopol-q") + "-ctl"
    broken_name = _xname(ctx, "nopol-q") + "-brk"

    stack, status = _create_stack_and_wait(
        ctx, _template(topic_name, control_name, broken_name),
        stack_name=_xname(ctx, "nopol"), timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"the stack must deploy cleanly -- a missing queue policy is not a template error, which "
        f"is the whole problem. Got {status!r}"
    )

    out = _outputs(cfn, stack)
    topic_arn = out["TopicArn"]
    control_url, broken_url = out["ControlQueueUrl"], out["BrokenQueueUrl"]
    broken_arn = out["BrokenQueueArn"]

    # ---- exactly one thing differs, and CloudFormation deployed both sides ----
    assert "Policy" not in _queue_attributes(sqs, broken_url, ["Policy"]), (
        f"the broken queue must have NO resource policy for this check to mean anything: "
        f"{_queue_attributes(sqs, broken_url, ['Policy'])!r}"
    )
    control_attrs = _queue_attributes(sqs, control_url, ["Policy"])
    assert "Policy" in control_attrs, (
        f"the control queue must have the CFN-deployed policy, else it is not a control: "
        f"{control_attrs!r}"
    )
    subs = {s["Endpoint"]: s for s in _subscriptions(sns, topic_arn)}
    assert broken_arn in subs, (
        f"the broken subscription must EXIST -- an absent subscription would explain the silence "
        f"without any authorisation decision. Topic had {sorted(subs)!r}"
    )
    broken_sub_arn = subs[broken_arn]["SubscriptionArn"]
    assert broken_sub_arn.startswith(topic_arn), (
        f"the broken subscription is not confirmed ({broken_sub_arn!r}); PendingConfirmation "
        f"would be a different defect from an unauthorised delivery"
    )

    # Drain both queues first so 'empty' means empty.
    _drain(sqs, broken_url)
    _drain(sqs, control_url)

    # ---- the differential barrier ----
    for i in range(_ROUNDS):
        marker = f"fanout-{i}-{topic_name}"
        sns.publish(TopicArn=topic_arn, Message=marker)
        delivered = _receive_one(sqs, control_url, timeout_s=180.0)
        assert delivered["Body"] == marker, (
            f"round {i}: the control queue received {delivered['Body']!r}, expected {marker!r} -- "
            f"without a healthy control there is no barrier"
        )
        sqs.delete_message(QueueUrl=control_url,
                           ReceiptHandle=delivered["ReceiptHandle"])
        stray = sqs.receive_message(QueueUrl=broken_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=1).get("Messages", [])
        assert stray == [], (
            f"round {i}: SNS delivered to a queue whose policy authorises nothing: {stray!r}"
        )

    counted = _queue_attributes(sqs, broken_url, ["ApproximateNumberOfMessages",
                                                  "ApproximateNumberOfMessagesNotVisible"])
    assert counted["ApproximateNumberOfMessages"] == "0", (
        f"after {_ROUNDS} sustained control deliveries the unauthorised queue holds "
        f"{counted!r} messages"
    )

    # ---- repair the ONE broken thing; the same queue must now receive ----
    sqs.set_queue_attributes(QueueUrl=broken_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowThisTopic", "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": broken_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    })})

    repaired_marker = f"repaired-{topic_name}"
    # The policy change is eventually consistent, so republish while polling rather than trusting
    # one publish to land: the claim is that the queue becomes reachable, not how fast.
    got = _poll_until(
        lambda: _publish_then_peek(sns, sqs, topic_arn, broken_url, repaired_marker),
        bool, timeout_s=300.0, interval_s=5.0,
        description=f"delivery to {broken_name} once its queue policy allows SNS")
    assert got[0]["Body"] == repaired_marker, (
        f"the repaired queue received {got[0]['Body']!r}, expected {repaired_marker!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                    "DELETE_COMPLETE", "DELETE_FAILED", "GONE"}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _receive_one(sqs, url: str, *, timeout_s=120.0) -> dict[str, Any]:
    """Long-poll a queue until one message arrives; return it (raises on timeout)."""
    msgs = _poll_until(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1,
                                    WaitTimeSeconds=20).get("Messages", []),
        bool, timeout_s=timeout_s, interval_s=1.0, description=f"a message on {url}")
    return msgs[0]


def _publish_then_peek(sns, sqs, topic_arn: str, url: str, body: str):
    """One publish, one short receive. The probe for the repair loop."""
    sns.publish(TopicArn=topic_arn, Message=body)
    return sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1,
                               WaitTimeSeconds=10).get("Messages", [])


def _drain(sqs, url: str) -> None:
    """Receive-and-delete until the queue reads empty twice, so 'empty' later means empty."""
    empties = 0
    while empties < 2:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=1).get("Messages", [])
        if not msgs:
            empties += 1
            continue
        empties = 0
        for m in msgs:
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])


def _queue_attributes(sqs, url: str, names: list[str]) -> dict[str, str]:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=names).get("Attributes", {})


def _subscriptions(sns, topic_arn: str) -> list[dict[str, Any]]:
    """Every subscription on a topic, paginated, so the check never reads page one only."""
    out: list[dict[str, Any]] = []
    for page in sns.get_paginator("list_subscriptions_by_topic").paginate(TopicArn=topic_arn):
        out.extend(page.get("Subscriptions", []))
    return out


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


def _outputs(cfn, name: str) -> dict[str, str]:
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _delete_stack_and_wait(ctx, name: str, *, timeout_s=900.0) -> None:
    """Delete a stack and wait for it to go; teardown, so a failure PRINTS rather than raises."""
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=name)
        final = _poll_until(lambda: _stack_status(cfn, name),
                            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
                            timeout_s=timeout_s, interval_s=5.0,
                            description=f"delete stack {name}")
        if final == "DELETE_FAILED":
            raise RuntimeError(
                f"stack {name} ended DELETE_FAILED — its resources are stranded"
            )
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(
                f"stack {name} teardown failed: {type(exc).__name__}: {exc}"
            ) from exc


def _create_stack_and_wait(ctx, template: str, *, stack_name=None, parameters=None,
                           capabilities=None, timeout_s=900.0) -> tuple[str, str]:
    """create_stack, then poll to a terminal status which is RETURNED rather than asserted."""
    cfn = ctx.client("cloudformation")
    ctx.verify_account_safety()
    name = stack_name or _xname(ctx, "stk")
    kwargs: dict[str, Any] = {
        "StackName": name, "TemplateBody": template, "Tags": _tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v}
                                for k, v in parameters.items()]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
    status = _poll_until(lambda: _stack_status(cfn, name), lambda s: s in _CREATE_TERMINAL,
                         timeout_s=timeout_s, interval_s=5.0,
                         description=f"create stack {name}")
    return name, status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
