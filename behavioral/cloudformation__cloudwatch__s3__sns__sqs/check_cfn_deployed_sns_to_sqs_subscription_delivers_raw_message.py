"""cfn-deployed-sns-to-sqs-subscription-delivers-raw-message."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deployed-sns-to-sqs-subscription-delivers-raw-message"

GROUP = "deploy_functional"

SERVICES = ["cloudformation", "cloudwatch", "s3", "sns", "sqs"]


def _template(topic_name: str, queue_name: str) -> str:
    """Topic + queue + queue policy + subscription, with the policy created FIRST.

    DependsOn is load-bearing: without it CloudFormation may create the subscription before the
    queue policy exists, and SNS cannot then send to the queue at all.
    """
    return json.dumps({
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": topic_name}},
            "Queue": {"Type": "AWS::SQS::Queue",
                      "Properties": {"QueueName": queue_name, "VisibilityTimeout": 30}},
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "AllowThisTopic",
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                            "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}},
                        }],
                    },
                },
            },
            "Subscription": {
                "Type": "AWS::SNS::Subscription",
                "DependsOn": "QueuePolicy",
                "Properties": {"Protocol": "sqs", "TopicArn": {"Ref": "Topic"},
                               "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]},
                               "RawMessageDelivery": True},
            },
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack declaring topic, queue, queue policy and a RawMessageDelivery subscription delivers a
    published message to the queue byte-identical, not JSON-enveloped; the subscription reports
    RawMessageDelivery=true and the queue policy grants sns.amazonaws.com."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_name = _xname(ctx, "raw-t")
    queue_name = _xname(ctx, "raw-q")

    stack, status = _create_stack_and_wait(
        ctx, _template(topic_name, queue_name), stack_name=_xname(ctx, "raw"), timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"the pipeline stack ended in {status!r}"

    outputs = _outputs(cfn, stack)
    assert set(outputs) == {"TopicArn", "QueueUrl", "QueueArn"}, (
        f"the stack must publish the whole pipeline structurally, got {outputs!r}"
    )
    topic_arn, queue_url, queue_arn = (
        outputs["TopicArn"], outputs["QueueUrl"], outputs["QueueArn"])

    # ---- the round trip: publish to SNS, receive from SQS ----
    marker = f"raw-delivery-{queue_name}"
    sns.publish(TopicArn=topic_arn, Message=marker, Subject="sim2real")
    received = _receive_one(sqs, queue_url, timeout_s=180.0)

    assert received["Body"] == marker, (
        f"RawMessageDelivery=true must deliver the published body verbatim, got "
        f"{received['Body']!r}"
    )
    assert not received["Body"].lstrip().startswith("{"), (
        f"the body is JSON-enveloped, so RawMessageDelivery did not take effect: "
        f"{received['Body']!r}"
    )

    # ---- and the deployed wiring is the wiring the template asked for ----
    sub_arn = _physical_id(cfn, stack, "Subscription")
    attrs = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    assert attrs["RawMessageDelivery"] == "true", (
        f"the delivered payload was raw but the subscription does not report it: {attrs!r}"
    )
    assert attrs["Endpoint"] == queue_arn, (
        f"the subscription is not wired to the stack's queue: {attrs!r} vs {queue_arn!r}"
    )
    assert attrs["TopicArn"] == topic_arn, f"{attrs!r} vs {topic_arn!r}"

    # The queue policy the stack deployed is what made the delivery legal, so it must be there.
    policy = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["Policy"])["Attributes"]["Policy"]
    statements = json.loads(policy)["Statement"]
    principals = [s.get("Principal") for s in statements]
    assert {"Service": "sns.amazonaws.com"} in principals, (
        f"the CFN-deployed queue policy does not allow the SNS service principal: {statements!r}"
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


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


def _outputs(cfn, name: str) -> dict[str, str]:
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _physical_id(cfn, stack: str, logical_id: str) -> str:
    """The PhysicalResourceId CloudFormation currently records for a logical id."""
    return cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId=logical_id)["StackResourceDetail"]["PhysicalResourceId"]


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
