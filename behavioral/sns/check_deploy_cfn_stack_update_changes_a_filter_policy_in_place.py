"""deploy-cfn-stack-update-changes-a-filter-policy-in-place."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-stack-update-changes-a-filter-policy-in-place"
GROUP = "deploy"
SERVICES = ["sns"]


def _template(colour: str) -> str:
    tags_ = [{"Key": "sim2real", "Value": CHECK}]

    def _policy(queue: str) -> dict:
        return {
            "Type": "AWS::SQS::QueuePolicy",
            "Properties": {
                "Queues": [{"Ref": queue}],
                "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "sqs:SendMessage", "Resource": {"Fn::GetAtt": [queue, "Arn"]},
                    "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}}}]},
            },
        }

    return json.dumps({
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"Tags": tags_}},
            "Filtered": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": tags_}},
            "FilteredPolicy": _policy("Filtered"),
            "Control": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": tags_}},
            "ControlPolicy": _policy("Control"),
            "FilteredSubscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {"TopicArn": {"Ref": "Topic"}, "Protocol": "sqs",
                               "Endpoint": {"Fn::GetAtt": ["Filtered", "Arn"]},
                               "FilterPolicy": {"colour": [colour]}},
            },
            "ControlSubscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {"TopicArn": {"Ref": "Topic"}, "Protocol": "sqs",
                               "Endpoint": {"Fn::GetAtt": ["Control", "Arn"]}},
            },
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "SubscriptionArn": {"Value": {"Ref": "FilteredSubscription"}},
            "FilteredUrl": {"Value": {"Ref": "Filtered"}},
            "ControlUrl": {"Value": {"Ref": "Control"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack update changing only a FilterPolicy keeps the subscription ARN, stores the new policy,
    and switches which colour the filtered queue receives; an unfiltered control gets both.
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    stack = ctx.unique_name("sim2real-behav-sns-cfnupd-")
    out = _create_stack(ctx, cfn, stack, _template("red"))
    topic, sub_arn = out["TopicArn"], out["SubscriptionArn"]

    published: set[str] = set()

    def _round(label: str) -> tuple[set[str], set[str]]:
        """Publish one red and one blue message; returns the colours of THIS round the filtered
        queue received, and any body it received that this check never published."""
        bodies = {c: ctx.unique_name(f"sim2real-{label}-{c}-") for c in ("red", "blue")}
        published.update(bodies.values())
        for colour, body in bodies.items():
            sns.publish(TopicArn=topic, Message=body, MessageAttributes={
                "colour": {"DataType": "String", "StringValue": colour}})
        control = _drain_until(sqs, out["ControlUrl"], set(bodies.values()), 60)
        assert set(bodies.values()) <= control, (
            f"the unfiltered control must receive both {label} messages; got {sorted(control)!r}")
        # The control queue's arrival bounds how long the filtered queue's absence is awaited.
        filtered = _drain_until(sqs, out["FilteredUrl"], set(), 4)
        return {c for c, b in bodies.items() if b in filtered}, filtered - published

    seen, stray = _round("before")
    assert (seen, stray) == ({"red"}, set()), (
        f"with FilterPolicy colour=[red] the filtered queue must receive only red; got {seen!r} {stray!r}")

    _update_stack(cfn, stack, _template("blue"))
    desc = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    after = {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
    assert after["SubscriptionArn"] == sub_arn, (
        "a FilterPolicy-only update must keep the subscription; its ARN changed across the update")
    stored = json.loads(sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]["FilterPolicy"])
    assert stored == {"colour": ["blue"]}, f"the updated subscription reads FilterPolicy {stored!r}"

    deadline = time.monotonic() + 120
    while True:
        seen, stray = _round("after")
        if seen == {"blue"} or time.monotonic() > deadline:
            break
        time.sleep(3)
    assert (seen, stray) == ({"blue"}, set()), (
        f"after the update to colour=[blue] the filtered queue must receive only blue; got {seen!r} {stray!r}")


def _create_stack(ctx, cfn, name: str, body: str) -> dict:
    def _cleanup():
        cfn.delete_stack(StackName=name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    cfn.create_stack(StackName=name, TemplateBody=body, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    desc = cfn.describe_stacks(StackName=name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _update_stack(cfn, name: str, body: str) -> None:
    cfn.update_stack(StackName=name, TemplateBody=body)
    cfn.get_waiter("stack_update_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _drain_until(sqs, url: str, wanted: set[str], timeout_s: float) -> set[str]:
    """Receive and delete until every body in ``wanted`` arrived or the deadline passed (at
    least one receive always runs); returns every notification Message drained."""
    out: set[str] = set()
    deadline = time.monotonic() + timeout_s
    while True:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            out.add(json.loads(msg["Body"])["Message"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        if (wanted and wanted <= out) or time.monotonic() >= deadline:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
