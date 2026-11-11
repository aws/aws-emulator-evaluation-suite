"""deploy-cfn-target-dead-letter-config-captures-undeliverable-events-until-a-stack-update-adds-the-queue-policy."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-target-dead-letter-config-captures-undeliverable-events-until-a-stack-update-adds-the-queue-policy"
GROUP = "deploy"
SERVICES = ["events"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack-deployed target with RetryPolicy/DeadLetterConfig but no queue policy dead-letters
    events (NO_RESOURCE, naming rule and queue); a stack update adding the policy restores delivery.
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    stack = ctx.unique_name("sim2real-evb-dlqstk-")
    names = {"bus": ctx.unique_name("sim2real-evb-cfnbus-"), "rule": ctx.unique_name("sim2real-evb-cfnrule-"),
             "source": ctx.unique_name("sim2real.cfndlq.")}
    cfn.create_stack(StackName=stack, TemplateBody=_template(names, with_target_policy=False),
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))
    status = _wait_stack(cfn, stack, "CREATE_COMPLETE", timeout_s=300.0)
    assert status == "CREATE_COMPLETE", f"stack create ended {status!r}: {_failure_reasons(cfn, stack)!r}"
    out = _outputs(cfn, stack)

    targets = events.list_targets_by_rule(Rule=names["rule"], EventBusName=names["bus"])["Targets"]
    assert len(targets) == 1, f"the deployed rule has {len(targets)} targets, expected 1"
    t = targets[0]
    assert t["Arn"] == out["QueueArn"], "the deployed target does not point at the stack's queue"
    assert t.get("RetryPolicy") == {"MaximumRetryAttempts": 3, "MaximumEventAgeInSeconds": 3600}, (
        f"deployed RetryPolicy read back as {t.get('RetryPolicy')!r}"
    )
    assert t.get("DeadLetterConfig") == {"Arn": out["DlqArn"]}, "deployed DeadLetterConfig does not name the DLQ"

    event_id = _put(events, names, ctx.unique_name("m-"))
    body, attrs = _await(sqs, out["DlqUrl"], lambda b, a: b.get("id") == event_id, 150.0)
    assert attrs.get("ERROR_CODE") == "NO_RESOURCE", f"dead-letter ERROR_CODE was {attrs.get('ERROR_CODE')!r}"
    shaped = re.sub(r"Request ID: [^;]+;", "Request ID: <id>;", attrs.get("ERROR_MESSAGE") or "")
    assert shaped == _NON_EXISTENT_QUEUE, f"dead-letter ERROR_MESSAGE was {shaped!r}"
    assert attrs.get("RULE_ARN") == out["RuleArn"], "dead-letter RULE_ARN does not name the deployed rule"
    assert attrs.get("TARGET_ARN") == out["QueueArn"], "dead-letter TARGET_ARN does not name the deployed queue"
    assert body["source"] == names["source"], f"dead-lettered event source was {body['source']!r}"
    left = sqs.receive_message(QueueUrl=out["QueueUrl"], MaxNumberOfMessages=10,
                               WaitTimeSeconds=2).get("Messages", [])
    assert left == [], f"the policy-less target queue holds {len(left)} message(s)"

    cfn.update_stack(StackName=stack, TemplateBody=_template(names, with_target_policy=True))
    status = _wait_stack(cfn, stack, "UPDATE_COMPLETE", timeout_s=300.0)
    assert status == "UPDATE_COMPLETE", f"stack update ended {status!r}: {_failure_reasons(cfn, stack)!r}"
    after = _outputs(cfn, stack)
    assert after["RuleArn"] == out["RuleArn"] and after["QueueArn"] == out["QueueArn"], (
        "the update replaced the rule or the queue instead of adding only the policy"
    )

    got = _resend_until(events, sqs, names, ctx.unique_name("m2-"), out["QueueUrl"], timeout_s=120.0)
    assert got["source"] == names["source"], f"event delivered after the update had source {got['source']!r}"


# SQS's error as EventBridge records it (SQS answers an unauthorized principal as if the queue did
# not exist); the minted request id is shaped.
_NON_EXISTENT_QUEUE = (
    "The specified queue does not exist or you do not have access to it. (Service: AmazonSQS; "
    "Status Code: 400; Error Code: AWS.SimpleQueueService.NonExistentQueue; Request ID: <id>; Proxy: null)"
)


def _template(names: dict, *, with_target_policy: bool) -> str:
    def allow(queue: str) -> dict:
        return {"Type": "AWS::SQS::QueuePolicy", "Properties": {
            "Queues": [{"Ref": queue}],
            "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage", "Resource": {"Fn::GetAtt": [queue, "Arn"]},
                "Condition": {"ArnEquals": {"aws:SourceArn": {"Fn::GetAtt": ["Rule", "Arn"]}}}}]}}}

    resources = {
        "Bus": {"Type": "AWS::Events::EventBus", "Properties": {"Name": names["bus"]}},
        "Queue": {"Type": "AWS::SQS::Queue", "Properties": {}},
        "Dlq": {"Type": "AWS::SQS::Queue", "Properties": {}},
        "Rule": {"Type": "AWS::Events::Rule", "Properties": {
            "Name": names["rule"], "EventBusName": {"Ref": "Bus"},
            "EventPattern": {"source": [names["source"]]}, "State": "ENABLED",
            "Targets": [{"Id": "queue", "Arn": {"Fn::GetAtt": ["Queue", "Arn"]},
                         "RetryPolicy": {"MaximumRetryAttempts": 3, "MaximumEventAgeInSeconds": 3600},
                         "DeadLetterConfig": {"Arn": {"Fn::GetAtt": ["Dlq", "Arn"]}}}]}},
        "DlqPolicy": allow("Dlq"),
    }
    if with_target_policy:
        resources["QueuePolicy"] = allow("Queue")
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
            "DlqUrl": {"Value": {"Ref": "Dlq"}},
            "DlqArn": {"Value": {"Fn::GetAtt": ["Dlq", "Arn"]}},
            "RuleArn": {"Value": {"Fn::GetAtt": ["Rule", "Arn"]}},
        },
    })


def _outputs(cfn, stack: str) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}


def _wait_stack(cfn, stack: str, goal: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if status == goal or status.endswith("_FAILED") or status.endswith("ROLLBACK_COMPLETE"):
            return status
        time.sleep(5)
    raise AssertionError(f"stack did not settle within {timeout_s}s (last {status!r})")


def _failure_reasons(cfn, stack: str) -> list:
    evs = cfn.describe_stack_events(StackName=stack)["StackEvents"]
    return [e.get("ResourceStatusReason") for e in evs if e["ResourceStatus"].endswith("FAILED")][:5]


def _delete_stack(cfn, stack: str, timeout_s: float = 240.0) -> None:
    cfn.delete_stack(StackName=stack)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ValidationError":
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack teardown failed: {_failure_reasons(cfn, stack)!r}")
        time.sleep(5)
    raise AssertionError(f"stack teardown did not finish within {timeout_s}s")


def _put(events, names: dict, marker: str) -> str:
    resp = events.put_events(Entries=[{"EventBusName": names["bus"], "Source": names["source"],
                                       "DetailType": "sim2real-cfn-dlq", "Detail": json.dumps({"marker": marker})}])
    assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
    return resp["Entries"][0]["EventId"]


def _receive(sqs, url: str) -> list:
    out = []
    for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                 MessageAttributeNames=["All"]).get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        attrs = {k: v.get("StringValue") for k, v in (m.get("MessageAttributes") or {}).items()}
        out.append((json.loads(m["Body"]), attrs))
    return out


def _await(sqs, url: str, match, timeout_s: float) -> tuple:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for body, attrs in _receive(sqs, url):
            if match(body, attrs):
                return body, attrs
    raise AssertionError(f"no matching message reached the queue within {timeout_s}s")


def _resend_until(events, sqs, names, marker, url, timeout_s: float) -> dict:
    """Send events until one lands on ``url`` (queue-policy propagation); returns its body."""
    deadline = time.monotonic() + timeout_s
    sent: set = set()
    n = 0
    while time.monotonic() < deadline:
        n += 1
        sent.add(_put(events, names, f"{marker}-{n}"))
        for body, _ in _receive(sqs, url):
            if body.get("id") in sent:
                return body
    raise AssertionError(f"after the stack update no event reached the target in {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
