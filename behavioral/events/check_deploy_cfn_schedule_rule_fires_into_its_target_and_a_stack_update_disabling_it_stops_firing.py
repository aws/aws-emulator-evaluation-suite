"""deploy-cfn-schedule-rule-fires-into-its-target-and-a-stack-update-disabling-it-stops-firing."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-schedule-rule-fires-into-its-target-and-a-stack-update-disabling-it-stops-firing"
GROUP = "deploy"
SERVICES = ["events"]

# A firing scheduled this long after the disabling update completed is a violation; earlier
# ones may have been in flight while the update ran.
_GRACE_S = 60.0


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A stack-deployed rate(1 minute) rule delivers its input-transformed payload to SQS; a stack
    update setting State=DISABLED keeps the rule and stops deliveries scheduled after the update.
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    stack = ctx.unique_name("sim2real-evb-schstk-")
    rule = ctx.unique_name("sim2real-evb-sched-")
    tag = ctx.unique_name("sch-")
    cfn.create_stack(StackName=stack, TemplateBody=_template(rule, tag, "ENABLED"),
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))
    status = _wait_stack(cfn, stack, "CREATE_COMPLETE", timeout_s=300.0)
    assert status == "CREATE_COMPLETE", f"stack create ended {status!r}: {_failure_reasons(cfn, stack)!r}"
    out = _outputs(cfn, stack)

    described = events.describe_rule(Name=rule)
    assert described["ScheduleExpression"] == "rate(1 minute)", (
        f"deployed rule ScheduleExpression is {described.get('ScheduleExpression')!r}"
    )
    assert described["State"] == "ENABLED", f"deployed rule State is {described['State']!r}"

    first = _await(sqs, out["QueueUrl"], timeout_s=180.0)
    assert first["tag"] == tag, f"the scheduled delivery carried tag {first.get('tag')!r}"
    assert first["resources"] == [out["RuleArn"]], "the scheduled event's resources do not name the deployed rule"
    assert first["detailType"] == "Scheduled Event", f"scheduled event detail-type was {first['detailType']!r}"

    cfn.update_stack(StackName=stack, TemplateBody=_template(rule, tag, "DISABLED"))
    status = _wait_stack(cfn, stack, "UPDATE_COMPLETE", timeout_s=300.0)
    assert status == "UPDATE_COMPLETE", f"stack update ended {status!r}: {_failure_reasons(cfn, stack)!r}"
    updated_at = _stack_status_time(cfn, stack, "UPDATE_COMPLETE")
    assert _outputs(cfn, stack)["RuleArn"] == out["RuleArn"], "the update replaced the rule"
    state = events.describe_rule(Name=rule)["State"]
    assert state == "DISABLED", f"after the update the rule reads back {state!r}"

    # Compares AWS's own times (scheduled event time vs stack event timestamp), never the host
    # clock; the window spans two further schedule slots.
    late = []
    window_end = time.monotonic() + 150.0
    while time.monotonic() < window_end:
        for body in _receive(sqs, out["QueueUrl"]):
            fired = dt.datetime.fromisoformat(body["time"].replace("Z", "+00:00"))
            if (fired - updated_at).total_seconds() > _GRACE_S:
                late.append(body["time"])
    assert late == [], f"the disabled rule kept firing; scheduled times {late!r} follow the update"


def _template(rule: str, tag: str, state: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {}},
            "Rule": {"Type": "AWS::Events::Rule", "Properties": {
                "Name": rule, "ScheduleExpression": "rate(1 minute)", "State": state,
                "Targets": [{
                    "Id": "queue", "Arn": {"Fn::GetAtt": ["Queue", "Arn"]},
                    "InputTransformer": {
                        "InputPathsMap": {"t": "$.time", "r": "$.resources", "d": "$.detail-type"},
                        "InputTemplate": '{"tag": "' + tag + '", "time": <t>, "resources": <r>, "detailType": <d>}',
                    },
                }]}},
            "QueuePolicy": {"Type": "AWS::SQS::QueuePolicy", "Properties": {
                "Queues": [{"Ref": "Queue"}],
                "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "sqs:SendMessage", "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                    "Condition": {"ArnEquals": {"aws:SourceArn": {"Fn::GetAtt": ["Rule", "Arn"]}}}}]}}},
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "RuleArn": {"Value": {"Fn::GetAtt": ["Rule", "Arn"]}},
        },
    })


def _outputs(cfn, stack: str) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}


def _stack_status_time(cfn, stack: str, status: str) -> dt.datetime:
    for e in cfn.describe_stack_events(StackName=stack)["StackEvents"]:
        if e["LogicalResourceId"] == stack and e["ResourceStatus"] == status:
            return e["Timestamp"]
    raise AssertionError(f"the stack's events record no {status} for the stack itself")


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


def _receive(sqs, url: str) -> list:
    out = []
    for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        out.append(json.loads(m["Body"]))
    return out


def _await(sqs, url: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = _receive(sqs, url)
        if got:
            return got[0]
    raise AssertionError(f"the deployed schedule rule delivered nothing within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
