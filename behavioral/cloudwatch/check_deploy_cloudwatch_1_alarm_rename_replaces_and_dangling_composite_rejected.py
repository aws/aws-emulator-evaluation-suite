"""deploy-cloudwatch-1-alarm-rename-replaces-and-dangling-composite-rejected."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudwatch-1-alarm-rename-replaces-and-dangling-composite-rejected"
GROUP = "deploy-update-replace"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:eventing",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "axis:rejection",
    "timing:real-time",
)
def run(ctx) -> None:
    """A CFN-deployed alarm notifies SNS -> SQS on a breach; renaming it replaces it so only the new
    name notifies; stack delete removes it; a CompositeAlarm on a missing alarm rolls its stack back.
    """
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")

    namespace = ctx.unique_name("sim2real-cwdep1-ns-")
    metric_name = "Breach"
    old_alarm = ctx.unique_name("sim2real-cwdep1-alarm-a-")
    new_alarm = ctx.unique_name("sim2real-cwdep1-alarm-b-")
    topic_name = ctx.unique_name("sim2real-cwdep1-topic-")
    queue_name = ctx.unique_name("sim2real-cwdep1-queue-")
    stack1 = ctx.unique_name("sim2real-cwdep1-stk-")

    cfn.create_stack(
        StackName=stack1,
        TemplateBody=_alarm_stack_template(old_alarm, topic_name, queue_name, namespace, metric_name),
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack1))

    # Launched early and asserted last: CloudFormation holds the failing CompositeAlarm in
    # CREATE_IN_PROGRESS for ~300 s (its dependency's eventual-consistency window) before rollback.
    valid_alarm = ctx.unique_name("sim2real-cwdep1-valid-")
    composite = ctx.unique_name("sim2real-cwdep1-comp-")
    missing = ctx.unique_name("sim2real-cwdep1-missing-")
    stack2 = ctx.unique_name("sim2real-cwdep1-rb-")
    cfn.create_stack(
        StackName=stack2,
        TemplateBody=_dangling_composite_template(valid_alarm, composite, missing, namespace, "Unused"),
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack2))

    status = _wait_stack(cfn, stack1, timeout_s=300.0)
    assert status == "CREATE_COMPLETE", f"stack {stack1} ended in {status!r}, expected CREATE_COMPLETE"

    outputs = _outputs(cfn, stack1)
    queue_url = outputs["QueueUrl"]
    topic_arn = outputs["TopicArn"]
    assert outputs["AlarmRef"] == old_alarm, (
        f"Ref of AWS::CloudWatch::Alarm should be the alarm name {old_alarm!r}, got {outputs['AlarmRef']!r}"
    )
    phys_before = _physical_id(cfn, stack1, "Alarm")
    topic_phys_before = _physical_id(cfn, stack1, "Topic")
    assert phys_before == old_alarm, f"Alarm PhysicalResourceId {phys_before!r} != AlarmName {old_alarm!r}"
    old_desc = _describe_metric_alarms(cw, [old_alarm])
    assert [a["AlarmName"] for a in old_desc] == [old_alarm], (
        f"DescribeAlarms for the deployed alarm returned {[a['AlarmName'] for a in old_desc]!r}"
    )
    old_arn = old_desc[0]["AlarmArn"]
    assert old_desc[0]["AlarmActions"] == [topic_arn], (
        f"deployed alarm's AlarmActions {old_desc[0]['AlarmActions']!r} != [{topic_arn!r}]"
    )

    seen: list[dict[str, Any]] = []
    first = _breach_until_notified(ctx, cw, sqs, queue_url, namespace, metric_name, old_alarm, seen,
                                   timeout_s=240.0)
    assert first["envelope"]["TopicArn"] == topic_arn, (
        f"notification came from {first['envelope'].get('TopicArn')!r}, expected {topic_arn!r}"
    )
    assert first["payload"]["NewStateValue"] == "ALARM", (
        f"first notification NewStateValue={first['payload'].get('NewStateValue')!r}, expected 'ALARM'"
    )
    assert first["payload"]["AlarmArn"] == old_arn, (
        f"first notification AlarmArn={first['payload'].get('AlarmArn')!r}, expected {old_arn!r}"
    )
    assert first["payload"]["Trigger"]["Namespace"] == namespace, (
        f"notification Trigger.Namespace={first['payload']['Trigger'].get('Namespace')!r}, expected {namespace!r}"
    )

    cfn.update_stack(
        StackName=stack1,
        TemplateBody=_alarm_stack_template(new_alarm, topic_name, queue_name, namespace, metric_name),
        Tags=_tags_kv(),
    )
    status = _wait_stack(cfn, stack1, timeout_s=300.0)
    assert status == "UPDATE_COMPLETE", f"stack {stack1} update ended in {status!r}, expected UPDATE_COMPLETE"
    update_done = datetime.now(timezone.utc)

    phys_after = _physical_id(cfn, stack1, "Alarm")
    assert phys_after == new_alarm, (
        f"after renaming, Alarm PhysicalResourceId is {phys_after!r}, expected the new name {new_alarm!r}"
    )
    assert phys_after != phys_before, f"PhysicalResourceId did not change across replacement ({phys_after!r})"
    topic_phys_after = _physical_id(cfn, stack1, "Topic")
    assert topic_phys_after == topic_phys_before, (
        f"untouched Topic was replaced too: {topic_phys_before!r} -> {topic_phys_after!r}"
    )
    gone = _describe_metric_alarms(cw, [old_alarm])
    assert gone == [], f"replaced alarm {old_alarm!r} still exists after UPDATE_COMPLETE: {gone!r}"
    new_desc = _describe_metric_alarms(cw, [new_alarm])
    assert [a["AlarmName"] for a in new_desc] == [new_alarm], (
        f"DescribeAlarms for the replacement alarm returned {[a['AlarmName'] for a in new_desc]!r}"
    )
    new_arn = new_desc[0]["AlarmArn"]
    assert new_arn != old_arn, f"replacement alarm kept the old ARN {new_arn!r}"
    assert new_desc[0]["AlarmActions"] == [topic_arn], (
        f"replacement alarm's AlarmActions {new_desc[0]['AlarmActions']!r} != [{topic_arn!r}]"
    )

    second = _breach_until_notified(ctx, cw, sqs, queue_url, namespace, metric_name, new_alarm, seen,
                                    timeout_s=240.0)
    assert second["payload"]["NewStateValue"] == "ALARM", (
        f"second notification NewStateValue={second['payload'].get('NewStateValue')!r}, expected 'ALARM'"
    )
    assert second["payload"]["AlarmArn"] == new_arn, (
        f"second notification AlarmArn={second['payload'].get('AlarmArn')!r}, expected {new_arn!r}"
    )
    # Drain what is left so that a late notification from the replaced alarm would be seen.
    _drain(sqs, queue_url, seen, quiet_polls=2)
    stale = [
        n["payload"].get("StateChangeTime") for n in seen
        if n["payload"].get("AlarmName") == old_alarm
        and _parse_ts(n["payload"].get("StateChangeTime")) >= update_done
    ]
    assert stale == [], f"the replaced alarm {old_alarm!r} notified after the update completed: {stale!r}"
    foreign = sorted({n["payload"].get("AlarmName") for n in seen} - {old_alarm, new_alarm})
    assert foreign == [], f"queue received notifications for unexpected alarms: {foreign!r}"

    cfn.delete_stack(StackName=stack1)
    status = _wait_stack(cfn, stack1, timeout_s=300.0)
    assert status == "DELETE_COMPLETE", f"stack {stack1} delete ended in {status!r}, expected DELETE_COMPLETE"
    after_delete = _describe_metric_alarms(cw, [old_alarm, new_alarm])
    assert after_delete == [], (
        f"alarms survived stack deletion: {[a['AlarmName'] for a in after_delete]!r}"
    )

    status = _wait_stack(cfn, stack2, timeout_s=480.0)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {stack2} with a dangling AlarmRule ended in {status!r}, expected ROLLBACK_COMPLETE"
    )
    events = _stack_events(cfn, stack2)
    by_resource: dict[str, list[str]] = {}
    for ev in events:
        by_resource.setdefault(ev["LogicalResourceId"], []).append(ev["ResourceStatus"])
    assert "CREATE_COMPLETE" in by_resource.get("ValidAlarm", []), (
        f"ValidAlarm was never created before the failure, so its absence proves nothing: "
        f"{by_resource.get('ValidAlarm')!r}"
    )
    assert "DELETE_COMPLETE" in by_resource.get("ValidAlarm", []), (
        f"ValidAlarm was not rolled back: {by_resource.get('ValidAlarm')!r}"
    )
    failed = [ev for ev in events if ev["ResourceStatus"] == "CREATE_FAILED"]
    assert [ev["LogicalResourceId"] for ev in failed] == ["Composite"], (
        f"expected exactly the Composite to fail creation, got "
        f"{[(ev['LogicalResourceId'], ev.get('ResourceStatusReason')) for ev in failed]!r}"
    )
    reason = failed[0].get("ResourceStatusReason") or ""
    code = re.search(r"Error Code: ([A-Za-z]+)", reason)
    assert code is not None and code.group(1) == "ValidationError", (
        f"Composite failure should carry CloudWatch's ValidationError, reason was {reason!r}"
    )
    assert f":alarm:{missing}]" in reason, (
        f"Composite failure reason does not name the missing alarm {missing!r}: {reason!r}"
    )
    leftover = _describe_alarms_any(cw, [valid_alarm, composite])
    assert leftover == [], f"rolled-back stack left alarms behind: {leftover!r}"


_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "UPDATE_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": CHECK}]


def _wait_stack(cfn, stack_name: str, *, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as e:
            if "does not exist" in str(e):
                return "DELETE_COMPLETE"
            raise
        if last in _TERMINAL:
            return last
        time.sleep(5.0)
    raise AssertionError(f"stack {stack_name} did not settle within {timeout_s}s; last status {last!r}")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
        status = _wait_stack(cfn, stack_name, timeout_s=300.0)
    except Exception as e:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"cloudformation stack {stack_name}: delete failed: {e!r}") from e
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"cloudformation stack {stack_name}: delete ended in {status}")


def _outputs(cfn, stack_name: str) -> dict[str, str]:
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _physical_id(cfn, stack_name: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId=logical_id)[
        "StackResourceDetail"]["PhysicalResourceId"]


def _stack_events(cfn, stack_name: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        events.extend(page["StackEvents"])
    events.reverse()  # chronological
    return events


def _describe_metric_alarms(cw, names: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for page in cw.get_paginator("describe_alarms").paginate(AlarmNames=names, AlarmTypes=["MetricAlarm"]):
        out.extend(page.get("MetricAlarms", []))
    return out


def _describe_alarms_any(cw, names: list[str]) -> list[str]:
    found: list[str] = []
    for page in cw.get_paginator("describe_alarms").paginate(
            AlarmNames=names, AlarmTypes=["MetricAlarm", "CompositeAlarm"]):
        found.extend(a["AlarmName"] for a in page.get("MetricAlarms", []))
        found.extend(a["AlarmName"] for a in page.get("CompositeAlarms", []))
    return found


def _parse_ts(value) -> datetime:
    # SNS alarm payload StateChangeTime has the form YYYY-MM-DDTHH:MM:SS.mmm+0000.
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")


def _receive(sqs, queue_url: str, seen: list[dict[str, Any]]) -> int:
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    msgs = resp.get("Messages", [])
    for msg in msgs:
        envelope = json.loads(msg["Body"])
        assert envelope.get("Type") == "Notification", f"queue received a non-notification body: {envelope!r}"
        payload = json.loads(envelope["Message"])
        seen.append({"envelope": envelope, "payload": payload})
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return len(msgs)


def _drain(sqs, queue_url: str, seen: list[dict[str, Any]], *, quiet_polls: int) -> None:
    quiet = 0
    while quiet < quiet_polls:
        quiet = quiet + 1 if _receive(sqs, queue_url, seen) == 0 else 0


def _breach_until_notified(ctx, cw, sqs, queue_url, namespace, metric_name, alarm_name, seen, *,
                           timeout_s: float) -> dict[str, Any]:
    """Re-publish a breaching datapoint each round until the queue holds `alarm_name`'s ALARM
    notification."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric_name, "Value": 100.0, "Unit": "Count",
                         "StorageResolution": 1, "Timestamp": datetime.now(timezone.utc)}],
        )
        _receive(sqs, queue_url, seen)
        for n in seen:
            if n["payload"].get("AlarmName") == alarm_name and n["payload"].get("NewStateValue") == "ALARM":
                return n
    states = [a["StateValue"] for a in _describe_metric_alarms(cw, [alarm_name])]
    raise AssertionError(
        f"no ALARM notification for {alarm_name!r} within {timeout_s}s; alarm state {states!r}; "
        f"notifications seen {[(n['payload'].get('AlarmName'), n['payload'].get('NewStateValue')) for n in seen]!r}"
    )


def _metric_alarm(name: str, namespace: str, metric_name: str, actions: list | None) -> dict[str, Any]:
    props: dict[str, Any] = {
        "AlarmName": name,
        "AlarmDescription": "sim2real deploy-cloudwatch-1 check",
        "Namespace": namespace,
        "MetricName": metric_name,
        "Statistic": "Maximum",
        "Period": 10,
        "EvaluationPeriods": 1,
        "DatapointsToAlarm": 1,
        "Threshold": 10,
        "ComparisonOperator": "GreaterThanThreshold",
        "TreatMissingData": "notBreaching",
    }
    if actions is not None:
        props["AlarmActions"] = actions
    return {"Type": "AWS::CloudWatch::Alarm", "Properties": props}


def _alarm_stack_template(alarm_name, topic_name, queue_name, namespace, metric_name) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name, "Tags": _tags_kv()}},
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": topic_name, "Tags": _tags_kv()}},
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
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
                "Properties": {
                    "TopicArn": {"Ref": "Topic"},
                    "Protocol": "sqs",
                    "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]},
                },
            },
            "Alarm": dict(_metric_alarm(alarm_name, namespace, metric_name, [{"Ref": "Topic"}]),
                          DependsOn="Subscription"),
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "AlarmRef": {"Value": {"Ref": "Alarm"}},
        },
    })


def _dangling_composite_template(valid_alarm, composite, missing, namespace, metric_name) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ValidAlarm": _metric_alarm(valid_alarm, namespace, metric_name, None),
            "Composite": {
                "Type": "AWS::CloudWatch::CompositeAlarm",
                "DependsOn": "ValidAlarm",
                "Properties": {
                    "AlarmName": composite,
                    # DependsOn guarantees ValidAlarm EXISTS before the failure, so its absence
                    # after rollback is a rollback, not a cancelled create. Without DependsOn the
                    # stack fails in ~4 s but ValidAlarm is cancelled before it is ever created.
                    "AlarmRule": f'ALARM("{missing}")',
                },
            },
        },
    })


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
