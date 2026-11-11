"""deploy-cfn-bus-target-with-a-stack-created-execution-role-forwards-events-to-the-destination-bus."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-bus-target-with-a-stack-created-execution-role-forwards-events-to-the-destination-bus"
GROUP = "deploy"
SERVICES = ["events"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack-deployed bus-to-bus target with a stack-created role reads back with that role,
    forwards a matching event to the destination bus's queue intact, and drops a non-matching one.
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    stack = ctx.unique_name("sim2real-evb-b2bstk-")
    names = {"src": ctx.unique_name("sim2real-evb-b2bsrc-"), "dst": ctx.unique_name("sim2real-evb-b2bdst-"),
             "fwd": ctx.unique_name("sim2real-evb-b2bfwd-"), "sink": ctx.unique_name("sim2real-evb-b2bsink-"),
             "source": ctx.unique_name("sim2real.b2b.")}
    cfn.create_stack(StackName=stack, TemplateBody=_template(names), Capabilities=["CAPABILITY_IAM"],
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))
    status = _wait_stack(cfn, stack, "CREATE_COMPLETE", timeout_s=300.0)
    assert status == "CREATE_COMPLETE", f"stack create ended {status!r}: {_failure_reasons(cfn, stack)!r}"
    out = _outputs(cfn, stack)

    targets = events.list_targets_by_rule(Rule=names["fwd"], EventBusName=names["src"])["Targets"]
    assert [(t["Arn"], t.get("RoleArn")) for t in targets] == [(out["DstArn"], out["RoleArn"])], (
        "the deployed forwarding target does not point at the destination bus with the stack's role"
    )

    skipped = ctx.unique_name("skip-")
    _put(events, names["src"], names["source"], "sim2real-unmatched", skipped)
    marker = ctx.unique_name("fwd-")
    detail = {"marker": marker, "nested": {"n": 7, "flag": True}}
    deadline = time.monotonic() + 150.0
    got = None
    seen: set = set()
    # The stack's role may not be usable by EventBridge the instant the stack completes (IAM
    # propagation); a forward attempted too early is dropped, so re-send until one arrives.
    while got is None and time.monotonic() < deadline:
        _put(events, names["src"], names["source"], "sim2real-forwarded", None, detail)
        for m in sqs.receive_message(QueueUrl=out["QueueUrl"], MaxNumberOfMessages=10,
                                     WaitTimeSeconds=10).get("Messages", []):
            sqs.delete_message(QueueUrl=out["QueueUrl"], ReceiptHandle=m["ReceiptHandle"])
            body = json.loads(m["Body"])
            seen.add(body.get("detail", {}).get("marker"))
            if body.get("detail", {}).get("marker") == marker:
                got = body
    assert got is not None, "no event put on the source bus reached the destination's queue in 150s"
    assert got["source"] == names["source"], f"forwarded event source was {got['source']!r}"
    assert got["detail-type"] == "sim2real-forwarded", f"forwarded detail-type was {got['detail-type']!r}"
    assert got["detail"] == detail, f"forwarded detail was {got['detail']!r}"
    assert skipped not in seen, "an event the forwarding rule does not match reached the destination's queue"


def _template(names: dict) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Src": {"Type": "AWS::Events::EventBus", "Properties": {"Name": names["src"]}},
            "Dst": {"Type": "AWS::Events::EventBus", "Properties": {"Name": names["dst"]}},
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {}},
            "Role": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]},
                "Policies": [{"PolicyName": "forward", "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Action": "events:PutEvents", "Resource": {"Fn::GetAtt": ["Dst", "Arn"]}}]}}],
                "Tags": [{"Key": "sim2real", "Value": CHECK}]}},
            "Forward": {"Type": "AWS::Events::Rule", "Properties": {
                "Name": names["fwd"], "EventBusName": {"Ref": "Src"},
                "EventPattern": {"source": [names["source"]], "detail-type": ["sim2real-forwarded"]},
                "State": "ENABLED",
                "Targets": [{"Id": "bus", "Arn": {"Fn::GetAtt": ["Dst", "Arn"]},
                             "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]}}]}},
            "Sink": {"Type": "AWS::Events::Rule", "Properties": {
                "Name": names["sink"], "EventBusName": {"Ref": "Dst"},
                "EventPattern": {"source": [names["source"]]}, "State": "ENABLED",
                "Targets": [{"Id": "queue", "Arn": {"Fn::GetAtt": ["Queue", "Arn"]}}]}},
            "QueuePolicy": {"Type": "AWS::SQS::QueuePolicy", "Properties": {
                "Queues": [{"Ref": "Queue"}],
                "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "sqs:SendMessage", "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                    "Condition": {"ArnEquals": {"aws:SourceArn": {"Fn::GetAtt": ["Sink", "Arn"]}}}}]}}},
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "DstArn": {"Value": {"Fn::GetAtt": ["Dst", "Arn"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
        },
    })


def _put(events, bus: str, source: str, detail_type: str, marker, detail=None) -> None:
    body = detail if detail is not None else {"marker": marker}
    resp = events.put_events(Entries=[{"EventBusName": bus, "Source": source, "DetailType": detail_type,
                                       "Detail": json.dumps(body)}])
    assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
