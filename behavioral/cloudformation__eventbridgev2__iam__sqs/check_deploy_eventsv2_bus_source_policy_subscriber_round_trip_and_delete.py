"""deploy-eventsv2-bus-source-policy-subscriber-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-eventsv2-bus-source-policy-subscriber-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "eventbridgev2", "iam", "sqs"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


#: The events service acts only for this account: no other account's bus can use the role or queue.
_SOURCE_ACCOUNT = {"StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}}
_BUS_NOT_FOUND = ("ResourceNotFoundException", "Resource does not exist")


def _source_not_found(source_arn: str) -> tuple[str, str]:
    return ("ResourceNotFoundException", f"EventSource not found: {source_arn}")


def _subscriber_not_found(subscriber_arn: str) -> tuple[str, str]:
    return ("ResourceNotFoundException", f"Subscriber not found: {subscriber_arn}")


def _template(bus_name: str, source_name: str, subscriber_name: str) -> str:
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowAccountPutEvents",
            "Effect": "Allow",
            "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
            "Action": "events:PutEvents",
            "Resource": {"Ref": "EventBus"},
        }],
    }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "EventBus": {"Type": "AWS::EventsV2::EventBus", "Properties": {"Name": bus_name}},
            "EventSource": {
                "Type": "AWS::EventsV2::EventSource",
                "Properties": {
                    "Name": source_name,
                    "EventBusArn": {"Ref": "EventBus"},
                    "Configuration": {"AwsServiceEventsConfiguration": {"AwsService": "aws.ec2"}},
                },
            },
            "ResourcePolicy": {
                "Type": "AWS::EventsV2::ResourcePolicy",
                "Properties": {"EventBusArn": {"Ref": "EventBus"}, "PolicyDocument": policy_doc},
            },
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {"AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow",
                                    "Principal": {"Service": "events.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                    "Condition": _SOURCE_ACCOUNT}],
                }},
            },
            "Queue": {"Type": "AWS::SQS::Queue"},
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                            "Condition": _SOURCE_ACCOUNT,
                        }],
                    },
                },
            },
            "RolePolicy": {
                "Type": "AWS::IAM::RolePolicy",
                "Properties": {
                    "RoleName": {"Ref": "Role"},
                    "PolicyName": "send-to-queue",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage",
                                        "Resource": {"Fn::GetAtt": ["Queue", "Arn"]}}],
                    },
                },
            },
            "Subscriber": {
                "Type": "AWS::EventsV2::Subscriber",
                "DependsOn": ["QueuePolicy", "RolePolicy"],
                "Properties": {
                    "Name": subscriber_name,
                    "EventBusArn": {"Ref": "EventBus"},
                    "InvokeConfiguration": {
                        "TargetArn": {"Fn::GetAtt": ["Queue", "Arn"]},
                        "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                        "SqsParameters": {},
                    },
                },
            },
        },
        "Outputs": {
            "EventBusArn": {"Value": {"Ref": "EventBus"}},
            "EventBusState": {"Value": {"Fn::GetAtt": ["EventBus", "State"]}},
            "EventSourceArn": {"Value": {"Ref": "EventSource"}},
            "EventSourceState": {"Value": {"Fn::GetAtt": ["EventSource", "State"]}},
            "ResourcePolicyRef": {"Value": {"Ref": "ResourcePolicy"}},
            "ResourcePolicyRevisionId": {"Value": {"Fn::GetAtt": ["ResourcePolicy", "RevisionId"]}},
            "SubscriberArn": {"Value": {"Ref": "Subscriber"}},
            "SubscriberBusName": {"Value": {"Fn::GetAtt": ["Subscriber", "BusName"]}},
            "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "RoleName": {"Value": {"Ref": "Role"}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation EventsV2 EventBus, EventSource, ResourcePolicy and Subscriber read back.

    Each Ref matches the service's listing and every property reads back, the subscriber's SQS
    queue policy and IAM role policy too; deleting the stack removes all four.
    """
    cfn = ctx.client("cloudformation")
    ebv2 = ctx.client("eventbridgev2")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    stack_name = ctx.unique_name("sim2real-behav-cfnebv2-")
    bus_name = ctx.unique_name("sim2real-behav-cfnebv2-bus-")
    source_name = ctx.unique_name("sim2real-behav-cfnebv2-src-")
    subscriber_name = ctx.unique_name("sim2real-behav-cfnebv2-sub-")

    stack_id = create_stack(ctx, cfn, stack_name,
                            _template(bus_name, source_name, subscriber_name),
                            Capabilities=["CAPABILITY_IAM"])
    created = wait_stack(cfn, stack_id)
    assert created == "CREATE_COMPLETE", (
        f"stack ended {created!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    bus_arn = outputs["EventBusArn"]
    source_arn = outputs["EventSourceArn"]
    policy_ref = outputs["ResourcePolicyRef"]
    subscriber_arn = outputs["SubscriberArn"]
    queue_arn = outputs["QueueArn"]
    role_arn = outputs["RoleArn"]

    # ---- EventBus: Ref is the bus's own ARN; DescribeEventBus agrees on Name and the GetAtt State.
    listed = [b["EventBusArn"] for b in paginate(ebv2, "list_event_buses", "EventBuses",
                                                 NamePrefix=bus_name) if b["Name"] == bus_name]
    assert listed == [bus_arn], f"ListEventBuses for {bus_name!r}: {listed!r}, Ref {bus_arn!r}"
    bus = ebv2.describe_event_bus(EventBusArn=bus_arn)
    assert bus["EventBusArn"] == bus_arn, f"DescribeEventBus ARN {bus['EventBusArn']!r} != Ref {bus_arn!r}"
    assert bus["Name"] == bus_name, f"expected Name {bus_name!r}, got {bus['Name']!r}"
    assert bus["State"] == "ACTIVE", f"expected ACTIVE, got {bus['State']!r}"
    assert outputs["EventBusState"] == bus["State"], (
        f"GetAtt EventBus.State {outputs['EventBusState']!r} != DescribeEventBus State {bus['State']!r}"
    )

    # ---- EventSource: Ref is its own ARN; DescribeEventSource agrees on the declared Configuration.
    listed = [x["EventSourceArn"] for x in paginate(ebv2, "list_event_sources", "EventSources",
                                                    EventBusArn=bus_arn)]
    assert listed == [source_arn], f"ListEventSources on the bus: {listed!r}, Ref {source_arn!r}"
    source = ebv2.describe_event_source(EventSourceArn=source_arn)
    assert source["EventSourceArn"] == source_arn, (
        f"DescribeEventSource ARN {source['EventSourceArn']!r} != Ref {source_arn!r}"
    )
    assert source["Name"] == source_name, f"expected Name {source_name!r}, got {source['Name']!r}"
    assert source["EventBusArn"] == bus_arn, (
        f"expected EventBusArn {bus_arn!r}, got {source['EventBusArn']!r}"
    )
    assert source["Configuration"] == {"AwsServiceEventsConfiguration": {"AwsService": "aws.ec2"}}, (
        f"unexpected Configuration {source['Configuration']!r}"
    )
    assert source["State"] == "ACTIVE", f"expected ACTIVE, got {source['State']!r}"
    assert outputs["EventSourceState"] == source["State"], (
        f"GetAtt EventSource.State {outputs['EventSourceState']!r} != "
        f"DescribeEventSource State {source['State']!r}"
    )

    # ---- ResourcePolicy: its Ref is the bus's own ARN (its primary identifier), not a generated
    # id; GetResourcePolicy reads back the declared document and the GetAtt RevisionId.
    assert policy_ref == bus_arn, (
        f"ResourcePolicy's Ref {policy_ref!r} must be the bus ARN {bus_arn!r}, its primary identifier"
    )
    policy = ebv2.get_resource_policy(ResourceArn=bus_arn)
    assert policy["RevisionId"] == outputs["ResourcePolicyRevisionId"], (
        f"GetResourcePolicy RevisionId {policy['RevisionId']!r} != "
        f"GetAtt ResourcePolicy.RevisionId {outputs['ResourcePolicyRevisionId']!r}"
    )
    want_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowAccountPutEvents", "Effect": "Allow",
            "Principal": {"AWS": f"arn:{partition}:iam::{ctx.account}:root"},
            "Action": "events:PutEvents", "Resource": bus_arn,
        }],
    }
    assert json.loads(policy["PolicyDocument"]) == want_doc, (
        f"expected the declared policy document {want_doc!r}, got {json.loads(policy['PolicyDocument'])!r}"
    )

    # ---- Subscriber: Ref is its own ARN; DescribeSubscriber agrees on the invoke target, the
    # role, and the GetAtt BusName resolves to the same bus DescribeEventBus already confirmed.
    listed = [x["SubscriberArn"] for x in paginate(ebv2, "list_subscribers", "Subscribers",
                                                   EventBusArn=bus_arn)]
    assert listed == [subscriber_arn], f"ListSubscribers on the bus: {listed!r}"
    subscriber = ebv2.describe_subscriber(SubscriberArn=subscriber_arn)
    assert subscriber["SubscriberArn"] == subscriber_arn, (
        f"DescribeSubscriber ARN {subscriber['SubscriberArn']!r} != Ref {subscriber_arn!r}"
    )
    assert subscriber["Name"] == subscriber_name, (
        f"expected Name {subscriber_name!r}, got {subscriber['Name']!r}"
    )
    assert subscriber["EventBusArn"] == bus_arn, (
        f"expected EventBusArn {bus_arn!r}, got {subscriber['EventBusArn']!r}"
    )
    assert subscriber["InvokeConfiguration"]["TargetArn"] == queue_arn, (
        f"expected InvokeConfiguration.TargetArn {queue_arn!r}, "
        f"got {subscriber['InvokeConfiguration']['TargetArn']!r}"
    )
    assert subscriber["InvokeConfiguration"]["RoleArn"] == role_arn, (
        f"expected InvokeConfiguration.RoleArn {role_arn!r}, "
        f"got {subscriber['InvokeConfiguration']['RoleArn']!r}"
    )
    assert subscriber["State"] == "RUNNING", f"expected RUNNING, got {subscriber['State']!r}"
    assert outputs["SubscriberBusName"] == bus["Name"], (
        f"GetAtt Subscriber.BusName {outputs['SubscriberBusName']!r} != "
        f"DescribeEventBus Name {bus['Name']!r}"
    )

    # ---- The subscriber's dependencies, read through their owners: the queue policy and the
    # role's inline policy carry the declared documents.
    attrs = sqs.get_queue_attributes(QueueUrl=outputs["QueueUrl"],
                                     AttributeNames=["Policy"])["Attributes"]
    queue_policy = json.loads(attrs["Policy"])
    source_account = {"StringEquals": {"aws:SourceAccount": ctx.account}}
    got = [(st["Effect"], st["Principal"], st["Action"], st["Resource"], st.get("Condition"))
           for st in queue_policy["Statement"]]
    want = [("Allow", {"Service": "events.amazonaws.com"}, "sqs:SendMessage", queue_arn,
             source_account)]
    assert got == want, f"queue policy statements {got!r}, expected {want!r}"
    trust = iam.get_role(RoleName=outputs["RoleName"])["Role"]["AssumeRolePolicyDocument"]
    got = [(st["Effect"], st["Principal"], st["Action"], st.get("Condition"))
           for st in trust["Statement"]]
    want = [("Allow", {"Service": "events.amazonaws.com"}, "sts:AssumeRole", source_account)]
    assert got == want, f"role trust statements {got!r}, expected {want!r}"
    role_policy = iam.get_role_policy(RoleName=outputs["RoleName"], PolicyName="send-to-queue")
    got = [(st["Effect"], st["Action"], st["Resource"])
           for st in role_policy["PolicyDocument"]["Statement"]]
    assert got == [("Allow", "sqs:SendMessage", queue_arn)], f"role policy statements {got!r}"

    # ---- Delete the stack; every resource is gone at EventBridge v2, not just at CloudFormation.
    delete_stack(cfn, stack_id)
    source_gone = _source_not_found(source_arn)
    subscriber_gone = _subscriber_not_found(subscriber_arn)
    expect_error(lambda: ebv2.describe_event_bus(EventBusArn=bus_arn), *_BUS_NOT_FOUND)
    expect_error(lambda: ebv2.describe_event_source(EventSourceArn=source_arn), *source_gone)
    expect_error(lambda: ebv2.get_resource_policy(ResourceArn=bus_arn), *_BUS_NOT_FOUND)
    expect_error(lambda: ebv2.describe_subscriber(SubscriberArn=subscriber_arn),
                 *subscriber_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
