"""deploy-sns-subscription-endpoint-change-replaces-raw-delivery-change-updates-in-place."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sns-subscription-endpoint-change-replaces-raw-delivery-change-updates-in-place"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

#: A stack or change-set transition here takes seconds to a few minutes; the bound only stops a
#: hung poll.
_DEADLINE_S = 600.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A change set classifies a Subscription Endpoint change Replacement=True and a
    RawMessageDelivery change Replacement=False; executing replaces the first subscription (new
    ARN, old gone from SNS, new points at the new endpoint) and updates the second in place.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")

    stack_name = ctx.unique_name("sim2real-behav-cfnrepl-sns-")
    stack_id = _create(ctx, cfn, stack_name, _template("QueueA", "false"))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", (
        f"create ended {_stack(cfn, stack_id)!r}"
    )

    outputs = _outputs(cfn, stack_id)
    queue_a_arn, queue_b_arn = outputs["QueueAArn"], outputs["QueueBArn"]

    old_replaced_arn = _physical_id(cfn, stack_id, "Replaced")
    old_modified_arn = _physical_id(cfn, stack_id, "Modified")

    replaced_before = sns.get_subscription_attributes(SubscriptionArn=old_replaced_arn)["Attributes"]
    assert replaced_before["Endpoint"] == queue_a_arn, replaced_before
    modified_before = sns.get_subscription_attributes(SubscriptionArn=old_modified_arn)["Attributes"]
    assert modified_before["RawMessageDelivery"] == "false", modified_before

    before = len(_events(cfn, stack_id))

    cs_name = ctx.unique_name("sim2real-behav-cfnrepl-sns-cs-")
    cfn.create_change_set(
        StackName=stack_id, ChangeSetName=cs_name,
        TemplateBody=_template("QueueB", "true"),
    )
    ctx.on_cleanup(_teardown(
        lambda: cfn.delete_change_set(StackName=stack_id, ChangeSetName=cs_name),
        "ChangeSetNotFound",
    ))
    cs = _wait_change_set(cfn, stack_id, cs_name, timeout_s=_cap(ctx, 300.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set failed: {cs.get('StatusReason')!r}"

    changes = {c["ResourceChange"]["LogicalResourceId"]: c["ResourceChange"] for c in cs["Changes"]}
    assert set(changes) == {"Replaced", "Modified"}, (
        f"the change set must report both touched resources, got {sorted(changes)}"
    )

    repl = changes["Replaced"]
    assert repl["Action"] == "Modify", f"expected Action=Modify, got {repl['Action']!r}"
    assert repl.get("Replacement") == "True", (
        f"changing the create-only Endpoint must classify Replacement=True, got "
        f"{repl.get('Replacement')!r}"
    )
    repl_targets = {
        d["Target"]["Name"]: d["Target"] for d in repl.get("Details", []) if d.get("Target", {}).get("Name")
    }
    assert repl_targets.get("Endpoint", {}).get("RequiresRecreation") == "Always", (
        f"Endpoint must report RequiresRecreation=Always, got {repl_targets!r}"
    )

    mod = changes["Modified"]
    assert mod["Action"] == "Modify", f"expected Action=Modify, got {mod['Action']!r}"
    assert mod.get("Replacement") == "False", (
        f"changing the mutable RawMessageDelivery must classify Replacement=False, got "
        f"{mod.get('Replacement')!r}"
    )
    mod_targets = {
        d["Target"]["Name"]: d["Target"] for d in mod.get("Details", []) if d.get("Target", {}).get("Name")
    }
    assert mod_targets.get("RawMessageDelivery", {}).get("RequiresRecreation") == "Never", (
        f"RawMessageDelivery must report RequiresRecreation=Never, got {mod_targets!r}"
    )

    # The change set's prediction must match what execution actually does.
    cfn.execute_change_set(StackName=stack_id, ChangeSetName=cs_name)
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_COMPLETE", (
        f"update ended {_stack(cfn, stack_id)!r}"
    )

    new_events = _events(cfn, stack_id)[before:]

    new_replaced_arn = _physical_id(cfn, stack_id, "Replaced")
    assert new_replaced_arn != old_replaced_arn, (
        f"the replacement must mint a new SubscriptionArn, still {old_replaced_arn!r}"
    )
    replaced_rows = _rows_for(new_events, "Replaced", "PhysicalResourceId")
    assert _in_order(replaced_rows, [
        ("UPDATE_IN_PROGRESS",
         "Requested update requires the creation of a new physical resource; hence creating one.",
         None),
        ("UPDATE_COMPLETE", None, new_replaced_arn),
        ("DELETE_COMPLETE", None, old_replaced_arn),
    ]), (
        "Replaced must report the replacement, complete as the new SubscriptionArn and delete "
        f"the old one, in that order: {replaced_rows!r}"
    )

    modified_arn_after = _physical_id(cfn, stack_id, "Modified")
    assert modified_arn_after == old_modified_arn, (
        f"an in-place update must keep the same SubscriptionArn {old_modified_arn!r}: "
        f"{modified_arn_after!r}"
    )
    modified_rows = _rows_for(new_events, "Modified", "PhysicalResourceId")
    assert _in_order(modified_rows, [("UPDATE_COMPLETE", None, old_modified_arn)]), (
        f"Modified must complete its update on the same SubscriptionArn: {modified_rows!r}"
    )
    modified_deletes = [r for r in modified_rows if r[0].startswith("DELETE_")]
    assert modified_deletes == [], f"an in-place update deletes nothing: {modified_deletes!r}"

    replaced_after = sns.get_subscription_attributes(SubscriptionArn=new_replaced_arn)["Attributes"]
    assert replaced_after["Endpoint"] == queue_b_arn, (
        f"the replacement subscription must point at the new endpoint {queue_b_arn!r}: "
        f"{replaced_after!r}"
    )

    gone_code, gone_message = _error(
        lambda: sns.get_subscription_attributes(SubscriptionArn=old_replaced_arn)
    )
    assert gone_code == "NotFound", (
        f"expected NotFound for the replaced subscription, got {gone_code!r}: {gone_message!r}"
    )
    assert gone_message == "Subscription does not exist", (
        f"expected 'Subscription does not exist', got {gone_message!r}"
    )

    modified_after = sns.get_subscription_attributes(SubscriptionArn=old_modified_arn)["Attributes"]
    assert modified_after["RawMessageDelivery"] == "true", (
        f"the in-place update must have applied the new RawMessageDelivery, got {modified_after!r}"
    )
    unchanged_before = {k: v for k, v in modified_before.items() if k != "RawMessageDelivery"}
    unchanged_after = {k: v for k, v in modified_after.items() if k != "RawMessageDelivery"}
    assert unchanged_after == unchanged_before, (
        f"an in-place update leaves every other subscription attribute as SNS set it: "
        f"{unchanged_before!r} -> {unchanged_after!r}"
    )


def _template(replaced_queue_logical: str, modified_raw_message_delivery: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"Tags": _TAGS}},
            "QueueA": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": _TAGS}},
            "QueueB": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": _TAGS}},
            "QueueC": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": _TAGS}},
            # Endpoint is create-only for AWS::SNS::Subscription -> changing it replaces.
            "Replaced": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "TopicArn": {"Ref": "Topic"},
                    "Protocol": "sqs",
                    "Endpoint": {"Fn::GetAtt": [replaced_queue_logical, "Arn"]},
                },
            },
            # RawMessageDelivery is updatable in place -> changing it modifies, and the Endpoint
            # is deliberately held constant (QueueC) so this resource is never replaced.
            "Modified": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "TopicArn": {"Ref": "Topic"},
                    "Protocol": "sqs",
                    "Endpoint": {"Fn::GetAtt": ["QueueC", "Arn"]},
                    "RawMessageDelivery": modified_raw_message_delivery,
                },
            },
        },
        "Outputs": {
            "QueueAArn": {"Value": {"Fn::GetAtt": ["QueueA", "Arn"]}},
            "QueueBArn": {"Value": {"Fn::GetAtt": ["QueueB", "Arn"]}},
            "QueueCArn": {"Value": {"Fn::GetAtt": ["QueueC", "Arn"]}},
        },
    })


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only the resource's own
    not_found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _cap(ctx, own_s: float, margin_s: float = 15.0) -> float:
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll(probe, done, *, timeout_s: float = _DEADLINE_S, interval_s: float = 3.0, what: str = "condition"):
    """Call ``probe()`` until ``done(result)`` holds and return the result; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in _stack(cfn, stack_id).get("Outputs", [])}


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _settle(cfn, stack_id: str, timeout_s: float = _DEADLINE_S) -> str:
    """The stack's status once no operation is in progress on it."""
    return _poll(
        lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
        timeout_s=timeout_s, what=f"stack {stack_id} settled",
    )


def _wait_change_set(cfn, stack_id: str, cs_name: str, *, timeout_s: float = 300.0) -> dict:
    """Poll DescribeChangeSet until Status is terminal; return the response."""
    return _poll(
        lambda: cfn.describe_change_set(StackName=stack_id, ChangeSetName=cs_name),
        lambda r: r["Status"] in ("CREATE_COMPLETE", "FAILED"),
        timeout_s=timeout_s, what=f"change set {cs_name}",
    )


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    status = _stack(cfn, stack_id)["StackStatus"]
    if status == "UPDATE_IN_PROGRESS":
        cfn.cancel_update_stack(StackName=stack_id)
    if status != "CREATE_IN_PROGRESS":
        status = _settle(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


def _create(ctx, cfn, name: str, body: str, **kw) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(StackName=name, TemplateBody=body, Tags=_TAGS, **kw)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _rows_for(events: list[dict], logical_id: str, *keys: str) -> list[tuple]:
    """``(ResourceStatus, ResourceStatusReason, *keys)`` for every event on ``logical_id``."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), *(e.get(k) for k in keys))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every ``wanted`` row occurs in ``rows`` in that order; a None field matches any."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row)) for row in remaining)
        for want in wanted
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
