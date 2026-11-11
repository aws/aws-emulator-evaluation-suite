"""events-chronological-ordering."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-chronological-ordering"
GROUP = 'stack_events'
SERVICES = ['cloudformation']


def _describe_stack(cf, name):
    stacks = cf.describe_stacks(StackName=name).get("Stacks", [])
    return stacks[0] if stacks else None

def _wait_stack(cf, name, targets, timeout_s=180):
    """Poll DescribeStacks until StackStatus is in `targets`; return the stack dict."""
    deadline = time.monotonic() + timeout_s
    stack = None
    while time.monotonic() < deadline:
        try:
            stack = _describe_stack(cf, name)
        except ClientError:
            stack = None
        if stack is not None and stack.get("StackStatus") in targets:
            return stack
        time.sleep(3)
    raise AssertionError(f"stack {name} did not reach {targets} within {timeout_s}s (last={stack})")

def _expect_error(fn):
    """Call fn(); return the raised ClientError. Raise if fn() succeeds unexpectedly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _parameterized_topic_template(logical_id="Topic", default="v1"):
    return json.dumps(
        {
            "Parameters": {"TagValue": {"Type": "String", "Default": default}},
            "Resources": {
                logical_id: {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"Tags": [{"Key": "probe", "Value": {"Ref": "TagValue"}}]},
                }
            },
            "Outputs": {"TopicArn": {"Value": {"Ref": logical_id}}},
        }
    )


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStackEvents and DescribeEvents return events newest-first; DescribeEvents scopes
    to one operation by OperationId, spans all by StackName, and rejects a call with neither."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-events-")
    cf.create_stack(StackName=name, TemplateBody=_parameterized_topic_template())
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    created = _wait_stack(cf, name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})
    assert created["StackStatus"] == "CREATE_COMPLETE", created.get("StackStatusReason")

    create_ops = created.get("LastOperations", [])
    assert create_ops, "DescribeStacks must report the operation that just completed"
    create_op_id = create_ops[0]["OperationId"]
    assert create_ops[0]["OperationType"] == "CREATE_STACK", create_ops[0]

    cf.update_stack(
        StackName=name,
        UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "TagValue", "ParameterValue": "v2"}],
    )
    updated = _wait_stack(cf, name, {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE"})
    assert updated["StackStatus"] == "UPDATE_COMPLETE", updated.get("StackStatusReason")

    update_ops = updated.get("LastOperations", [])
    assert update_ops, "DescribeStacks must report the update operation"
    update_op_id = update_ops[0]["OperationId"]
    assert update_ops[0]["OperationType"] == "UPDATE_STACK", update_ops[0]
    assert update_op_id != create_op_id

    # -- DescribeStackEvents: strict reverse-chronological order --------
    events = cf.describe_stack_events(StackName=name)["StackEvents"]
    assert len(events) >= 2
    timestamps = [e["Timestamp"] for e in events]
    assert timestamps == sorted(timestamps, reverse=True), "StackEvents must be newest-first"
    assert events[0]["ResourceType"] == "AWS::CloudFormation::Stack"
    assert events[0]["ResourceStatus"] == "UPDATE_COMPLETE"

    # -- DescribeEvents(StackName=...): spans both operations, newest-first --
    all_op_events = []
    token = None
    while True:
        kwargs = {"StackName": name}
        if token:
            kwargs["NextToken"] = token
        resp = cf.describe_events(**kwargs)
        all_op_events.extend(resp.get("OperationEvents", []))
        token = resp.get("NextToken")
        if not token:
            break
    assert len(all_op_events) >= 2
    op_timestamps = [e["Timestamp"] for e in all_op_events]
    assert op_timestamps == sorted(op_timestamps, reverse=True), "OperationEvents must be newest-first"
    seen_op_ids = {e["OperationId"] for e in all_op_events if e.get("OperationId")}
    assert {create_op_id, update_op_id}.issubset(seen_op_ids), seen_op_ids
    assert all_op_events[0]["OperationId"] == update_op_id, (
        "the newest operation event must belong to the latest operation"
    )

    # -- DescribeEvents(OperationId=...): scoped strictly to that operation --
    create_scoped = cf.describe_events(OperationId=create_op_id)["OperationEvents"]
    assert create_scoped, "no events returned for the create operation"
    assert all(e.get("OperationId") == create_op_id for e in create_scoped), create_scoped
    create_scoped_ts = [e["Timestamp"] for e in create_scoped]
    assert create_scoped_ts == sorted(create_scoped_ts, reverse=True)

    update_scoped = cf.describe_events(OperationId=update_op_id)["OperationEvents"]
    assert update_scoped, "no events returned for the update operation"
    assert all(e.get("OperationId") == update_op_id for e in update_scoped), update_scoped
    # The two operations' event sets must not bleed into one another.
    create_event_ids = {e["EventId"] for e in create_scoped}
    update_event_ids = {e["EventId"] for e in update_scoped}
    assert create_event_ids.isdisjoint(update_event_ids)

    # DescribeEvents requires one of ChangeSetName/OperationId/StackName.
    err = _expect_error(lambda: cf.describe_events()).response["Error"]
    assert err["Code"] == "ValidationError", (
        f"DescribeEvents with no identifying parameter: expected ValidationError, got {err['Code']!r}"
    )
    expected_message = "One of ChangeSetName, OperationId or StackName must be specified."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
