"""stack-refactor-actions-ordering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-refactor-actions-ordering"
GROUP = "ordering"
SERVICES = ["cloudformation"]

_STACK_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListStackRefactorActions returns a stable, deterministic action order matching what actually executes."""
    cfn = ctx.client("cloudformation")

    stack1_name = ctx.unique_name("sim2real-refactor1-")
    stack2_name = ctx.unique_name("sim2real-refactor2-")

    stack1_v1 = _template({"TopicA": "TopicA", "Keep1": "Keep1"})
    stack2_v1 = _template({"TopicC": "TopicC", "Keep2": "Keep2"})

    stack1_id = cfn.create_stack(StackName=stack1_name, TemplateBody=json.dumps(stack1_v1))["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_when_settled(cfn, stack1_id))
    stack2_id = cfn.create_stack(StackName=stack2_name, TemplateBody=json.dumps(stack2_v1))["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_when_settled(cfn, stack2_id))

    stack1_status = _wait_stack_terminal(cfn, stack1_id)
    assert stack1_status == "CREATE_COMPLETE", f"stack1 expected CREATE_COMPLETE, got {stack1_status}"
    stack2_status = _wait_stack_terminal(cfn, stack2_id)
    assert stack2_status == "CREATE_COMPLETE", f"stack2 expected CREATE_COMPLETE, got {stack2_status}"

    # swap TopicA (stack1 -> stack2) and TopicC (stack2 -> stack1); each stack stays non-empty
    stack1_v2 = _template({"Keep1": "Keep1", "TopicC": "TopicC"})
    stack2_v2 = _template({"Keep2": "Keep2", "TopicA": "TopicA"})
    resource_mappings = [
        {"Source": {"StackName": stack1_name, "LogicalResourceId": "TopicA"},
         "Destination": {"StackName": stack2_name, "LogicalResourceId": "TopicA"}},
        {"Source": {"StackName": stack2_name, "LogicalResourceId": "TopicC"},
         "Destination": {"StackName": stack1_name, "LogicalResourceId": "TopicC"}},
    ]

    refactor_id = cfn.create_stack_refactor(
        StackDefinitions=[
            {"StackName": stack1_name, "TemplateBody": json.dumps(stack1_v2)},
            {"StackName": stack2_name, "TemplateBody": json.dumps(stack2_v2)},
        ],
        ResourceMappings=resource_mappings,
    )["StackRefactorId"]

    _wait_refactor_status(cfn, refactor_id, {"CREATE_COMPLETE", "CREATE_FAILED"})
    refactor = cfn.describe_stack_refactor(StackRefactorId=refactor_id)
    assert refactor["Status"] == "CREATE_COMPLETE", refactor

    actions_1 = _list_all_actions(cfn, refactor_id)
    actions_2 = _list_all_actions(cfn, refactor_id)
    assert len(actions_1) == 2, f"expected 2 MOVE actions, got {actions_1}"
    assert actions_1 == actions_2, "ListStackRefactorActions returned a different order across repeated calls"

    # the two planned moves must be exactly the two we asked for, not just the right shape.
    # real CloudFormation echoes ResourceMapping StackName as the stack ARN (StackId), not
    # the plain name that was submitted in the request.
    expected_mappings = {
        _mapping_key({"Source": {"StackName": stack1_id, "LogicalResourceId": "TopicA"},
                       "Destination": {"StackName": stack2_id, "LogicalResourceId": "TopicA"}}),
        _mapping_key({"Source": {"StackName": stack2_id, "LogicalResourceId": "TopicC"},
                       "Destination": {"StackName": stack1_id, "LogicalResourceId": "TopicC"}}),
    }
    seen_mappings = set()
    for action in actions_1:
        assert action["Action"] == "MOVE", f"expected Action=MOVE, got {action['Action']!r}: {action}"
        assert action["Entity"] == "RESOURCE", f"expected Entity=RESOURCE, got {action['Entity']!r}: {action}"
        seen_mappings.add(_mapping_key(action["ResourceMapping"]))
    assert seen_mappings == expected_mappings, (
        f"listed ResourceMappings do not match the requested moves: "
        f"expected {expected_mappings}, got {seen_mappings}"
    )

    cfn.execute_stack_refactor(StackRefactorId=refactor_id)
    _wait_refactor_status(cfn, refactor_id, {"EXECUTE_COMPLETE", "EXECUTE_FAILED"}, key="ExecutionStatus")
    refactor = cfn.describe_stack_refactor(StackRefactorId=refactor_id)
    assert refactor["ExecutionStatus"] == "EXECUTE_COMPLETE", refactor

    # the planned actions must match what actually happened. A cross-stack MOVE
    # keeps the physical resource but is CREATE_COMPLETE at the destination stack,
    # not UPDATE_COMPLETE.
    topic_a_in_stack2 = cfn.describe_stack_resource(StackName=stack2_id, LogicalResourceId="TopicA")
    topic_a_status = topic_a_in_stack2["StackResourceDetail"]["ResourceStatus"]
    assert topic_a_status == "CREATE_COMPLETE", (
        f"TopicA in stack2 expected CREATE_COMPLETE, got {topic_a_status}"
    )
    topic_c_in_stack1 = cfn.describe_stack_resource(StackName=stack1_id, LogicalResourceId="TopicC")
    topic_c_status = topic_c_in_stack1["StackResourceDetail"]["ResourceStatus"]
    assert topic_c_status == "CREATE_COMPLETE", (
        f"TopicC in stack1 expected CREATE_COMPLETE, got {topic_c_status}"
    )

    code, msg = _client_error(
        lambda: cfn.describe_stack_resource(StackName=stack1_id, LogicalResourceId="TopicA"),
        "DescribeStackResource of TopicA in stack1 after the move",
    )
    assert code == "ValidationError", f"TopicA should no longer be addressable in stack1, got {code!r}"
    assert msg == f"Resource TopicA does not exist for stack {stack1_id}", msg

    # The refactor's own stack updates settle after EXECUTE_COMPLETE; wait for both stacks
    # so teardown can delete them.
    for stack_id in (stack1_id, stack2_id):
        settled = _poll_stack_settled(cfn, stack_id)
        assert settled == "UPDATE_COMPLETE", f"{stack_id} settled in {settled}"


def _template(logical_to_display: dict) -> dict:
    return {
        "Resources": {
            logical_id: {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": display}}
            for logical_id, display in logical_to_display.items()
        }
    }


def _mapping_key(resource_mapping: dict) -> tuple:
    source = resource_mapping["Source"]
    destination = resource_mapping["Destination"]
    return (
        source["StackName"], source["LogicalResourceId"],
        destination["StackName"], destination["LogicalResourceId"],
    )


def _client_error(fn, what):
    """Return (code, message) of the ClientError fn() raises; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


def _list_all_actions(cfn, refactor_id: str) -> list:
    actions: list = []
    kwargs = {"StackRefactorId": refactor_id}
    while True:
        resp = cfn.list_stack_refactor_actions(**kwargs)
        actions.extend(resp.get("StackRefactorActions", []))
        token = resp.get("NextToken")
        if not token:
            return actions
        kwargs["NextToken"] = token


def _wait_refactor_status(cfn, refactor_id: str, terminal: set, key: str = "Status", timeout_s: float = 240.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stack_refactor(StackRefactorId=refactor_id)[key]
        if status in terminal:
            return
        time.sleep(3)
    raise AssertionError(f"stack refactor {key} did not reach a terminal state within {timeout_s}s (last={status})")


def _delete_stack_when_settled(cfn, stack_id: str) -> None:
    """Wait the stack out of _IN_PROGRESS (a timeout raises), then delete it by StackId and poll
    to DELETE_COMPLETE, so an earlier assertion failure still leaves cleanup able to delete."""
    _poll_stack_settled(cfn, stack_id)
    _teardown_stack(cfn, stack_id)


def _poll_stack_settled(cfn, stack_id: str, timeout_s: float = 180.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id} still in progress after {timeout_s}s (last={status})")


def _wait_stack_terminal(cfn, stack_name: str, timeout_s: float = 180.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        stacks = resp.get("Stacks", [])
        if not stacks:
            return "DELETE_COMPLETE"
        status = stacks[0]["StackStatus"]
        if status in _STACK_TERMINAL:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach terminal status within {timeout_s}s (last={status})")


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
