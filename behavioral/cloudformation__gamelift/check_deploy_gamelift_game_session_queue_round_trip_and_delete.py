"""deploy-gamelift-game-session-queue-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-gamelift-game-session-queue-round-trip-and-delete"
GROUP = "cloudformation"
SERVICES = ["cloudformation", "gamelift"]

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


# ---- Check-specific: the template, then run(). ----

_TIMEOUT_SECONDS = 20


def _template(name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue": {
                "Type": "AWS::GameLift::GameSessionQueue",
                "Properties": {"Name": name, "TimeoutInSeconds": _TIMEOUT_SECONDS},
            },
        },
        "Outputs": {
            "QueueName": {"Value": {"Ref": "Queue"}},
            "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::GameLift::GameSessionQueue is a real GameLift queue:
    DescribeGameSessionQueues reflects its Name, TimeoutInSeconds and Arn, and deleting the
    stack removes it from GameLift's own queue list, not just from the stack.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-gamelift-gamesessionqueue.html
    """
    gl = ctx.client("gamelift")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-glqueue-")
    name = ctx.unique_name("sim2real-glqueue-name-")

    stack_id = create_stack(ctx, cfn, stack, _template(name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    queue_name, queue_arn = outputs["QueueName"], outputs["QueueArn"]
    assert queue_name == name, f"Ref output {queue_name!r} does not equal the declared Name {name!r}"

    queues = gl.describe_game_session_queues(Names=[name])["GameSessionQueues"]
    assert len(queues) == 1, f"expected one queue named {queue_name!r}, got {queues!r}"
    queue = queues[0]
    assert queue["Name"] == name, f"expected Name {name!r}, GameLift reports {queue['Name']!r}"
    assert queue["GameSessionQueueArn"] == queue_arn, (
        f"expected Arn {queue_arn!r}, GameLift reports {queue['GameSessionQueueArn']!r}"
    )
    assert queue["TimeoutInSeconds"] == _TIMEOUT_SECONDS, (
        f"expected TimeoutInSeconds {_TIMEOUT_SECONDS}, GameLift reports {queue['TimeoutInSeconds']!r}"
    )

    delete_stack(cfn, stack_id)

    # GameSessionQueue has no tombstone: a deleted queue drops out of DescribeGameSessionQueues
    # entirely rather than erroring, so the absence read must use the same accepted name.
    after = gl.describe_game_session_queues(Names=[name])["GameSessionQueues"]
    assert after == [], f"expected the deleted queue to be gone, GameLift still reports {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
