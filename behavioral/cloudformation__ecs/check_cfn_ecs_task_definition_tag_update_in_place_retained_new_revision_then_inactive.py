"""cfn-ecs-task-definition-tag-update-in-place-retained-new-revision-then-inactive."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ecs-task-definition-tag-update-in-place-retained-new-revision-then-inactive"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecs"]

#: Real-AWS caps: a stack transition takes seconds to minutes and the cap only stops a hung
#: poll. Every wait is also bounded by ctx.time_left().
_STACK_CAP_S = 600.0
#: Revision listings and statuses can lag a register or deregister.
_CONVERGE_CAP_S = 120.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

_IMAGE = "public.ecr.aws/docker/library/busybox:latest"


def _template(family: str, memory: str, revision_tag: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "TaskDef": {
                    "Type": "AWS::ECS::TaskDefinition",
                    # Every property but Tags is create-only: a change registers a new revision.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Family": family,
                        "RequiresCompatibilities": ["FARGATE"],
                        "NetworkMode": "awsvpc",
                        "Cpu": "256",
                        "Memory": memory,
                        "ContainerDefinitions": [
                            {"Name": "app", "Image": _IMAGE, "Essential": True}
                        ],
                        "Tags": [{"Key": "revision", "Value": revision_tag}],
                    },
                },
            },
            "Outputs": {"Arn": {"Value": {"Fn::GetAtt": ["TaskDef", "TaskDefinitionArn"]}}},
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation task definition is revision 1 of its family, as templated.

    A Tags change keeps the revision; a Memory change under UpdateReplacePolicy Retain registers
    revision 2 and keeps 1 ACTIVE; the stack delete leaves 2 INACTIVE and the family resolving to 1.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecs-taskdefinition.html
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-cfntd-")
    stack_name = ctx.unique_name("sim2real-cfntd-stack-")
    ref = {"stack": stack_name}

    # Revisions outlive the stack (the retained one ACTIVE, the stack's own INACTIVE).
    ctx.on_cleanup(lambda: _retire_family(ecs, family))
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view, ECS's view, the family resolves to revision 1
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(family, "512", "one"), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    first = _outputs(stack)["Arn"]
    _assert_arn(ctx, first, "ecs", f"task-definition/{family}:1")
    assert _physical_ids(cfn, ref["stack"])["TaskDef"] == first, "physical id is the revision ARN"
    _assert_revision(ecs, first, family, 1, "512", "ACTIVE", "one")
    _assert_family(ctx, ecs, family, [first], first)

    # ---- 2. in-place: a Tags change, the same revision and no new one
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(family, "512", "two"), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _outputs(stack)["Arn"] == first, "a tag update keeps the revision"
    assert _physical_ids(cfn, ref["stack"])["TaskDef"] == first, "an in-place update keeps it"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "TaskDef"), first, "TaskDef")
    # TagResource is eventually consistent: poll the tag before the exact read-back.
    _poll(
        ctx,
        lambda: _tags(ecs, first),
        lambda got: got.get("revision") == "two",
        f"{first} to carry the updated revision tag",
    )
    _assert_revision(ecs, first, family, 1, "512", "ACTIVE", "two")
    _assert_family(ctx, ecs, family, [first], first)

    # ---- 3. replacement under UpdateReplacePolicy Retain: revision 2, revision 1 still ACTIVE
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(family, "1024", "two"), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second = _outputs(stack)["Arn"]
    _assert_arn(ctx, second, "ecs", f"task-definition/{family}:2")
    assert _physical_ids(cfn, ref["stack"])["TaskDef"] == second, "the stack tracks revision 2"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "TaskDef"), first, second, "TaskDef"
    )
    _assert_revision(ecs, second, family, 2, "1024", "ACTIVE", "two")
    _assert_revision(ecs, first, family, 1, "512", "ACTIVE", "two")
    _assert_family(ctx, ecs, family, [first, second], second)

    # ---- 4. delete: revision 2 is deregistered, the family falls back to the kept revision 1
    _delete_stack(ctx, cfn, ref["stack"])
    _poll(
        ctx,
        lambda: ecs.describe_task_definition(taskDefinition=second)["taskDefinition"]["status"],
        lambda status: status == "INACTIVE",
        f"{second} to be INACTIVE after the stack delete",
    )
    _assert_revision(ecs, second, family, 2, "1024", "INACTIVE", "two")
    _assert_family(ctx, ecs, family, [first], first)


def _assert_revision(ecs, arn, family, revision, memory, status, revision_tag) -> None:
    """DescribeTaskDefinition reports the template's revision exactly."""
    resp = ecs.describe_task_definition(taskDefinition=arn, include=["TAGS"])
    td = resp["taskDefinition"]
    got = {
        "taskDefinitionArn": td.get("taskDefinitionArn"),
        "family": td.get("family"),
        "revision": td.get("revision"),
        "status": td.get("status"),
        "requiresCompatibilities": td.get("requiresCompatibilities"),
        "networkMode": td.get("networkMode"),
        "cpu": td.get("cpu"),
        "memory": td.get("memory"),
        "containers": [
            (c.get("name"), c.get("image"), c.get("essential"))
            for c in td.get("containerDefinitions", [])
        ],
        "tags": {
            t["key"]: t["value"] for t in resp.get("tags", []) if not t["key"].startswith("aws:")
        },
    }
    want = {
        "taskDefinitionArn": arn,
        "family": family,
        "revision": revision,
        "status": status,
        "requiresCompatibilities": ["FARGATE"],
        "networkMode": "awsvpc",
        "cpu": "256",
        "memory": memory,
        "containers": [("app", _IMAGE, True)],
        "tags": {"sim2real": CHECK, "revision": revision_tag},
    }
    assert got == want, f"DescribeTaskDefinition {arn}: {got!r}, expected {want!r}"


def _assert_family(ctx, ecs, family: str, active: list[str], latest: str) -> None:
    """The family lists exactly *active* as ACTIVE, and the bare family resolves to *latest*."""

    def read():
        listed = [
            a
            for page in ecs.get_paginator("list_task_definitions").paginate(
                familyPrefix=family, status="ACTIVE", sort="ASC"
            )
            for a in page["taskDefinitionArns"]
        ]
        resolved = ecs.describe_task_definition(taskDefinition=family)["taskDefinition"]
        return listed, resolved["taskDefinitionArn"]

    _poll(
        ctx, read, lambda got: got == (active, latest), f"family {family}: {active!r}, {latest!r}"
    )


def _tags(ecs, arn: str) -> dict[str, str]:
    resp = ecs.describe_task_definition(taskDefinition=arn, include=["TAGS"])
    return {t["key"]: t["value"] for t in resp.get("tags", [])}


def _retire_family(ecs, family: str) -> None:
    """Retire every revision of *family*, also ones a failed create or update never reported."""
    arns = [
        arn
        for status in ("ACTIVE", "INACTIVE")
        for page in ecs.get_paginator("list_task_definitions").paginate(
            familyPrefix=family, status=status
        )
        for arn in page["taskDefinitionArns"]
        if arn.rsplit("/", 1)[-1].rsplit(":", 1)[0] == family
    ]
    for arn in arns:
        _retire_task_definition(ecs, arn)


def _retire_task_definition(ecs, task_definition_arn: str) -> None:
    """Deregister then delete a task definition revision; an already-gone one is fine."""
    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition_arn)[
            "taskDefinition"
        ]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=task_definition_arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[task_definition_arn]).get(
        "failures", []
    )
    if failures:
        raise RuntimeError(f"task definition {task_definition_arn} teardown failed: {failures}")


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. A teardown passes ctx=None
    and waits the full cap; in a teardown, ctx.time_left() counts down the runner's cleanup timeout.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Its waits use their fixed caps, not the runner's remaining time (see _budget_s).
    """
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"])
    _delete_stack(None, cfn, stack["StackId"])


def _poll(ctx, read, done, what: str, cap_s: float = _CONVERGE_CAP_S):
    """Poll ``read()`` until ``done(value)``; return that value (an eventually consistent read)."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if done(value):
            return value
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while waiting for {what}; last {value!r}")
            raise AssertionError(f"{what} not reached after {timeout:.0f}s; last {value!r}")
        time.sleep(_POLL_S)


def _assert_arn(ctx, arn: str, service: str, resource: str) -> None:
    """*arn* names *resource* of *service* in the run's region and account (any partition)."""
    parts = arn.split(":", 5)
    got = (parts[0], parts[2:]) if len(parts) == 6 else (arn, [])
    want = ("arn", [service, ctx.region, ctx.account, resource])
    assert got == want, f"ARN {arn!r} must be arn:<partition>:{':'.join(want[1])}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
