"""stack-event-detailed-status-configuration-complete-precedes-create-complete."""

from __future__ import annotations

import json
import time
from urllib.parse import urlparse

from behavioral_harness import tags

CHECK = "stack-event-detailed-status-configuration-complete-precedes-create-complete"
GROUP = "stack-events"
SERVICES = ["cloudformation", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An SQS queue's create events carry DetailedStatus CONFIGURATION_COMPLETE before CREATE_COMPLETE,
    and the queue they describe exists in SQS with the template's attribute.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_StackEvent.html"""
    cfn, sqs = ctx.client("cloudformation"), ctx.client("sqs")
    queue = ctx.unique_name("sim2real-cfn-detail-")
    stack_id = _create(ctx, cfn, ctx.unique_name("sim2real-cfn-detail-"), _template(queue))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"

    rows = _of(_rows(_events(cfn, stack_id), "DetailedStatus"), "Queue")
    assert rows == [
        ("CREATE_IN_PROGRESS", None, None),
        ("CREATE_IN_PROGRESS", "Resource creation Initiated", None),
        ("CREATE_IN_PROGRESS", "Eventual consistency check initiated", "CONFIGURATION_COMPLETE"),
        ("CREATE_COMPLETE", None, None),
    ], f"queue events (status, reason, DetailedStatus): {rows!r}"

    url = sqs.get_queue_url(QueueName=queue)["QueueUrl"]
    physical = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Queue")["StackResourceDetail"]
    # The URL's host part is endpoint-specific, so the /<account>/<name> path identifies the queue.
    paths = (urlparse(physical["PhysicalResourceId"]).path, urlparse(url).path)
    assert paths == (f"/{ctx.account}/{queue}",) * 2, (
        f"physical id {physical['PhysicalResourceId']!r} vs queue URL {url!r}")
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]
    assert attrs == {"VisibilityTimeout": "45"}, f"queue attributes: {attrs!r}"


def _template(queue: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Queue": {"Type": "AWS::SQS::Queue",
                                "Properties": {"QueueName": queue, "VisibilityTimeout": 45}}},
    })


# ===== helpers =====

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: A stack transition here takes seconds to a few minutes; the bound only stops a hung poll.
_DEADLINE_S = 600.0


def _cap(ctx, own_s, margin_s=15.0):
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


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(cfn, stack_id: str, timeout_s: float = _DEADLINE_S) -> str:
    """The stack's status once no operation is in progress on it."""
    return _poll(lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=timeout_s, what=f"stack {stack_id} settled")


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE by id; DELETE_FAILED or a timeout raises."""
    status = _stack(cfn, stack_id)["StackStatus"]
    if status == "UPDATE_IN_PROGRESS":
        cfn.cancel_update_stack(StackName=stack_id)
    if status != "CREATE_IN_PROGRESS":
        status = _settle(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _stack(cfn, stack_id)["StackStatus"],
                  lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}")


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


def _rows(events: list[dict], *keys: str) -> list[tuple]:
    """``(LogicalResourceId, ResourceStatus, ResourceStatusReason, *keys)`` per event; absent is None."""
    return [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"),
             *(e.get(k) for k in keys)) for e in events]


def _of(rows: list[tuple], logical_id: str) -> list[tuple]:
    """The rows of one logical resource, without the logical id."""
    return [r[1:] for r in rows if r[0] == logical_id]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
