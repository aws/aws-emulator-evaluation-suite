"""cfn-ecs-cluster-in-place-update-retained-replacement-then-inactive."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ecs-cluster-in-place-update-retained-replacement-then-inactive"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecs"]

#: Real-AWS caps: a stack transition takes seconds to minutes and the cap only stops a hung
#: poll. Every wait is also bounded by ctx.time_left().
_STACK_CAP_S = 600.0
#: A capacity provider change can take a while to show in DescribeClusters.
_CONVERGE_CAP_S = 120.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


#: The two capacity configurations: providers, then default strategy as the template states it.
#: Only FARGATE, which every Region offers (FARGATE_SPOT is not offered everywhere).
_V1 = (["FARGATE"], [{"CapacityProvider": "FARGATE", "Weight": 1}])
_V2 = (["FARGATE"], [{"CapacityProvider": "FARGATE", "Base": 2, "Weight": 3}])


def _template(name: str, capacity: tuple, revision: str) -> str:
    providers, strategy = capacity
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Cluster": {
                    "Type": "AWS::ECS::Cluster",
                    # ClusterName is create-only, so changing it replaces the cluster.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "ClusterName": name,
                        "ClusterSettings": [{"Name": "containerInsights", "Value": "disabled"}],
                        "CapacityProviders": providers,
                        "DefaultCapacityProviderStrategy": strategy,
                        "Tags": [{"Key": "revision", "Value": revision}],
                    },
                },
            },
            "Outputs": {"ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "Arn"]}}},
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
    """A CloudFormation cluster's settings, capacity providers and strategy read back as templated.

    A strategy and tag change keeps the cluster; a ClusterName change under UpdateReplacePolicy
    Retain keeps the old one ACTIVE; after the stack delete ECS describes the new one INACTIVE.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecs-cluster.html
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    first = ctx.unique_name("sim2real-cfncl-a-")
    second = ctx.unique_name("sim2real-cfncl-b-")
    stack_name = ctx.unique_name("sim2real-cfncl-stack-")
    ref = {"stack": stack_name}

    # The replaced cluster is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_cluster(ecs, first))
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view, ECS's view, the cluster takes scoped calls
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(first, _V1, "one"), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Cluster"] == first, "physical id is the ClusterName"
    first_arn = _outputs(stack)["ClusterArn"]
    _assert_arn(ctx, first_arn, "ecs", f"cluster/{first}")
    _assert_cluster(ctx, ecs, first, first_arn, _V1, "one")
    assert _services(ecs, first) == [], "a new cluster has no services"

    # ---- 2. in-place: a new default strategy and tag, the same cluster
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(first, _V2, "two"), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Cluster"] == first, "an in-place update keeps it"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Cluster"), first, "Cluster")
    _assert_cluster(ctx, ecs, first, first_arn, _V2, "two")

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new cluster, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(second, _V2, "two"), Tags=_TAGS)
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Cluster"] == second, "the stack tracks the new one"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Cluster"), first, second, "Cluster"
    )
    second_arn = _outputs(stack)["ClusterArn"]
    _assert_arn(ctx, second_arn, "ecs", f"cluster/{second}")
    _assert_cluster(ctx, ecs, second, second_arn, _V2, "two")
    _assert_cluster(ctx, ecs, first, first_arn, _V2, "two")

    # ---- 4. delete: a deleted cluster stays describable as INACTIVE; the retained one stays
    _delete_stack(ctx, cfn, ref["stack"])
    gone = _poll(
        ctx,
        lambda: _describe(ecs, second),
        lambda d: d["status"] != "ACTIVE",
        f"cluster {second} to leave ACTIVE after the stack delete",
    )
    got = (gone["clusterName"], gone["clusterArn"], gone["status"])
    want = (second, second_arn, "INACTIVE")
    assert got == want, f"DescribeClusters after the stack delete: {got!r}, expected {want!r}"
    _assert_cluster(ctx, ecs, first, first_arn, _V2, "two")


def _describe(ecs, name: str) -> dict:
    """DescribeClusters with settings and tags, reduced to the template's view."""
    resp = ecs.describe_clusters(clusters=[name], include=["SETTINGS", "TAGS"])
    assert resp.get("failures", []) == [], f"DescribeClusters {name}: {resp['failures']!r}"
    (cluster,) = resp["clusters"]
    return {
        "clusterName": cluster.get("clusterName"),
        "clusterArn": cluster.get("clusterArn"),
        "status": cluster.get("status"),
        "settings": cluster.get("settings"),
        "capacityProviders": cluster.get("capacityProviders"),
        "defaultCapacityProviderStrategy": cluster.get("defaultCapacityProviderStrategy"),
        "tags": {
            t["key"]: t["value"] for t in cluster.get("tags", []) if not t["key"].startswith("aws:")
        },
    }


def _assert_cluster(ctx, ecs, name: str, arn: str, capacity: tuple, revision: str) -> None:
    """DescribeClusters reports the template's cluster exactly (capacity changes converge)."""
    providers, strategy = capacity
    want = {
        "clusterName": name,
        "clusterArn": arn,
        "status": "ACTIVE",
        "settings": [{"name": "containerInsights", "value": "disabled"}],
        "capacityProviders": providers,
        "defaultCapacityProviderStrategy": [
            {
                "capacityProvider": s["CapacityProvider"],
                "weight": s["Weight"],
                "base": s.get("Base", 0),
            }
            for s in strategy
        ],
        "tags": {"sim2real": CHECK, "revision": revision},
    }
    got = _poll(
        ctx, lambda: _describe(ecs, name), lambda d: d == want, f"cluster {name} as templated"
    )
    assert got == want, f"DescribeClusters {name}: {got!r}, expected {want!r}"


def _services(ecs, name: str) -> list[str]:
    return [
        a
        for page in ecs.get_paginator("list_services").paginate(cluster=name)
        for a in page["serviceArns"]
    ]


def _delete_cluster(ecs, name: str) -> None:
    """Delete the retained cluster; one already gone is done."""
    try:
        ecs.delete_cluster(cluster=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


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
