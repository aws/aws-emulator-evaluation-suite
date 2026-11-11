"""cfn-rds-db-subnet-group-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-rds-db-subnet-group-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "rds"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: A deleted subnet group stops resolving within seconds; the bound only stops a hung poll.
_GONE_S = 60.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
#: DeleteDBSubnetGroup of a group that does not exist; formatted with the group name.
_DELETE_NOT_FOUND = ("DBSubnetGroupNotFoundFault", "DB subnet group '{name}' does not exist.")
_DESCRIPTION_V1 = "sim2real subnet group, first description"
_DESCRIPTION_V2 = "sim2real subnet group, updated description"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An AWS::RDS::DBSubnetGroup survives create, in-place update, retained replacement and delete.

    RDS resolves the templated subnets to their zones in the VPC; a description change keeps the
    group; a DBSubnetGroupName change under UpdateReplacePolicy Retain keeps the old group too.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbsubnetgroup.html
    """
    cfn = ctx.client("cloudformation")
    rds = ctx.client("rds")
    network = ctx.network()
    # A subnet group needs subnets in at least two zones; the shared network has one per zone.
    zones = network.availability_zones[:2]
    subnets = {network.subnets[z]: z for z in zones}

    stack_name = ctx.unique_name("sim2real-cfnreal-dbsg-")
    group_v1 = ctx.unique_name("sim2real-cfnreal-dbsg-a-")
    group_v2 = ctx.unique_name("sim2real-cfnreal-dbsg-b-")

    # The replaced group outlives the stack, so the check deletes it itself.
    ctx.on_cleanup(lambda: _delete_group(rds, group_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, RDS view -------------------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(group_v1, _DESCRIPTION_V1, list(subnets)),
        Tags=_TAGS,
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    _assert_tracks(cfn, stack_id, "SubnetGroup", group_v1)
    group = _group(rds, group_v1)
    _assert_group(group, group_v1, _DESCRIPTION_V1, network.vpc_id, subnets)
    outputs = _outputs(cfn, stack_id)
    assert outputs == {"Arn": group["DBSubnetGroupArn"]}, (
        f"GetAtt DBSubnetGroupArn must be RDS's DBSubnetGroupArn: {outputs!r} vs {group!r}"
    )
    arn_v1 = group["DBSubnetGroupArn"]

    # ---- 2. in-place update of the mutable DBSubnetGroupDescription -------------------------
    rows = _update(
        ctx,
        cfn,
        stack_id,
        "SubnetGroup",
        _template(group_v1, _DESCRIPTION_V2, list(subnets)),
    )
    _assert_updated_in_place(rows, group_v1)
    _assert_tracks(cfn, stack_id, "SubnetGroup", group_v1)
    group = _group(rds, group_v1)
    _assert_group(group, group_v1, _DESCRIPTION_V2, network.vpc_id, subnets)
    assert group["DBSubnetGroupArn"] == arn_v1, f"an in-place update keeps {arn_v1!r}: {group!r}"

    # ---- 3. DBSubnetGroupName forces replacement; UpdateReplacePolicy Retain keeps the old --
    rows = _update(
        ctx,
        cfn,
        stack_id,
        "SubnetGroup",
        _template(group_v2, _DESCRIPTION_V2, list(subnets)),
    )
    _assert_replaced_and_retained(rows, group_v1, group_v2)
    _assert_tracks(cfn, stack_id, "SubnetGroup", group_v2)
    _assert_group(_group(rds, group_v2), group_v2, _DESCRIPTION_V2, network.vpc_id, subnets)
    _assert_group(_group(rds, group_v1), group_v1, _DESCRIPTION_V2, network.vpc_id, subnets)

    # ---- 4. DeleteStack: the group it owns is gone, the retained one stays ------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    gone = ("DBSubnetGroupNotFoundFault", f"DB Subnet group '{group_v2}' not found.")
    got = _poll(
        ctx,
        lambda: _refusal(lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=group_v2)),
        lambda e: e[0] != "<exists>",
        cap_s=_GONE_S,
        what=f"DescribeDBSubnetGroups of {group_v2!r} refused after DeleteStack",
    )
    assert got == gone, f"DescribeDBSubnetGroups after DeleteStack: {got!r}, not {gone!r}"
    _assert_group(_group(rds, group_v1), group_v1, _DESCRIPTION_V2, network.vpc_id, subnets)


def _template(name: str, description: str, subnet_ids: list[str]) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "SubnetGroup": {
                    "Type": "AWS::RDS::DBSubnetGroup",
                    # DBSubnetGroupName is create-only, so a new name replaces the group.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "DBSubnetGroupName": name,
                        "DBSubnetGroupDescription": description,
                        "SubnetIds": subnet_ids,
                    },
                },
            },
            "Outputs": {"Arn": {"Value": {"Fn::GetAtt": ["SubnetGroup", "DBSubnetGroupArn"]}}},
        }
    )


def _outputs(cfn, stack_id: str) -> dict:
    stack = _stack(cfn, stack_id)
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _group(rds, name: str) -> dict:
    found = rds.describe_db_subnet_groups(DBSubnetGroupName=name)["DBSubnetGroups"]
    assert len(found) == 1, f"RDS must hold exactly one subnet group {name!r}, got {found!r}"
    return found[0]


def _assert_group(group: dict, name: str, description: str, vpc_id: str, subnets: dict) -> None:
    """RDS's view: the group's name, description, VPC, status and each subnet's zone and status."""
    got = (
        group["DBSubnetGroupName"],
        group["DBSubnetGroupDescription"],
        group["VpcId"],
        group["SubnetGroupStatus"],
    )
    want = (name, description, vpc_id, "Complete")
    assert got == want, f"DescribeDBSubnetGroups must report {want!r}, got {got!r}"
    resolved = {
        s["SubnetIdentifier"]: (s["SubnetAvailabilityZone"]["Name"], s["SubnetStatus"])
        for s in group["Subnets"]
    }
    expected = {subnet: (zone, "Active") for subnet, zone in subnets.items()}
    assert resolved == expected, f"RDS must resolve the subnets as {expected!r}, got {resolved!r}"


def _refusal(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises, or an <exists> pair while it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    return "<exists>", "the call still succeeds"


def _delete_group(rds, name: str) -> None:
    """Teardown: delete the subnet group; a group that does not exist is done."""
    try:
        rds.delete_db_subnet_group(DBSubnetGroupName=name)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        gone = (_DELETE_NOT_FOUND[0], _DELETE_NOT_FOUND[1].format(name=name))
        if (err.get("Code"), err.get("Message")) != gone:
            raise


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    """Call probe() until done(result) holds and return it; ctx=None (teardown) is not budgeted."""
    timeout_s = cap_s if ctx is None else _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    """The stack once no operation (cleanup phase included) is in progress on it."""
    return _poll(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled",
    )


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _assert_tracks(cfn, stack_id: str, logical_id: str, expected: str) -> None:
    """CloudFormation's view: the stack resource carries the expected PhysicalResourceId."""
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"the stack must track {logical_id} as {expected!r}, got {got!r}"


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _update(ctx, cfn, stack_id: str, logical_id: str, body: str, **kw) -> list[tuple]:
    """UpdateStack to body, assert UPDATE_COMPLETE and return the update's rows for logical_id.

    A row is (ResourceStatus, ResourceStatusReason, PhysicalResourceId), oldest first.
    """
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, **kw)
    stack = _settle(ctx, cfn, stack_id)
    events = _events(cfn, stack_id)[before:]
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; {failed!r}"
    )
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every wanted row occurs in rows in that order; a None field matches any value."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row, strict=True)) for row in remaining)
        for want in wanted
    )


def _assert_updated_in_place(rows: list[tuple], physical: str) -> None:
    """The update completed on the same physical id and reported no replacement or delete."""
    assert _in_order(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert replacing == [], f"an in-place update must not replace anything: {replacing!r}"


def _assert_replaced_and_retained(rows: list[tuple], old: str, new: str) -> None:
    """The update reported a replacement, completed on the new id and skipped deleting the old."""
    assert _in_order(
        rows,
        [
            ("UPDATE_IN_PROGRESS", _REPLACING, None),
            ("UPDATE_COMPLETE", None, new),
            ("DELETE_SKIPPED", None, old),
        ],
    ), (
        f"the replacement must report creating a new resource, complete as {new!r} and skip "
        f"deleting {old!r} (UpdateReplacePolicy Retain), in that order: {rows!r}"
    )
    deleted = [r for r in rows if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing: {deleted!r}"


def _delete_and_confirm(ctx, cfn, stack_id: str) -> None:
    """DeleteStack by StackId and assert it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        ctx,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    assert final == "DELETE_COMPLETE", (
        f"DeleteStack ended {final!r}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: delete the stack by its StackId and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
