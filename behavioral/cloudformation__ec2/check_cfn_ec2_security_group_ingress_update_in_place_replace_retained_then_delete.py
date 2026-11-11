"""cfn-ec2-security-group-ingress-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-security-group-ingress-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: EC2 reads are eventually consistent: a change can take a moment to reach every Describe.
_PROPAGATE_CAP_S = 30.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_VPC_CIDR = "10.83.0.0/16"
#: A documentation range (RFC 5737): the rule is exact and admits no real peer.
_SOURCE = "192.0.2.0/24"
_FIRST_PORT = 8443
_SECOND_PORT = 9443
_FIRST_NOTE = "sim2real ingress one"
_SECOND_NOTE = "sim2real ingress two"

#: EC2's refusals of a security group and of a security group rule that no longer exist.
_GROUP_NOT_FOUND = ("InvalidGroup.NotFound", "The security group '{}' does not exist")
_RULE_NOT_FOUND = (
    "InvalidSecurityGroupRuleId.NotFound",
    "The security group rule ID '{}' does not exist",
)


def _template(port: int, note: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": _VPC_CIDR, "Tags": _TAGS},
                },
                "Group": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "sim2real ingress target",
                        "VpcId": {"Ref": "Vpc"},
                        "Tags": _TAGS,
                    },
                },
                "Ingress": {
                    "Type": "AWS::EC2::SecurityGroupIngress",
                    # The ports are create-only, so changing them replaces the rule.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "GroupId": {"Fn::GetAtt": ["Group", "GroupId"]},
                        "IpProtocol": "tcp",
                        "FromPort": port,
                        "ToPort": port,
                        "CidrIp": _SOURCE,
                        "Description": note,
                    },
                },
            },
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ingress rule is its group's one ingress rule, with the templated permission.

    A Description change updates the same rule in place; a port change under UpdateReplacePolicy
    Retain leaves both rules in the group; delete: the group and both rules are NotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-securitygroupingress.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stack_name = ctx.unique_name("sim2real-cfnsgi-")
    ref = {"stack": stack_name}
    # The retained rule lives in the stack's own group, so the stack delete removes it too.
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view, the rule's view, and the group it opens
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(_FIRST_PORT, _FIRST_NOTE), Tags=_TAGS
    )["StackId"]
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    group_id, first_id = ids["Group"], ids["Ingress"]
    # The rule does its job: it is the group's only ingress rule and ingress permission.
    rule_ids = _assert_rules(ctx, ec2, group_id, [(_FIRST_PORT, _FIRST_NOTE)])
    first_rule = rule_ids[_FIRST_PORT]
    assert first_id == first_rule, (
        f"the rule's physical id {first_id!r} must be EC2's rule id {first_rule!r}"
    )
    _assert_permissions(ctx, ec2, group_id, [(_FIRST_PORT, _FIRST_NOTE)])

    # ---- 2. in-place: a new Description on the same rule
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(_FIRST_PORT, _SECOND_NOTE), Tags=_TAGS
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Ingress"] == first_id, (
        "an in-place update keeps the rule"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Ingress"), first_id, "Ingress")
    rule_ids = _assert_rules(ctx, ec2, group_id, [(_FIRST_PORT, _SECOND_NOTE)])
    assert rule_ids == {_FIRST_PORT: first_rule}, (
        f"a description update keeps the rule {first_rule!r}, EC2 now lists {rule_ids!r}"
    )
    _assert_permissions(ctx, ec2, group_id, [(_FIRST_PORT, _SECOND_NOTE)])

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new rule, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(_SECOND_PORT, _SECOND_NOTE), Tags=_TAGS
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    second_id = _physical_ids(cfn, ref["stack"])["Ingress"]
    assert second_id != first_id, f"the replacement must be a new rule, still {first_id!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Ingress"), first_id, second_id, "Ingress"
    )
    rule_ids = _assert_rules(
        ctx, ec2, group_id, [(_FIRST_PORT, _SECOND_NOTE), (_SECOND_PORT, _SECOND_NOTE)]
    )
    assert rule_ids[_FIRST_PORT] == first_rule, (
        f"the retained rule must still be {first_rule!r}, EC2 lists {rule_ids!r}"
    )
    assert second_id == rule_ids[_SECOND_PORT], (
        f"the new physical id {second_id!r} must be EC2's rule id {rule_ids[_SECOND_PORT]!r}"
    )
    _assert_permissions(
        ctx, ec2, group_id, [(_FIRST_PORT, _SECOND_NOTE), (_SECOND_PORT, _SECOND_NOTE)]
    )

    # ---- 4. delete: the group and every rule in it, the retained one included, are gone
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: ec2.describe_security_groups(GroupIds=[group_id]),
        _GROUP_NOT_FOUND[0],
        f"security group {group_id}",
    )
    assert got == (_GROUP_NOT_FOUND[0], _GROUP_NOT_FOUND[1].format(group_id)), (
        f"DescribeSecurityGroups after the stack delete answered {got!r}"
    )
    for rule_id in sorted(rule_ids.values()):
        got = _wait_error(
            ctx,
            lambda r=rule_id: ec2.describe_security_group_rules(SecurityGroupRuleIds=[r]),
            _RULE_NOT_FOUND[0],
            f"security group rule {rule_id}",
        )
        assert got == (_RULE_NOT_FOUND[0], _RULE_NOT_FOUND[1].format(rule_id)), (
            f"DescribeSecurityGroupRules {rule_id} after the stack delete answered {got!r}"
        )


def _assert_rules(ctx, ec2, group_id: str, rules: list[tuple[int, str]]) -> dict[int, str]:
    """The group's ingress rules are exactly one tcp rule per (port, note); port -> rule id."""
    keys = ("GroupId", "IsEgress", "IpProtocol", "FromPort", "ToPort", "CidrIpv4", "Description")
    listed: list[dict] = []

    def read() -> list[dict]:
        listed[:] = [
            r
            for r in ec2.describe_security_group_rules(
                Filters=[{"Name": "group-id", "Values": [group_id]}]
            )["SecurityGroupRules"]
            if not r.get("IsEgress")
        ]
        return sorted(
            ({k: r.get(k) for k in keys} for r in listed), key=lambda r: r["FromPort"] or 0
        )

    want = [
        {
            "GroupId": group_id,
            "IsEgress": False,
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "CidrIpv4": _SOURCE,
            "Description": note,
        }
        for port, note in rules
    ]
    _wait_for(ctx, read, want, f"ingress rules of {group_id}")
    return {r["FromPort"]: r["SecurityGroupRuleId"] for r in listed}


def _assert_permissions(ctx, ec2, group_id: str, rules: list[tuple[int, str]]) -> None:
    """The group's IpPermissions are exactly one tcp permission per (port, note), by port."""
    want = [
        {
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [{"CidrIp": _SOURCE, "Description": note}],
            "Ipv6Ranges": [],
            "PrefixListIds": [],
            "UserIdGroupPairs": [],
        }
        for port, note in rules
    ]
    _wait_for(
        ctx,
        lambda: sorted(
            ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]["IpPermissions"],
            key=lambda p: p.get("FromPort", -1),
        ),
        want,
        f"IpPermissions of {group_id}",
    )


# ===== helpers =====


def _wait_for(ctx, read, want, what: str):
    """Poll ``read()`` until it equals *want*: EC2 reads are eventually consistent."""
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        got = read()
        if got == want:
            return got
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended with {what} at {got!r}, expected {want!r}")
            raise AssertionError(f"{what}: {got!r}, expected {want!r}")
        time.sleep(_POLL_S)


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. ctx=None (teardown) waits the full cap;
    in a teardown, ctx.time_left() counts down the runner's cleanup timeout.
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
    quota = [reason for _, _, reason in failed if reason and "LimitExceeded" in reason]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
        + (f"; an account quota refused it, not the template: {quota!r}" if quota else "")
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


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Its waits pass ctx=None, so a body that ran out of time still gets the full stack cap.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
