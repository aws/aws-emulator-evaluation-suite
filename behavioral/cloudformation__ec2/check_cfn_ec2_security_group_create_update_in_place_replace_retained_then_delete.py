"""cfn-ec2-security-group-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-security-group-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: EC2 reads are eventually consistent: a change can take a moment to reach every Describe.
_PROPAGATE_CAP_S = 30.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_VPC_CIDR = "10.82.0.0/16"
#: A documentation range (RFC 5737): the rule is exact and admits no real peer.
_SOURCE = "198.51.100.0/24"
_RULE_NOTE = "tcp from the documentation range"
_FIRST_PORT = 8443
_SECOND_PORT = 9443
_FIRST_DESCRIPTION = "sim2real security group one"
_SECOND_DESCRIPTION = "sim2real security group two"

#: EC2's refusal of a security group that no longer exists.
_NOT_FOUND = ("InvalidGroup.NotFound", "The security group '{}' does not exist")

#: With no SecurityGroupEgress declared, a VPC security group keeps AWS's allow-all egress rule;
#: the check only reads it back.
_EGRESS_DESTINATION = "0.0.0.0/0"


def _template(description: str, port: int) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": _VPC_CIDR, "Tags": _TAGS},
                },
                "SecurityGroup": {
                    "Type": "AWS::EC2::SecurityGroup",
                    # GroupDescription is create-only, so changing it replaces the group.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "GroupDescription": description,
                        "VpcId": {"Ref": "Vpc"},
                        "SecurityGroupIngress": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": port,
                                "ToPort": port,
                                "CidrIp": _SOURCE,
                                "Description": _RULE_NOTE,
                            }
                        ],
                        "Tags": _TAGS,
                    },
                },
            },
            "Outputs": {
                "GroupId": {"Value": {"Fn::GetAtt": ["SecurityGroup", "GroupId"]}},
                "VpcId": {"Value": {"Fn::GetAtt": ["SecurityGroup", "VpcId"]}},
            },
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation security group holds exactly its ingress rule and AWS's default egress rule.

    An ingress port change rewrites the rule in place; a GroupDescription change under
    UpdateReplacePolicy Retain keeps both groups; delete: InvalidGroup.NotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-securitygroup.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stack_name = ctx.unique_name("sim2real-cfnsg-")
    ref = {"stack": stack_name}
    retained: dict[str, str] = {}

    # The replaced group is retained inside the stack's VPC, so it is deleted before the stack.
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))
    ctx.on_cleanup(lambda: _delete_group(ec2, retained.get("id")))

    # ---- 1. create: CloudFormation's view, EC2's view, and the rules the group enforces
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(_FIRST_DESCRIPTION, _FIRST_PORT),
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    vpc_id, first_id = ids["Vpc"], ids["SecurityGroup"]
    assert _outputs(stack) == {"GroupId": first_id, "VpcId": vpc_id}, (
        f"GetAtt outputs {_outputs(stack)!r}"
    )
    stamped = _stack_tags(stack_name, ref["stack"], "SecurityGroup")
    _assert_group(ctx, ec2, first_id, vpc_id, _FIRST_DESCRIPTION, _FIRST_PORT, stamped)
    first_name = ec2.describe_security_groups(GroupIds=[first_id])["SecurityGroups"][0]["GroupName"]
    # With no GroupName, CloudFormation names the group <stack name>-<logical id>-<suffix>.
    assert first_name.startswith(f"{stack_name}-SecurityGroup-"), (
        f"generated GroupName {first_name!r} must start with the stack and logical id"
    )

    # ---- 2. in-place: a new ingress port, the same group
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(_FIRST_DESCRIPTION, _SECOND_PORT),
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["SecurityGroup"] == first_id, (
        "an in-place update keeps the security group"
    )
    _assert_in_place(
        _rows(_events(cfn, ref["stack"]), seen, "SecurityGroup"), first_id, "SecurityGroup"
    )
    _assert_group(ctx, ec2, first_id, vpc_id, _FIRST_DESCRIPTION, _SECOND_PORT, stamped)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new group, the old one kept
    # Registered before the update: CloudFormation may retain the old one before the poll ends.
    retained["id"] = first_id
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(_SECOND_DESCRIPTION, _SECOND_PORT),
        Tags=_TAGS,
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_id = _physical_ids(cfn, ref["stack"])["SecurityGroup"]
    assert second_id != first_id, f"the replacement must be a new group, still {first_id!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "SecurityGroup"),
        first_id,
        second_id,
        "SecurityGroup",
    )
    assert _outputs(stack) == {"GroupId": second_id, "VpcId": vpc_id}, (
        f"GetAtt outputs after replacement {_outputs(stack)!r}"
    )
    _assert_group(ctx, ec2, second_id, vpc_id, _SECOND_DESCRIPTION, _SECOND_PORT, stamped)
    _assert_group(ctx, ec2, first_id, vpc_id, _FIRST_DESCRIPTION, _SECOND_PORT, stamped)

    # ---- 4. delete: the retained group by hand, then the stack; EC2 knows neither
    ec2.delete_security_group(GroupId=first_id)
    _assert_gone(ctx, ec2, first_id)
    _delete_stack(ctx, cfn, ref["stack"])
    _assert_gone(ctx, ec2, second_id)


def _assert_group(ctx, ec2, group_id, vpc_id, description, port, stamped) -> None:
    """The group's own view and its rule list both hold exactly the templated rule.

    DescribeSecurityGroupRules is the per-rule view of what the group admits and emits.
    """

    def read() -> dict:
        g = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
        rules = ec2.describe_security_group_rules(
            Filters=[{"Name": "group-id", "Values": [group_id]}]
        )["SecurityGroupRules"]
        return {
            "VpcId": g.get("VpcId"),
            "Description": g.get("Description"),
            "IpPermissions": g.get("IpPermissions"),
            "IpPermissionsEgress": g.get("IpPermissionsEgress"),
            "Tags": _tag_map(g.get("Tags")),
            "Rules": sorted(
                [
                    (
                        r["IsEgress"],
                        r["IpProtocol"],
                        r.get("FromPort"),
                        r.get("ToPort"),
                        r.get("CidrIpv4"),
                        r.get("Description"),
                    )
                    for r in rules
                ],
                # repr orders rules whose Description is None beside one that is a string.
                key=repr,
            ),
        }

    want = {
        "VpcId": vpc_id,
        "Description": description,
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
                "IpRanges": [{"CidrIp": _SOURCE, "Description": _RULE_NOTE}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
            }
        ],
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": _EGRESS_DESTINATION}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
            }
        ],
        "Tags": {"sim2real": CHECK, **stamped},
        "Rules": [
            (False, "tcp", port, port, _SOURCE, _RULE_NOTE),
            (True, "-1", -1, -1, _EGRESS_DESTINATION, None),
        ],
    }
    _wait_for(ctx, read, want, f"security group {group_id}")


def _assert_gone(ctx, ec2, group_id: str) -> None:
    got = _wait_error(
        ctx,
        lambda: ec2.describe_security_groups(GroupIds=[group_id]),
        _NOT_FOUND[0],
        f"security group {group_id}",
    )
    assert got == (_NOT_FOUND[0], _NOT_FOUND[1].format(group_id)), (
        f"DescribeSecurityGroups {group_id} after its delete answered {got!r}"
    )


def _delete_group(ec2, group_id: str | None) -> None:
    if group_id is None:
        return
    try:
        ec2.delete_security_group(GroupId=group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND[0]:
            raise


# ===== helpers =====


def _tag_map(tags: list[dict] | None) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in tags or []}


def _stack_tags(stack_name: str, stack_id: str, logical_id: str) -> dict[str, str]:
    """The tags CloudFormation itself stamps on an EC2 resource it creates."""
    return {
        "aws:cloudformation:stack-name": stack_name,
        "aws:cloudformation:stack-id": stack_id,
        "aws:cloudformation:logical-id": logical_id,
    }


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


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o.get("OutputValue") for o in stack.get("Outputs", [])}


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
