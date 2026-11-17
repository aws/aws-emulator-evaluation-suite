"""deploy-cfn-ec2-security-group-duplicate-inline-ingress-rule-still-blocks-a-later-authorize."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-ec2-security-group-duplicate-inline-ingress-rule-still-blocks-a-later-authorize"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
#: EC2 reads are eventually consistent: a change can take a moment to reach every Describe.
_PROPAGATE_CAP_S = 30.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_VPC_CIDR = "10.84.0.0/16"
#: A documentation range (RFC 5737): the rule is exact and admits no real peer.
_SOURCE = "192.0.2.0/24"
_PORT = 8443
_CONTROL_PORT = 9443

#: EC2's refusal of an ingress permission that already exists on the group.
_DUPLICATE = (
    "InvalidPermission.Duplicate",
    'the specified rule "peer: {}, TCP, from port: {}, to port: {}, ALLOW" already exists',
)


def _template() -> str:
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
                        "GroupDescription": "sim2real duplicate inline ingress target",
                        "VpcId": {"Ref": "Vpc"},
                        # The same permission appears twice in the one inline list.
                        "SecurityGroupIngress": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": _PORT,
                                "ToPort": _PORT,
                                "CidrIp": _SOURCE,
                            },
                            {
                                "IpProtocol": "tcp",
                                "FromPort": _PORT,
                                "ToPort": _PORT,
                                "CidrIp": _SOURCE,
                            },
                        ],
                        "Tags": _TAGS,
                    },
                },
            },
        }
    )


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A permission CloudFormation's inline ingress list lists twice reaches CREATE_COMPLETE
    stored once, and that stored permission is not a second-class rule: authorizing it again is
    still refused as a duplicate, leaving the rule set unchanged and open to a distinct new rule."""
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stack_name = ctx.unique_name("sim2real-cfnsgdup-")
    ref = {"stack": stack_name}
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- setup: the duplicated inline permission still reaches CREATE_COMPLETE, stored once
    ref["stack"] = cfn.create_stack(StackName=stack_name, TemplateBody=_template(), Tags=_TAGS)[
        "StackId"
    ]
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "CREATE_COMPLETE")
    group_id = _physical_ids(cfn, ref["stack"])["Group"]
    rule_ids = _assert_rules(ctx, ec2, group_id, [_PORT])
    _assert_permissions(ctx, ec2, group_id, [_PORT])

    # ---- break exactly one thing: authorize the identical permission a second time
    got = _error(
        lambda: ec2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": _PORT,
                    "ToPort": _PORT,
                    "IpRanges": [{"CidrIp": _SOURCE}],
                }
            ],
        )
    )
    expected = (_DUPLICATE[0], _DUPLICATE[1].format(_SOURCE, _PORT, _PORT))
    assert got == expected, (
        f"authorizing the CFN-created rule again must be refused {expected!r}, got {got!r}"
    )
    # Effect absent: the refused call left the rule count exactly where it was.
    rule_ids = _assert_rules(ctx, ec2, group_id, [_PORT])

    # ---- positive control: a distinct new rule is still accepted on the same group
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": _CONTROL_PORT,
                "ToPort": _CONTROL_PORT,
                "IpRanges": [{"CidrIp": _SOURCE}],
            }
        ],
    )
    rule_ids = _assert_rules(ctx, ec2, group_id, [_PORT, _CONTROL_PORT])
    assert set(rule_ids) == {_PORT, _CONTROL_PORT}, (
        f"the group's ingress ports read {sorted(rule_ids)!r} after the control rule"
    )


# ===== helpers =====


def _assert_rules(ctx, ec2, group_id: str, ports: list[int]) -> dict[int, str]:
    """The group's ingress rules are exactly one tcp rule per *ports* entry; port -> rule id."""
    keys = ("GroupId", "IsEgress", "IpProtocol", "FromPort", "ToPort", "CidrIpv4")
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
        }
        for port in sorted(ports)
    ]
    _wait_for(ctx, read, want, f"ingress rules of {group_id}")
    return {r["FromPort"]: r["SecurityGroupRuleId"] for r in listed}


def _assert_permissions(ctx, ec2, group_id: str, ports: list[int]) -> None:
    """The group's IpPermissions hold exactly one tcp permission per *ports* entry, by port."""
    want = [
        {
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [{"CidrIp": _SOURCE}],
            "Ipv6Ranges": [],
            "PrefixListIds": [],
            "UserIdGroupPairs": [],
        }
        for port in sorted(ports)
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


def _error(fn) -> tuple:
    """(code, message) of the ClientError fn() raises; raises when the call SUCCEEDS instead."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("the call succeeded; real AWS rejects it, so there is no error code")


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


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


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
