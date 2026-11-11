"""cfn-elbv2-target-group-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import ipaddress
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-elbv2-target-group-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "elbv2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: A registration or attribute change can take a moment to show in the describe calls.
_CONVERGE_CAP_S = 60.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: CloudFormation's reason on the event that starts a replacement.
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)

#: ELB's refusal of a target group that no longer exists.
_NOT_FOUND = ("TargetGroupNotFound", "One or more target groups not found")

#: A registered target of a group no listener forwards to: (state, reason).
_NOT_IN_USE = ("unused", "Target.NotInUse")

#: The mutable settings of the two revisions: health check path, interval, matcher, delay.
_V1 = ("/healthz", 20, "200,204", "120")
_V2 = ("/ready", 15, "200-299", "30")


def _template(name: str, vpc_id: str, settings: tuple) -> str:
    path, interval, matcher, delay = settings
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "TargetGroup": {
                    "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                    # Name is create-only, so changing it replaces the target group.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Name": name,
                        "VpcId": vpc_id,
                        "Protocol": "HTTP",
                        "ProtocolVersion": "HTTP1",
                        "Port": 8080,
                        "TargetType": "ip",
                        "HealthCheckProtocol": "HTTP",
                        "HealthCheckPath": path,
                        "HealthCheckIntervalSeconds": interval,
                        "Matcher": {"HttpCode": matcher},
                        "TargetGroupAttributes": [
                            {"Key": "deregistration_delay.timeout_seconds", "Value": delay}
                        ],
                        "Tags": _TAGS,
                    },
                },
            },
            "Outputs": {
                "TargetGroupArn": {"Value": {"Fn::GetAtt": ["TargetGroup", "TargetGroupArn"]}},
                "TargetGroupName": {"Value": {"Fn::GetAtt": ["TargetGroup", "TargetGroupName"]}},
                "TargetGroupFullName": {
                    "Value": {"Fn::GetAtt": ["TargetGroup", "TargetGroupFullName"]}
                },
            },
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
    """A CloudFormation target group reads back as templated and holds an IP target as unused.

    A health check and attribute change keeps the group and its target; a Name change under
    UpdateReplacePolicy Retain keeps the old group with its target; delete: TargetGroupNotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticloadbalancingv2-targetgroup.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    network = ctx.network()
    first = ctx.unique_name("sim2real-tg-a-")
    second = ctx.unique_name("sim2real-tg-b-")
    stack_name = ctx.unique_name("sim2real-cfntg-stack-")
    ref = {"stack": stack_name}
    retained = {}

    # The replaced group is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_target_group(elbv2, retained.get("arn")))
    ctx.on_cleanup(lambda: _teardown_stack(None, cfn, ref))

    # An address inside one of the shared VPC's subnets, past the addresses AWS reserves.
    subnet = ec2.describe_subnets(SubnetIds=[network.subnet_ids[0]])["Subnets"][0]
    target_ip = str(ipaddress.ip_network(subnet["CidrBlock"])[10])

    # ---- 1. create: CloudFormation's view, ELB's view, a registered target
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(first, network.vpc_id, _V1), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    first_arn = _physical_ids(cfn, ref["stack"])["TargetGroup"]
    retained["arn"] = first_arn
    _assert_outputs(stack, first_arn, first)
    _assert_target_group(ctx, elbv2, first_arn, first, network.vpc_id, _V1)
    elbv2.register_targets(TargetGroupArn=first_arn, Targets=[{"Id": target_ip}])
    _assert_targets(ctx, elbv2, first_arn, {target_ip})

    # ---- 2. in-place: a new health check, matcher and delay, the same group and target
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(first, network.vpc_id, _V2), Tags=_TAGS
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["TargetGroup"] == first_arn, (
        "an in-place update keeps the target group"
    )
    _assert_in_place(
        _rows(_events(cfn, ref["stack"]), seen, "TargetGroup"), first_arn, "TargetGroup"
    )
    _assert_target_group(ctx, elbv2, first_arn, first, network.vpc_id, _V2)
    _assert_targets(ctx, elbv2, first_arn, {target_ip})

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new empty group, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(second, network.vpc_id, _V2), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_arn = _physical_ids(cfn, ref["stack"])["TargetGroup"]
    assert second_arn != first_arn, f"the replacement must be a new group, still {first_arn!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "TargetGroup"), first_arn, second_arn, "TargetGroup"
    )
    _assert_outputs(stack, second_arn, second)
    _assert_target_group(ctx, elbv2, second_arn, second, network.vpc_id, _V2)
    _assert_targets(ctx, elbv2, second_arn, set())
    _assert_target_group(ctx, elbv2, first_arn, first, network.vpc_id, _V2)
    _assert_targets(ctx, elbv2, first_arn, {target_ip})

    # ---- 4. delete: ELB no longer finds the stack's group; the retained one stays
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: elbv2.describe_target_groups(TargetGroupArns=[second_arn]),
        _NOT_FOUND[0],
        f"target group {second}",
    )
    assert got == _NOT_FOUND, f"DescribeTargetGroups after the stack delete answered {got!r}"
    _assert_target_group(ctx, elbv2, first_arn, first, network.vpc_id, _V2)


def _assert_outputs(stack: dict, arn: str, name: str) -> None:
    """GetAtt names the stack's group: its ARN, its name and the ARN's resource part."""
    want = {
        "TargetGroupArn": arn,
        "TargetGroupName": name,
        "TargetGroupFullName": arn.split(":", 5)[-1],
    }
    assert _outputs(stack) == want, f"GetAtt outputs {_outputs(stack)!r}, expected {want!r}"


def _describe(elbv2, arn: str) -> dict:
    """DescribeTargetGroups, its attributes and tags, reduced to the template's view."""
    (tg,) = elbv2.describe_target_groups(TargetGroupArns=[arn])["TargetGroups"]
    attributes = {
        a["Key"]: a["Value"]
        for a in elbv2.describe_target_group_attributes(TargetGroupArn=arn)["Attributes"]
    }
    (described,) = elbv2.describe_tags(ResourceArns=[arn])["TagDescriptions"]
    return {
        "TargetGroupArn": tg["TargetGroupArn"],
        "TargetGroupName": tg["TargetGroupName"],
        "VpcId": tg.get("VpcId"),
        "Protocol": tg.get("Protocol"),
        "ProtocolVersion": tg.get("ProtocolVersion"),
        "Port": tg.get("Port"),
        "TargetType": tg.get("TargetType"),
        "HealthCheckProtocol": tg.get("HealthCheckProtocol"),
        "HealthCheckPath": tg.get("HealthCheckPath"),
        "HealthCheckIntervalSeconds": tg.get("HealthCheckIntervalSeconds"),
        "Matcher": tg.get("Matcher"),
        "LoadBalancerArns": tg.get("LoadBalancerArns"),
        "deregistration_delay": attributes.get("deregistration_delay.timeout_seconds"),
        "tags": {
            t["Key"]: t["Value"] for t in described["Tags"] if not t["Key"].startswith("aws:")
        },
    }


def _assert_target_group(ctx, elbv2, arn: str, name: str, vpc_id: str, settings: tuple) -> None:
    """DescribeTargetGroups and its attributes report the template's group exactly."""
    path, interval, matcher, delay = settings
    want = {
        "TargetGroupArn": arn,
        "TargetGroupName": name,
        "VpcId": vpc_id,
        "Protocol": "HTTP",
        "ProtocolVersion": "HTTP1",
        "Port": 8080,
        "TargetType": "ip",
        "HealthCheckProtocol": "HTTP",
        "HealthCheckPath": path,
        "HealthCheckIntervalSeconds": interval,
        "Matcher": {"HttpCode": matcher},
        "LoadBalancerArns": [],
        "deregistration_delay": delay,
        "tags": {"sim2real": CHECK},
    }
    got = _poll(ctx, lambda: _describe(elbv2, arn), lambda d: d == want, f"{name} as templated")
    assert got == want, f"target group {name}: {got!r}, expected {want!r}"


def _health(elbv2, arn: str) -> dict:
    """{(target id, port): (state, reason)} for every target the group holds."""
    return {
        (d["Target"]["Id"], d["Target"].get("Port")): (
            d["TargetHealth"]["State"],
            d["TargetHealth"].get("Reason"),
        )
        for d in elbv2.describe_target_health(TargetGroupArn=arn)["TargetHealthDescriptions"]
    }


def _assert_targets(ctx, elbv2, arn: str, ips: set[str]) -> None:
    """The group holds exactly *ips* on its port 8080, each unused: no listener forwards to it."""
    want = {(ip, 8080): _NOT_IN_USE for ip in ips}
    got = _poll(ctx, lambda: _health(elbv2, arn), lambda h: h == want, f"targets of {arn}")
    assert got == want, f"DescribeTargetHealth {arn}: {got!r}, expected {want!r}"


def _delete_target_group(elbv2, arn: str | None) -> None:
    """Delete the group; a refusal passes only on DescribeTargetGroups' exact not-found pair."""
    if arn is None:
        return
    try:
        elbv2.delete_target_group(TargetGroupArn=arn)
    except ClientError as exc:
        try:
            elbv2.describe_target_groups(TargetGroupArns=[arn])
        except ClientError as gone:
            err = gone.response["Error"]
            if (err["Code"], err.get("Message")) == _NOT_FOUND:
                return
            raise exc from gone
        raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. A teardown passes no ctx: it waits the full cap.
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
    """The resource's update events are an in-place update ending on *physical_id*.

    Repeated statuses collapse: a type may add an UPDATE_IN_PROGRESS row while it stabilizes.
    """
    statuses = [s for i, (s, _, _) in enumerate(rows) if i == 0 or rows[i - 1][0] != s]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert not [r for r in rows if r[1] == _REPLACING or r[0].startswith(("CREATE_", "DELETE_"))], (
        f"{logical_id} must not be created, deleted or replaced, its events were {rows!r}"
    )
    assert rows[-1][0] == "UPDATE_COMPLETE" and rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        _REPLACING,
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


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done."""
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"])
    _delete_stack(ctx, cfn, stack["StackId"])


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
