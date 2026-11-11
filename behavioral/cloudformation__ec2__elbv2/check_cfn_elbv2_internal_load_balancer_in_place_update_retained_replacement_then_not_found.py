"""cfn-elbv2-internal-load-balancer-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-elbv2-internal-load-balancer-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "elbv2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 900.0
#: One deadline for the whole teardown, within the suites' 1800 s cleanup budget.
_TEARDOWN_CAP_S = 1500.0
_GONE_CAP_S = 300.0
#: An attribute change or a node's ENI can take a moment to show in the describe calls.
_CONVERGE_CAP_S = 120.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: CloudFormation's reason on the event that starts a replacement.
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)

#: ELB's refusal of a load balancer that no longer exists.
_NOT_FOUND = ("LoadBalancerNotFound", "One or more load balancers not found")

#: The attributes of the two revisions: idle timeout, drop invalid header fields.
_V1 = ("90", "true")
_V2 = ("120", "false")


def _template(name: str, subnets: list[str], group: str, attributes: tuple) -> str:
    idle, drop = attributes
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "LoadBalancer": {
                    "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                    # Name is create-only, so changing it replaces the load balancer.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Name": name,
                        "Type": "application",
                        "Scheme": "internal",
                        "IpAddressType": "ipv4",
                        "Subnets": subnets,
                        "SecurityGroups": [group],
                        "LoadBalancerAttributes": [
                            {"Key": "idle_timeout.timeout_seconds", "Value": idle},
                            {
                                "Key": "routing.http.drop_invalid_header_fields.enabled",
                                "Value": drop,
                            },
                            {"Key": "deletion_protection.enabled", "Value": "false"},
                        ],
                        "Tags": _TAGS,
                    },
                },
            },
            "Outputs": {
                "LoadBalancerArn": {"Value": {"Fn::GetAtt": ["LoadBalancer", "LoadBalancerArn"]}},
                "LoadBalancerName": {"Value": {"Fn::GetAtt": ["LoadBalancer", "LoadBalancerName"]}},
                "LoadBalancerFullName": {
                    "Value": {"Fn::GetAtt": ["LoadBalancer", "LoadBalancerFullName"]}
                },
                "DNSName": {"Value": {"Fn::GetAtt": ["LoadBalancer", "DNSName"]}},
                "CanonicalHostedZoneID": {
                    "Value": {"Fn::GetAtt": ["LoadBalancer", "CanonicalHostedZoneID"]}
                },
                "SecurityGroups": {
                    "Value": {"Fn::Join": [",", {"Fn::GetAtt": ["LoadBalancer", "SecurityGroups"]}]}
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
    """A CloudFormation internal ALB reads back as templated and holds in-use node ENIs.

    An attribute change keeps the load balancer; a Name change under UpdateReplacePolicy Retain
    keeps the old one active; after the stack delete: LoadBalancerNotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticloadbalancingv2-loadbalancer.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    network = ctx.network()
    subnets = list(network.subnet_ids[:2])
    group = network.security_group_id
    first = ctx.unique_name("sim2real-lb-a-")
    second = ctx.unique_name("sim2real-lb-b-")
    stack_name = ctx.unique_name("sim2real-cfnlb-stack-")
    ref = {"stack": stack_name}
    retained = {}

    # Teardown waits on one deadline of its own: the body's deadline does not bound cleanup.
    # LIFO: the stack goes first, then the retained load balancer, then both release their ENIs.
    limit: dict = {}
    ctx.on_cleanup(lambda: _await_eni_release(ec2, network.vpc_id, [first, second], limit))
    ctx.on_cleanup(lambda: _drop_load_balancer(elbv2, retained.get("arn"), limit))
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref, limit))

    # ---- 1. create: CloudFormation's view, ELB's view, its node ENIs
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(first, subnets, group, _V1), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    first_arn = _physical_ids(cfn, ref["stack"])["LoadBalancer"]
    retained["arn"] = first_arn
    lb = _assert_load_balancer(ctx, elbv2, first_arn, first, network.vpc_id, subnets, group, _V1)
    _assert_outputs(stack, lb, group)
    _assert_enis(ctx, ec2, network.vpc_id, lb, subnets, group)

    # ---- 2. in-place: new attributes, the same load balancer
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(first, subnets, group, _V2), Tags=_TAGS
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["LoadBalancer"] == first_arn, (
        "an in-place update keeps the load balancer"
    )
    _assert_in_place(
        _rows(_events(cfn, ref["stack"]), seen, "LoadBalancer"), first_arn, "LoadBalancer"
    )
    _assert_load_balancer(ctx, elbv2, first_arn, first, network.vpc_id, subnets, group, _V2)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new load balancer, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(second, subnets, group, _V2), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_arn = _physical_ids(cfn, ref["stack"])["LoadBalancer"]
    assert second_arn != first_arn, (
        f"the replacement must be a new load balancer, still {first_arn!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "LoadBalancer"),
        first_arn,
        second_arn,
        "LoadBalancer",
    )
    lb2 = _assert_load_balancer(ctx, elbv2, second_arn, second, network.vpc_id, subnets, group, _V2)
    _assert_outputs(stack, lb2, group)
    _assert_load_balancer(ctx, elbv2, first_arn, first, network.vpc_id, subnets, group, _V2)

    # ---- 4. delete: ELB no longer finds the stack's load balancer; the retained one stays
    _delete_stack(ctx, cfn, ref["stack"], _STACK_CAP_S)
    got = _wait_error(
        ctx,
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[second_arn]),
        _NOT_FOUND[0],
        f"load balancer {second}",
    )
    assert got == _NOT_FOUND, f"DescribeLoadBalancers after the stack delete answered {got!r}"
    _assert_load_balancer(ctx, elbv2, first_arn, first, network.vpc_id, subnets, group, _V2)


def _describe(elbv2, arn: str) -> tuple[dict, dict]:
    """(DescribeLoadBalancers row, template view of it with its attributes and tags)."""
    (lb,) = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"]
    attributes = {
        a["Key"]: a["Value"]
        for a in elbv2.describe_load_balancer_attributes(LoadBalancerArn=arn)["Attributes"]
    }
    (described,) = elbv2.describe_tags(ResourceArns=[arn])["TagDescriptions"]
    view = {
        "LoadBalancerArn": lb["LoadBalancerArn"],
        "LoadBalancerName": lb["LoadBalancerName"],
        "Type": lb.get("Type"),
        "Scheme": lb.get("Scheme"),
        "IpAddressType": lb.get("IpAddressType"),
        "VpcId": lb.get("VpcId"),
        "State": lb.get("State", {}).get("Code"),
        "Subnets": sorted(z["SubnetId"] for z in lb.get("AvailabilityZones", [])),
        "SecurityGroups": lb.get("SecurityGroups"),
        "attributes": {
            k: attributes.get(k)
            for k in (
                "idle_timeout.timeout_seconds",
                "routing.http.drop_invalid_header_fields.enabled",
                "deletion_protection.enabled",
            )
        },
        "tags": {
            t["Key"]: t["Value"] for t in described["Tags"] if not t["Key"].startswith("aws:")
        },
    }
    return lb, view


def _assert_load_balancer(ctx, elbv2, arn, name, vpc_id, subnets, group, attributes) -> dict:
    """ELB reports the template's active internal load balancer exactly; return its row."""
    idle, drop = attributes
    want = {
        "LoadBalancerArn": arn,
        "LoadBalancerName": name,
        "Type": "application",
        "Scheme": "internal",
        "IpAddressType": "ipv4",
        "VpcId": vpc_id,
        "State": "active",
        "Subnets": sorted(subnets),
        "SecurityGroups": [group],
        "attributes": {
            "idle_timeout.timeout_seconds": idle,
            "routing.http.drop_invalid_header_fields.enabled": drop,
            "deletion_protection.enabled": "false",
        },
        "tags": {"sim2real": CHECK},
    }
    lb, got = _poll(
        ctx, lambda: _describe(elbv2, arn), lambda r: r[1] == want, f"{name} as templated"
    )
    assert got == want, f"load balancer {name}: {got!r}, expected {want!r}"
    return lb


def _assert_outputs(stack: dict, lb: dict, group: str) -> None:
    """GetAtt names the stack's load balancer as ELB describes it."""
    want = {
        "LoadBalancerArn": lb["LoadBalancerArn"],
        "LoadBalancerName": lb["LoadBalancerName"],
        "LoadBalancerFullName": lb["LoadBalancerArn"].split(":loadbalancer/", 1)[-1],
        "DNSName": lb["DNSName"],
        "CanonicalHostedZoneID": lb["CanonicalHostedZoneId"],
        "SecurityGroups": group,
    }
    assert _outputs(stack) == want, f"GetAtt outputs {_outputs(stack)!r}, expected {want!r}"


def _assert_enis(ctx, ec2, vpc_id: str, lb: dict, subnets: list[str], group: str) -> None:
    """The load balancer holds in-use, ELB-managed ENIs with its group, each in one of its subnets.

    AWS does not attach a node ENI in every enabled subnet at once, so which subnets hold one
    is not asserted; every ENI's own fields are.
    """
    full_name = lb["LoadBalancerArn"].split(":loadbalancer/", 1)[-1]
    fields = (f"ELB {full_name}", "in-use", True, (group,))

    def view():
        return sorted(
            (
                eni["SubnetId"],
                (
                    eni.get("Description"),
                    eni.get("Status"),
                    eni.get("RequesterManaged"),
                    tuple(g["GroupId"] for g in eni.get("Groups", [])),
                ),
            )
            for eni in _lb_enis(ec2, vpc_id, lb["LoadBalancerName"])
        )

    def done(v):
        return bool(v) and all(subnet in subnets and got == fields for subnet, got in v)

    got = _poll(ctx, view, done, f"ENIs of {lb['LoadBalancerName']}")
    assert done(got), (
        f"ENIs of {lb['LoadBalancerName']}: {got!r}, each expected in {subnets!r} as {fields!r}"
    )


def _lb_enis(ec2, vpc_id: str, name: str) -> list[dict]:
    """The ENIs of the application load balancer *name*: description ``ELB app/<name>/<id>``."""
    return [
        eni
        for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "description", "Values": [f"ELB app/{name}/*"]},
            ]
        )
        for eni in page["NetworkInterfaces"]
    ]


def _await_eni_release(ec2, vpc_id: str, names: list[str], limit: dict) -> None:
    """Wait until no load balancer in *names* holds an ENI; ENIs outlive the delete by minutes.

    The shared network's subnets cannot be deleted while they hold them.
    """
    timeout = _remaining(limit)
    deadline = time.monotonic() + timeout
    while True:
        held = {name: len(_lb_enis(ec2, vpc_id, name)) for name in names}
        if not any(held.values()):
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"load balancer ENIs not released after {timeout:.0f}s: {held!r}")
        time.sleep(10.0)


def _drop_load_balancer(elbv2, arn: str | None, limit: dict) -> None:
    """Delete a load balancer the stack no longer owns and poll until ELB no longer finds it.

    DeleteLoadBalancer succeeds on a load balancer that no longer exists.
    """
    if arn is None:
        return
    elbv2.delete_load_balancer(LoadBalancerArn=arn)
    got = _wait_error(
        None,
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[arn]),
        _NOT_FOUND[0],
        f"load balancer {arn}",
        _remaining(limit),
    )
    assert got == _NOT_FOUND, f"DescribeLoadBalancers after deleting {arn} answered {got!r}"


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


def _settle(ctx, cfn, stack_id: str, cap_s: float = _STACK_CAP_S) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, cap_s)
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


def _wait_error(ctx, fn, code: str, what: str, cap_s: float = _GONE_CAP_S):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, cap_s)
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


def _delete_stack(ctx, cfn, stack_id: str, cap_s: float) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id, cap_s), "DELETE_COMPLETE")


def _remaining(limit: dict) -> float:
    """Seconds left of the one teardown deadline, which starts at the first teardown wait."""
    deadline = limit.setdefault("at", time.monotonic() + _TEARDOWN_CAP_S)
    return max(1.0, deadline - time.monotonic())


def _teardown_stack(cfn, ref: dict, limit: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Every wait shares the one deadline in *limit*, so the whole teardown fits its cap.
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
        stack = _settle(None, cfn, stack["StackId"], _remaining(limit))
    _delete_stack(None, cfn, stack["StackId"], _remaining(limit))


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
