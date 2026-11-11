"""cfn-elbv2-listener-fixed-response-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-elbv2-listener-fixed-response-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "elbv2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 900.0
#: One deadline for the whole teardown, within the suites' 1800 s cleanup budget.
_TEARDOWN_CAP_S = 1500.0
_GONE_CAP_S = 300.0
_CONVERGE_CAP_S = 60.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: CloudFormation's reason on the event that starts a replacement.
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)

#: ELB's refusal of a listener that no longer exists.
_NOT_FOUND = ("ListenerNotFound", "One or more listeners not found")
#: ELB's refusal of a second listener on a port that one already holds (load balancer ARN).
_DUPLICATE = (
    "DuplicateListener",
    "A listener already exists on this port for this load balancer '{}'",
)

#: The listener revisions: (port, fixed response status, body).
_V1 = (8080, "503", "listener revision one")
_V2 = (8081, "200", "listener revision two")


def _fixed(status: str, body: str) -> list[dict]:
    return [
        {
            "Type": "fixed-response",
            "Order": 1,
            "FixedResponseConfig": {
                "StatusCode": status,
                "ContentType": "text/plain",
                "MessageBody": body,
            },
        }
    ]


def _template(names: tuple, subnets: list[str], group: str, owner: str, revision: tuple) -> str:
    port, status, body = revision

    def load_balancer(name: str) -> dict:
        return {
            "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
            "Properties": {
                "Name": name,
                "Type": "application",
                "Scheme": "internal",
                "Subnets": subnets,
                "SecurityGroups": [group],
                "Tags": _TAGS,
            },
        }

    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "LoadBalancerA": load_balancer(names[0]),
                "LoadBalancerB": load_balancer(names[1]),
                "Listener": {
                    "Type": "AWS::ElasticLoadBalancingV2::Listener",
                    # LoadBalancerArn is create-only, so moving it replaces the listener.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "LoadBalancerArn": {"Ref": owner},
                        "Protocol": "HTTP",
                        "Port": port,
                        "DefaultActions": _fixed(status, body),
                    },
                },
            },
            "Outputs": {
                "ListenerArn": {"Value": {"Fn::GetAtt": ["Listener", "ListenerArn"]}},
                "LoadBalancerA": {"Value": {"Ref": "LoadBalancerA"}},
                "LoadBalancerB": {"Value": {"Ref": "LoadBalancerB"}},
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
    """A CloudFormation listener's fixed response is its default rule and it holds its port.

    A port and response change keeps the listener; a move to another load balancer under
    UpdateReplacePolicy Retain keeps the old listener; after the stack delete: ListenerNotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticloadbalancingv2-listener.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    network = ctx.network()
    subnets = list(network.subnet_ids[:2])
    group = network.security_group_id
    names = (ctx.unique_name("sim2real-lsn-a-"), ctx.unique_name("sim2real-lsn-b-"))
    stack_name = ctx.unique_name("sim2real-cfnlsn-stack-")
    ref = {"stack": stack_name}

    # Teardown waits on one deadline of its own: the body's deadline does not bound cleanup.
    # LIFO: the stack (and with its load balancers every listener) goes, then the ENIs release.
    limit: dict = {}
    ctx.on_cleanup(lambda: _await_eni_release(ec2, network.vpc_id, list(names), limit))
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref, limit))

    def template(owner: str, revision: tuple) -> str:
        return _template(names, subnets, group, owner, revision)

    # ---- 1. create: CloudFormation's view, ELB's view, the default rule and the held port
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=template("LoadBalancerA", _V1), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    lb_a, lb_b, first = ids["LoadBalancerA"], ids["LoadBalancerB"], ids["Listener"]
    assert _outputs(stack) == {
        "ListenerArn": first,
        "LoadBalancerA": lb_a,
        "LoadBalancerB": lb_b,
    }, f"GetAtt/Ref outputs {_outputs(stack)!r}"
    _assert_listener(ctx, elbv2, first, lb_a, _V1)
    _assert_holds_port(elbv2, lb_a, _V1[0])

    # ---- 2. in-place: a new port and fixed response, the same listener
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=template("LoadBalancerA", _V2), Tags=_TAGS
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Listener"] == first, "an in-place update keeps it"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Listener"), first, "Listener")
    _assert_listener(ctx, elbv2, first, lb_a, _V2)
    _assert_holds_port(elbv2, lb_a, _V2[0])

    # ---- 3. replacement under UpdateReplacePolicy Retain: a listener on B, the one on A kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=template("LoadBalancerB", _V2), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second = _physical_ids(cfn, ref["stack"])["Listener"]
    assert second != first, f"the replacement must be a new listener, still {first!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Listener"), first, second, "Listener"
    )
    assert _outputs(stack)["ListenerArn"] == second, f"GetAtt after replacement {_outputs(stack)!r}"
    _assert_listener(ctx, elbv2, second, lb_b, _V2)
    _assert_holds_port(elbv2, lb_b, _V2[0])
    _assert_listener(ctx, elbv2, first, lb_a, _V2)

    # ---- 4. delete: both listeners go with the stack's load balancers
    _delete_stack(ctx, cfn, ref["stack"], _STACK_CAP_S)
    for arn in (second, first):
        got = _wait_error(
            ctx,
            lambda arn=arn: elbv2.describe_listeners(ListenerArns=[arn]),
            _NOT_FOUND[0],
            f"listener {arn}",
        )
        assert got == _NOT_FOUND, f"DescribeListeners {arn} after the stack delete: {got!r}"


def _describe(elbv2, arn: str) -> dict:
    """DescribeListeners and the listener's DescribeRules, reduced to the template's view."""
    (listener,) = elbv2.describe_listeners(ListenerArns=[arn])["Listeners"]
    rules = elbv2.describe_rules(ListenerArn=arn)["Rules"]
    return {
        "ListenerArn": listener["ListenerArn"],
        "LoadBalancerArn": listener.get("LoadBalancerArn"),
        "Protocol": listener.get("Protocol"),
        "Port": listener.get("Port"),
        "DefaultActions": listener.get("DefaultActions"),
        "rules": [
            (r.get("Priority"), r.get("IsDefault"), r.get("Conditions"), r.get("Actions"))
            for r in rules
        ],
    }


def _assert_listener(ctx, elbv2, arn: str, lb_arn: str, revision: tuple) -> None:
    """ELB reports the template's listener, and its only rule is the default with that action."""
    port, status, body = revision
    actions = _fixed(status, body)
    want = {
        "ListenerArn": arn,
        "LoadBalancerArn": lb_arn,
        "Protocol": "HTTP",
        "Port": port,
        "DefaultActions": actions,
        "rules": [("default", True, [], actions)],
    }
    got = _poll(ctx, lambda: _describe(elbv2, arn), lambda d: d == want, f"listener {arn}")
    assert got == want, f"listener {arn}: {got!r}, expected {want!r}"


def _assert_holds_port(elbv2, lb_arn: str, port: int) -> None:
    """A second listener with another action on the same port of the load balancer is refused."""
    got = _error(
        lambda: elbv2.create_listener(
            LoadBalancerArn=lb_arn,
            Protocol="HTTP",
            Port=port,
            DefaultActions=_fixed("404", "a second listener on the port"),
        )
    )
    want = (_DUPLICATE[0], _DUPLICATE[1].format(lb_arn))
    assert got == want, f"CreateListener on the held port {port}: {got!r}, expected {want!r}"


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


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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
