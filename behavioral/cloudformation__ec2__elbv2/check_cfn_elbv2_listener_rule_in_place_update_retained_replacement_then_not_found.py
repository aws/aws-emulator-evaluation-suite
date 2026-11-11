"""cfn-elbv2-listener-rule-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-elbv2-listener-rule-in-place-update-retained-replacement-then-not-found"
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

#: ELB's refusal of a rule that no longer exists.
_NOT_FOUND = ("RuleNotFound", "One or more rules not found")
#: ELB's refusal of a second rule at a priority the listener already holds (that priority).
_PRIORITY_IN_USE = ("PriorityInUse", "Priority '{}' is currently in use")

#: The priority of the rule the check adds next to the stack's rule.
_OWN_PRIORITY = 20

_DEFAULT_ACTIONS = [
    {
        "Type": "fixed-response",
        "Order": 1,
        "FixedResponseConfig": {
            "StatusCode": "404",
            "ContentType": "text/plain",
            "MessageBody": "no rule matched",
        },
    }
]


def _path(pattern: str) -> list[dict]:
    """A path-pattern condition as DescribeRules echoes it (Values mirrors PathPatternConfig)."""
    return [
        {"Field": "path-pattern", "Values": [pattern], "PathPatternConfig": {"Values": [pattern]}}
    ]


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


#: The rule revisions: (priority, path pattern, actions).
_V1 = (10, "/a/*", _fixed("200", "rule revision one"))
_V2 = (
    30,
    "/b/*",
    [
        {
            "Type": "redirect",
            "Order": 1,
            "RedirectConfig": {
                "Protocol": "HTTP",
                "Port": "8081",
                "Host": "#{host}",
                "Path": "/moved",
                "Query": "#{query}",
                "StatusCode": "HTTP_302",
            },
        }
    ],
)


def _template(lb_name: str, subnets: list[str], group: str, owner: str, revision: tuple) -> str:
    priority, pattern, actions = revision

    def listener(port: int) -> dict:
        return {
            "Type": "AWS::ElasticLoadBalancingV2::Listener",
            "Properties": {
                "LoadBalancerArn": {"Ref": "LoadBalancer"},
                "Protocol": "HTTP",
                "Port": port,
                "DefaultActions": _DEFAULT_ACTIONS,
            },
        }

    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "LoadBalancer": {
                    "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                    "Properties": {
                        "Name": lb_name,
                        "Type": "application",
                        "Scheme": "internal",
                        "Subnets": subnets,
                        "SecurityGroups": [group],
                        "Tags": _TAGS,
                    },
                },
                "ListenerA": listener(8080),
                "ListenerB": listener(8081),
                "Rule": {
                    "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
                    # ListenerArn is create-only, so moving it replaces the rule.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "ListenerArn": {"Ref": owner},
                        "Priority": priority,
                        "Conditions": [
                            {"Field": "path-pattern", "PathPatternConfig": {"Values": [pattern]}}
                        ],
                        "Actions": actions,
                    },
                },
            },
            "Outputs": {
                "RuleArn": {"Value": {"Fn::GetAtt": ["Rule", "RuleArn"]}},
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
    """A CloudFormation listener rule takes its priority slot in DescribeRules' order.

    A priority, condition and action change keeps the rule and reorders it past another; a move
    to another listener under UpdateReplacePolicy Retain keeps the old rule; delete: RuleNotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticloadbalancingv2-listenerrule.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    network = ctx.network()
    subnets = list(network.subnet_ids[:2])
    group = network.security_group_id
    lb_name = ctx.unique_name("sim2real-rule-")
    stack_name = ctx.unique_name("sim2real-cfnrule-stack-")
    ref = {"stack": stack_name}
    own = {}

    # Teardown waits on one deadline of its own: the body's deadline does not bound cleanup.
    # LIFO: the stack (and with its listeners every rule) goes, then the ENIs release.
    limit: dict = {}
    ctx.on_cleanup(lambda: _await_eni_release(ec2, network.vpc_id, [lb_name], limit))
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref, limit))
    ctx.on_cleanup(lambda: _delete_rule(elbv2, own.get("arn")))

    def template(owner: str, revision: tuple) -> str:
        return _template(lb_name, subnets, group, owner, revision)

    # ---- 1. create: CloudFormation's view, ELB's view, the rule holds its priority
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=template("ListenerA", _V1), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    listener_a, listener_b, first = ids["ListenerA"], ids["ListenerB"], ids["Rule"]
    assert _outputs(stack) == {"RuleArn": first}, f"GetAtt outputs {_outputs(stack)!r}"
    taken = _error(
        lambda: elbv2.create_rule(
            ListenerArn=listener_a,
            Priority=_V1[0],
            Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/own/*"]}}],
            Actions=_fixed("200", "own rule"),
        )
    )
    want = (_PRIORITY_IN_USE[0], _PRIORITY_IN_USE[1].format(_V1[0]))
    assert taken == want, f"CreateRule at the stack rule's priority: {taken!r}, expected {want!r}"
    own["arn"] = elbv2.create_rule(
        ListenerArn=listener_a,
        Priority=_OWN_PRIORITY,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/own/*"]}}],
        Actions=_fixed("200", "own rule"),
    )["Rules"][0]["RuleArn"]
    own_row = (own["arn"], str(_OWN_PRIORITY), _path("/own/*"), _fixed("200", "own rule"))
    _assert_rules(ctx, elbv2, listener_a, [_row(first, _V1), own_row])

    # ---- 2. in-place: a new priority, condition and redirect action, the same rule
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=template("ListenerA", _V2), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Rule"] == first, "an in-place update keeps the rule"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Rule"), first, "Rule")
    _assert_rules(ctx, elbv2, listener_a, [own_row, _row(first, _V2)])

    # ---- 3. replacement under UpdateReplacePolicy Retain: a rule on listener B, A's rule kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=template("ListenerB", _V2), Tags=_TAGS)
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second = _physical_ids(cfn, ref["stack"])["Rule"]
    assert second != first, f"the replacement must be a new rule, still {first!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Rule"), first, second, "Rule"
    )
    assert _outputs(stack) == {"RuleArn": second}, (
        f"GetAtt outputs after replacement {_outputs(stack)!r}"
    )
    _assert_rules(ctx, elbv2, listener_b, [_row(second, _V2)])
    _assert_rules(ctx, elbv2, listener_a, [own_row, _row(first, _V2)])

    # ---- 4. delete: all three rules go with the stack's listeners
    _delete_stack(ctx, cfn, ref["stack"], _STACK_CAP_S)
    for arn in (second, first, own["arn"]):
        got = _wait_error(
            ctx,
            lambda arn=arn: elbv2.describe_rules(RuleArns=[arn]),
            _NOT_FOUND[0],
            f"rule {arn}",
        )
        assert got == _NOT_FOUND, f"DescribeRules {arn} after the stack delete: {got!r}"


def _row(arn: str, revision: tuple) -> tuple:
    priority, pattern, actions = revision
    return (arn, str(priority), _path(pattern), actions)


def _rules(elbv2, listener_arn: str) -> list[tuple]:
    """(rule ARN or "default", priority, conditions, actions) per rule, in DescribeRules order."""
    return [
        (
            "default" if r.get("IsDefault") else r["RuleArn"],
            r.get("Priority"),
            r.get("Conditions"),
            r.get("Actions"),
        )
        for r in elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    ]


def _assert_rules(ctx, elbv2, listener_arn: str, rules: list[tuple]) -> None:
    """DescribeRules lists *rules* in priority order, then the listener's default rule."""
    want = [*rules, ("default", "default", [], _DEFAULT_ACTIONS)]
    got = _poll(
        ctx, lambda: _rules(elbv2, listener_arn), lambda r: r == want, f"rules of {listener_arn}"
    )
    assert got == want, f"DescribeRules {listener_arn}: {got!r}, expected {want!r}"


def _delete_rule(elbv2, arn: str | None) -> None:
    """Delete the rule; a refused delete passes only on DescribeRules' exact not-found pair."""
    if arn is None:
        return
    try:
        elbv2.delete_rule(RuleArn=arn)
    except ClientError as exc:
        try:
            elbv2.describe_rules(RuleArns=[arn])
        except ClientError as gone:
            err = gone.response["Error"]
            if (err["Code"], err.get("Message")) == _NOT_FOUND:
                return
            raise exc from gone
        raise


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
        if e["ResourceStatus"].endswith("_FAILED") or e.get("ResourceStatusReason")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed or explained events: {failed!r}"
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
