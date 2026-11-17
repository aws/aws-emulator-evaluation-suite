"""cfn-elbv2-gateway-load-balancer-geneve-target-group-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-elbv2-gateway-load-balancer-geneve-target-group-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "elbv2"]

_POLL_S = 2.0
_STACK_CAP_S = 900.0
_CONVERGE_CAP_S = 120.0

def _lb_gone(arn: str) -> tuple[str, str]:
    return "LoadBalancerNotFound", f"Load balancers '[{arn}]' not found"


def _tg_gone(arn: str) -> tuple[str, str]:
    return "TargetGroupNotFound", f"Target groups '[{arn}]' not found"


_LISTENER_GONE = ("ListenerNotFound", "One or more listeners not found")

#: The two revisions: load balancer cross-zone attribute, target group health-check interval.
_V1 = ("false", 10)
_V2 = ("true", 30)


def _template(name: str, cross_zone: str, interval: int) -> str:
    tag = [{"Key": "sim2real", "Value": CHECK}]
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": "10.97.0.0/16", "Tags": tag},
                },
                "Subnet": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "CidrBlock": "10.97.1.0/24",
                        "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                        "Tags": tag,
                    },
                },
                "Gwlb": {
                    "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                    "Properties": {
                        "Name": name,
                        "Type": "gateway",
                        "Subnets": [{"Ref": "Subnet"}],
                        "LoadBalancerAttributes": [
                            {"Key": "load_balancing.cross_zone.enabled", "Value": cross_zone},
                        ],
                        "Tags": tag,
                    },
                },
                "Tg": {
                    "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "Protocol": "GENEVE",
                        "Port": 6081,
                        "TargetType": "ip",
                        "HealthCheckProtocol": "TCP",
                        "HealthCheckPort": "80",
                        "HealthCheckIntervalSeconds": interval,
                        "Tags": tag,
                    },
                },
                "Listener": {
                    "Type": "AWS::ElasticLoadBalancingV2::Listener",
                    "Properties": {
                        "LoadBalancerArn": {"Ref": "Gwlb"},
                        "DefaultActions": [{"Type": "forward", "TargetGroupArn": {"Ref": "Tg"}}],
                    },
                },
            },
            "Outputs": {
                "GwlbRef": {"Value": {"Ref": "Gwlb"}},
                "GwlbFullName": {"Value": {"Fn::GetAtt": ["Gwlb", "LoadBalancerFullName"]}},
                "TgRef": {"Value": {"Ref": "Tg"}},
                "TgFullName": {"Value": {"Fn::GetAtt": ["Tg", "TargetGroupFullName"]}},
                "ListenerRef": {"Value": {"Ref": "Listener"}},
            },
        }
    )


def _deadline(seconds: float) -> float:
    return time.monotonic() + seconds


def _poll_until(read, satisfied, what: str, cap_s: float = _CONVERGE_CAP_S):
    """Poll ``read()`` until ``satisfied(value)``; raise naming the last value otherwise."""
    end = _deadline(cap_s)
    value = read()
    while not satisfied(value):
        if time.monotonic() >= end:
            raise AssertionError(f"{what} not reached within {cap_s:.0f}s; last read {value!r}")
        time.sleep(_POLL_S)
        value = read()
    return value


def _poll_for_error(fn, want: tuple[str, str], what: str, cap_s: float = _CONVERGE_CAP_S):
    """Poll ``fn()`` until it raises exactly *want*; a delete can lag its DELETE_COMPLETE."""
    end = _deadline(cap_s)
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = (err.get("Code"), err.get("Message"))
            if got == want:
                return got
            raise AssertionError(f"{what}: expected {want!r}, got {got!r}") from None
        if time.monotonic() >= end:
            raise AssertionError(f"{what} still answered after {cap_s:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _stack_settled(cfn, stack_id: str, cap_s: float = _STACK_CAP_S) -> dict:
    """Poll ``DescribeStacks`` until the stack leaves every ``*_IN_PROGRESS`` status."""
    return _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_id)["Stacks"][0],
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        f"stack {stack_id}",
        cap_s,
    )


def _require_status(cfn, stack: dict, want: str) -> None:
    if stack["StackStatus"] == want:
        return
    failures = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _all_events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r}, expected {want!r}; failed resources: {failures!r}"
    )


def _all_events(cfn, stack_id: str) -> list[dict]:
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _resource_statuses(events: list[dict], since: set[str], logical_id: str) -> list[str]:
    """The ``ResourceStatus`` values of *logical_id*'s events raised after *since*, in order."""
    return [
        e["ResourceStatus"]
        for e in events
        if e["EventId"] not in since and e["LogicalResourceId"] == logical_id
    ]


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only *not_found* codes mean the resource is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation Gateway Load Balancer and its GENEVE target group read back as templated.

    An attribute and health-check change updates both in place; the stack delete then leaves
    every one of the three resources unreachable with its exact not-found error.

    Reference:
    https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/create-target-group.html
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticloadbalancingv2-loadbalancer.html
    """
    cfn = ctx.client("cloudformation")
    elbv2 = ctx.client("elbv2")

    name = ctx.unique_name("sim2real-gwlb-")
    stack_name = ctx.unique_name("sim2real-cfngwlb-stack-")
    ref = {"stack": stack_name}

    ctx.on_cleanup(_teardown(lambda: _delete_stack(cfn, ref["stack"]), "ValidationError"))

    # ---- 1. create: CloudFormation's view and ELB's view of every resource
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(name, *_V1),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    stack = _stack_settled(cfn, ref["stack"])
    _require_status(cfn, stack, "CREATE_COMPLETE")

    ids = _physical_ids(cfn, ref["stack"])
    gwlb_arn, tg_arn, listener_arn = ids["Gwlb"], ids["Tg"], ids["Listener"]
    outputs = _outputs(stack)
    assert outputs["GwlbRef"] == gwlb_arn, (
        f"Ref Gwlb {outputs['GwlbRef']!r} must equal the stack's own PhysicalResourceId {gwlb_arn!r}"
    )
    assert outputs["TgRef"] == tg_arn, (
        f"Ref Tg {outputs['TgRef']!r} must equal the stack's own PhysicalResourceId {tg_arn!r}"
    )
    assert outputs["ListenerRef"] == listener_arn, (
        f"Ref Listener {outputs['ListenerRef']!r} must equal the stack's own "
        f"PhysicalResourceId {listener_arn!r}"
    )

    _assert_gwlb(elbv2, gwlb_arn, name, _V1[0])
    full_name = gwlb_arn.split(":loadbalancer/", 1)[-1]
    assert outputs["GwlbFullName"] == full_name, (
        f"Fn::GetAtt LoadBalancerFullName {outputs['GwlbFullName']!r} must be the ARN's "
        f"resource id minus its 'loadbalancer/' prefix, {full_name!r}"
    )

    _assert_target_group(elbv2, tg_arn, _V1[1])
    tg_full_name = tg_arn.split(":", 5)[-1]
    assert outputs["TgFullName"] == tg_full_name, (
        f"Fn::GetAtt TargetGroupFullName {outputs['TgFullName']!r} must be the ARN's "
        f"resource id, {tg_full_name!r}"
    )

    listener = _assert_listener(elbv2, listener_arn, gwlb_arn, tg_arn)
    assert listener["ListenerArn"] == listener_arn, (
        f"Ref Listener {listener_arn!r} must equal DescribeListeners' own ListenerArn "
        f"{listener['ListenerArn']!r}"
    )

    # The forward action associates the target group with its gateway load balancer.
    _assert_target_group_bound(elbv2, tg_arn, gwlb_arn)

    # ---- 2. in-place: a new cross-zone attribute and health-check interval, the same resources
    since_gwlb = set(_resource_statuses_seen(cfn, ref["stack"], "Gwlb"))
    since_tg = set(_resource_statuses_seen(cfn, ref["stack"], "Tg"))
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(name, *_V2),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack = _stack_settled(cfn, ref["stack"])
    _require_status(cfn, stack, "UPDATE_COMPLETE")

    updated_ids = _physical_ids(cfn, ref["stack"])
    assert updated_ids["Gwlb"] == gwlb_arn, "an in-place attribute update must keep the load balancer"
    assert updated_ids["Tg"] == tg_arn, "an in-place health-check update must keep the target group"
    _assert_updated_in_place(cfn, ref["stack"], "Gwlb", since_gwlb)
    _assert_updated_in_place(cfn, ref["stack"], "Tg", since_tg)
    _assert_gwlb(elbv2, gwlb_arn, name, _V2[0])
    _assert_target_group(elbv2, tg_arn, _V2[1])

    # ---- 3. delete: every one of the three resources answers its own exact not-found error
    _delete_stack(cfn, ref["stack"])
    _poll_for_error(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[gwlb_arn]),
        _lb_gone(gwlb_arn),
        f"DescribeLoadBalancers for the deleted {gwlb_arn}",
    )
    _poll_for_error(
        lambda: elbv2.describe_target_groups(TargetGroupArns=[tg_arn]),
        _tg_gone(tg_arn),
        f"DescribeTargetGroups for the deleted {tg_arn}",
    )
    _poll_for_error(
        lambda: elbv2.describe_listeners(ListenerArns=[listener_arn]),
        _LISTENER_GONE,
        f"DescribeListeners for the deleted {listener_arn}",
    )


def _resource_statuses_seen(cfn, stack_id: str, logical_id: str) -> list[str]:
    return [e["EventId"] for e in _all_events(cfn, stack_id) if e["LogicalResourceId"] == logical_id]


def _assert_updated_in_place(cfn, stack_id: str, logical_id: str, since: set[str]) -> None:
    statuses = _resource_statuses(_all_events(cfn, stack_id), since, logical_id)
    collapsed = [s for i, s in enumerate(statuses) if i == 0 or statuses[i - 1] != s]
    assert collapsed == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no create, delete or replacement, "
        f"its events were {statuses!r}"
    )


def _assert_gwlb(elbv2, arn: str, name: str, cross_zone: str) -> dict:
    """ELB reports the templated gateway load balancer exactly; return its live row."""

    def view():
        (lb,) = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"]
        attrs = {
            a["Key"]: a["Value"]
            for a in elbv2.describe_load_balancer_attributes(LoadBalancerArn=arn)["Attributes"]
        }
        return lb, attrs.get("load_balancing.cross_zone.enabled")

    def satisfied(value):
        lb, cz = value
        return lb["State"]["Code"] == "active" and cz == cross_zone

    lb, cz = _poll_until(view, satisfied, f"gateway load balancer {name} as templated")
    assert lb["Type"] == "gateway", f"expected Type gateway, got {lb['Type']!r}"
    assert lb.get("Scheme") is None, f"a gateway load balancer carries no Scheme, got {lb.get('Scheme')!r}"
    assert lb["LoadBalancerName"] == name, (
        f"expected LoadBalancerName {name!r}, got {lb['LoadBalancerName']!r}"
    )
    assert cz == cross_zone, (
        f"expected load_balancing.cross_zone.enabled {cross_zone!r}, got {cz!r}"
    )
    return lb


def _assert_target_group(elbv2, arn: str, interval: int) -> dict:
    """ELB reports the templated GENEVE target group exactly; return its live row."""

    def view():
        (tg,) = elbv2.describe_target_groups(TargetGroupArns=[arn])["TargetGroups"]
        return tg

    tg = _poll_until(
        view, lambda tg: tg["HealthCheckIntervalSeconds"] == interval, f"target group {arn} as templated"
    )
    assert tg["Protocol"] == "GENEVE", f"expected Protocol GENEVE, got {tg['Protocol']!r}"
    assert tg["Port"] == 6081, f"expected Port 6081, got {tg['Port']!r}"
    assert tg["TargetType"] == "ip", f"expected TargetType ip, got {tg['TargetType']!r}"
    assert tg["HealthCheckProtocol"] == "TCP", (
        f"expected HealthCheckProtocol TCP, got {tg['HealthCheckProtocol']!r}"
    )
    assert tg["HealthCheckPort"] == "80", f"expected HealthCheckPort 80, got {tg['HealthCheckPort']!r}"
    assert tg["HealthCheckIntervalSeconds"] == interval, (
        f"expected HealthCheckIntervalSeconds {interval!r}, got {tg['HealthCheckIntervalSeconds']!r}"
    )
    return tg


def _assert_listener(elbv2, arn: str, gwlb_arn: str, tg_arn: str) -> dict:
    (listener,) = elbv2.describe_listeners(ListenerArns=[arn])["Listeners"]
    assert listener["LoadBalancerArn"] == gwlb_arn, (
        f"expected LoadBalancerArn {gwlb_arn!r}, got {listener['LoadBalancerArn']!r}"
    )
    (action,) = listener["DefaultActions"]
    assert action["Type"] == "forward", f"expected a forward action, got {action['Type']!r}"
    assert action["TargetGroupArn"] == tg_arn, (
        f"expected the default action to forward to {tg_arn!r}, got {action['TargetGroupArn']!r}"
    )
    return listener


def _assert_target_group_bound(elbv2, tg_arn: str, gwlb_arn: str) -> None:
    """The listener's forward action associates the target group with its load balancer."""

    def read():
        (tg,) = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"]
        return tg["LoadBalancerArns"]

    got = _poll_until(read, lambda arns: arns == [gwlb_arn], f"target group {tg_arn} bound to {gwlb_arn}")
    assert got == [gwlb_arn], f"expected LoadBalancerArns [{gwlb_arn!r}], got {got!r}"


def _delete_stack(cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    _require_status(cfn, _stack_settled(cfn, stack_id), "DELETE_COMPLETE")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
