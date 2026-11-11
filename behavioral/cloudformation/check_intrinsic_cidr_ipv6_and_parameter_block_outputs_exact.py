"""intrinsic-cidr-ipv6-and-parameter-block-outputs-exact."""
from __future__ import annotations

import ipaddress
import json
import time

from behavioral_harness import tags

CHECK = "intrinsic-cidr-ipv6-and-parameter-block-outputs-exact"
GROUP = "intrinsics"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0
_V6_BLOCK, _V6_COUNT, _V6_BITS = "2001:db8:1234:5600::/56", 3, 64
_V4_BLOCK, _V4_COUNT, _V4_BITS = "192.168.8.0/22", 5, 6

_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {"Block": {"Type": "String"}},
    "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    "Outputs": {
        "V6": {"Value": {"Fn::Join": [",", {"Fn::Cidr": [_V6_BLOCK, _V6_COUNT, str(_V6_BITS)]}]}},
        "V4": {"Value": {"Fn::Join": [",", {"Fn::Cidr": [{"Ref": "Block"}, str(_V4_COUNT), _V4_BITS]}]}},
        "V4Last": {"Value": {"Fn::Select": [_V4_COUNT - 1, {"Fn::Cidr": [{"Ref": "Block"}, _V4_COUNT, _V4_BITS]}]}},
    },
})


def _format(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    """CloudFormation renders an IPv6 subnet with every group spelled out, never the :: shorthand."""
    if net.version == 4:
        return str(net)
    groups = [g.lstrip("0") or "0" for g in net.network_address.exploded.split(":")]
    return f"{':'.join(groups)}/{net.prefixlen}"


def _cidr(block: str, count: int, host_bits: int) -> list[str]:
    """Fn::Cidr(block, count, host_bits) by RFC arithmetic: cidrBits counts host bits."""
    net = ipaddress.ip_network(block)
    subs = net.subnets(new_prefix=net.max_prefixlen - host_bits)
    return [_format(next(subs)) for _ in range(count)]


def _settle(cf, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"{stack_id} still {stack['StackStatus']!r} after {_DEADLINE_S}s")
        time.sleep(3.0)


def _delete_stack(cf, stack_id: str) -> None:
    """DeleteStack, then poll by StackId to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    # The first read after DeleteStack may still show the prior status, so only the two terminal
    # delete states end the poll.
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        if stack["StackStatus"] == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack_id} ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
            )
        time.sleep(3.0)


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Fn::Cidr splits an IPv6 /56 into /64s and a parameter-supplied IPv4 block into /26s, with count
    and cidrBits accepted as numbers or strings; each output is the exact subnet list, with every
    IPv6 group spelled out rather than collapsed with the :: shorthand.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/intrinsic-function-reference-cidr.html
    """
    cf = ctx.client("cloudformation")
    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-cidr6-"), TemplateBody=_TEMPLATE, Tags=_TAGS,
                               Parameters=[{"ParameterKey": "Block", "ParameterValue": _V4_BLOCK}])["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _settle(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"got {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}
    v4 = _cidr(_V4_BLOCK, _V4_COUNT, _V4_BITS)
    expected = {
        "V6": ",".join(_cidr(_V6_BLOCK, _V6_COUNT, _V6_BITS)),
        "V4": ",".join(v4),
        "V4Last": v4[-1],
    }
    assert outputs == expected, f"Fn::Cidr outputs differ: expected {expected!r}, got {outputs!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
