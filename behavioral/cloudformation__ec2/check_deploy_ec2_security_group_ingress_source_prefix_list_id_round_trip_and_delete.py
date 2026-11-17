"""deploy-ec2-security-group-ingress-source-prefix-list-id-round-trip-and-delete."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-security-group-ingress-source-prefix-list-id-round-trip-and-delete"
GROUP = "deploy-cfn-resource-existence"
SERVICES = ["cloudformation", "ec2"]

VPC_BLOCK = "10.86.0.0/16"


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "PrefixListId": {"Type": "String"},
        },
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": VPC_BLOCK}},
            "Sg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real-xsvc-plingress",
                    "VpcId": {"Ref": "Vpc"},
                },
            },
            "Ingress": {
                "Type": "AWS::EC2::SecurityGroupIngress",
                "Properties": {
                    "GroupId": {"Fn::GetAtt": ["Sg", "GroupId"]},
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "SourcePrefixListId": {"Ref": "PrefixListId"},
                },
            },
        },
        "Outputs": {
            "SgId": {"Value": {"Fn::GetAtt": ["Sg", "GroupId"]}},
            "IngressId": {"Value": {"Ref": "Ingress"}},
        },
    }


_CREATE_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
    }
)
_DELETE_TERMINAL = frozenset({"DELETE_COMPLETE", "DELETE_FAILED"})


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _stack(cfn, stack_id: str) -> dict:
    """The stack read by StackId; the exact not-found pair reads as DELETE_COMPLETE."""
    try:
        return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
            "ValidationError",
            f"Stack with id {stack_id} does not exist",
        ):
            return {"StackId": stack_id, "StackStatus": "DELETE_COMPLETE"}
        raise


def _wait_stack(ctx, cfn, stack_id: str, terminal, timeout_s: float) -> dict:
    return _poll_until(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: s["StackStatus"] in terminal,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"stack {stack_id} reaches one of {sorted(terminal)}",
    )


def _delete_stack(ctx, cfn, stack_id: str, timeout_s: float = 900.0) -> None:
    """Delete the stack whatever state it is in, and raise unless it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _wait_stack(ctx, cfn, stack_id, _DELETE_TERMINAL, timeout_s)
    if final["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_id} delete ended {final['StackStatus']!r}: "
            f"{final.get('StackStatusReason')!r}"
        )


def _expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code!r} but the call succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN SecurityGroupIngress rule declaring SourcePrefixListId reads back through
    DescribeSecurityGroupRules as the rule its Ref names, with the exact prefix list id and no
    CIDR; deleting the stack deletes the group."""
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    pl_name = ctx.unique_name("sim2real-xsvc-plingress-")
    pl = ec2.create_managed_prefix_list(
        PrefixListName=pl_name,
        AddressFamily="IPv4",
        MaxEntries=1,
        Entries=[{"Cidr": "198.51.100.0/24", "Description": "sim2real"}],
        TagSpecifications=[
            {"ResourceType": "prefix-list", "Tags": [{"Key": "sim2real", "Value": pl_name}]}
        ],
    )["PrefixList"]
    pl_id = pl["PrefixListId"]
    ctx.on_cleanup(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id))
    _poll_until(
        ctx,
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0]["State"],
        lambda state: state == "create-complete",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"prefix list {pl_id} 'create-complete'",
    )

    name = ctx.unique_name("sim2real-xsvc-plingress-")
    stack_id = cfn.create_stack(
        StackName=name,
        TemplateBody=json.dumps(_template()),
        Parameters=[{"ParameterKey": "PrefixListId", "ParameterValue": pl_id}],
        Tags=[{"Key": "sim2real", "Value": name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack_id))

    stack = _wait_stack(ctx, cfn, stack_id, _CREATE_TERMINAL, 600.0)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), "
        f"expected 'CREATE_COMPLETE'"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    sg_id = outputs["SgId"]

    rules = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [sg_id]}])[
        "SecurityGroupRules"
    ]
    ingress_rules = [r for r in rules if not r["IsEgress"]]
    assert len(ingress_rules) == 1, (
        f"expected exactly one ingress rule on {sg_id!r}, EC2 reports {ingress_rules!r}"
    )
    rule = ingress_rules[0]
    got = (
        rule["SecurityGroupRuleId"],
        rule["IpProtocol"],
        rule["FromPort"],
        rule["ToPort"],
        rule["PrefixListId"],
        rule.get("CidrIpv4"),
        rule.get("CidrIpv6"),
    )
    want = (outputs["IngressId"], "tcp", 443, 443, pl_id, None, None)
    assert got == want, f"expected {want!r}, EC2 reports {got!r}"

    _delete_stack(ctx, cfn, stack_id)
    group_gone = ("InvalidGroup.NotFound", f"The security group '{sg_id}' does not exist")
    _expect_error(lambda: ec2.describe_security_groups(GroupIds=[sg_id]), *group_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
