"""deploy-ec2-security-group-ingress-unknown-source-prefix-list-id-rejected-and-rolled-back."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-security-group-ingress-unknown-source-prefix-list-id-rejected-and-rolled-back"
GROUP = "deploy-ec2-resource-sweep"
SERVICES = ["cloudformation", "ec2"]

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "IMPORT_ROLLBACK_FAILED",
    }
)
_DELETE_BUDGET_S = 600.0
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)

#: A syntactically valid managed-prefix-list id this check never created.
_UNKNOWN_PL_ID = "pl-0123456789abcdef0"
_REJECTED_MESSAGE = (
    f"The prefix list ID '{_UNKNOWN_PL_ID}' does not exist (Service: Ec2, Status Code: 400, "
    "Request ID: <id>) (SDK Attempt Count: <n>)"
)
_REJECTED = (_REJECTED_MESSAGE, "InvalidRequest")


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice."""
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic()
    )
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def delete_stack_named(cf, name, stack_id=None):
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                "ValidationError",
                f"Stack with id {name} does not exist",
            ):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    return [
        e
        for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
        for e in page["StackEvents"]
    ][::-1]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text):
    """``text`` masking only Request ID and SDK Attempt Count."""
    text = re.sub(r"Request ID: [^,;)]+", "Request ID: <id>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    return text


def handler_reason(reason):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"]), m["code"]


def physical_ids(cfn, stack_id, resource_type):
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    return [r["PhysicalResourceId"] for r in resources if r["ResourceType"] == resource_type]


def expect_error(fn, code, message):
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _template(prefix_list_id: str, cidr: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": cidr}},
                "Sg": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "sim2real-xsvc-plneg",
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
                        "SourcePrefixListId": prefix_list_id,
                    },
                },
            },
            "Outputs": {
                "SgId": {"Value": {"Fn::GetAtt": ["Sg", "GroupId"]}},
            },
        }
    )


def _poll_prefix_list_state(ec2, pl_id: str, timeout_s: float = 60.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        state = ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0]["State"]
        if state != "create-in-progress" or time.monotonic() > deadline:
            return state
        time.sleep(2)


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CFN AWS::EC2::SecurityGroupIngress naming an unknown SourcePrefixListId fails with EC2's
    exact error and the rollback deletes the group and VPC; the same template naming a managed
    prefix list the check created deploys a rule EC2 reads back with that exact id."""
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")

    bad_stack = ctx.unique_name("sim2real-ec2plneg-")
    bad_stack_id = create_stack(ctx, cfn, bad_stack, _template(_UNKNOWN_PL_ID, "10.97.0.0/16"))

    status = wait_stack(cfn, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )
    got = handler_reason(failed_reason(stack_events(cfn, bad_stack_id), "Ingress"))
    assert got == _REJECTED, f"CREATE_FAILED reason: expected {_REJECTED!r}, got {got!r}"

    vpc_ids = physical_ids(cfn, bad_stack_id, "AWS::EC2::VPC")
    group_ids = physical_ids(cfn, bad_stack_id, "AWS::EC2::SecurityGroup")
    assert len(vpc_ids) == 1 and len(group_ids) == 1, (
        f"expected exactly one VPC and one group, got vpcs={vpc_ids!r} groups={group_ids!r}"
    )
    group_gone = ("InvalidGroup.NotFound", f"The security group '{group_ids[0]}' does not exist")
    expect_error(lambda: ec2.describe_security_groups(GroupIds=[group_ids[0]]), *group_gone)
    vpc_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_ids[0]}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc_ids[0]]), *vpc_gone)
    delete_stack(cfn, bad_stack_id)

    # Positive control: the same shape naming a prefix list that exists deploys the rule.
    pl_name = ctx.unique_name("sim2real-ec2plneg-")
    pl_id = ec2.create_managed_prefix_list(
        PrefixListName=pl_name,
        AddressFamily="IPv4",
        MaxEntries=1,
        Entries=[{"Cidr": "203.0.113.0/24", "Description": "sim2real"}],
        TagSpecifications=[
            {"ResourceType": "prefix-list", "Tags": [{"Key": "sim2real", "Value": pl_name}]}
        ],
    )["PrefixList"]["PrefixListId"]
    ctx.on_cleanup(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id))
    pl_state = _poll_prefix_list_state(ec2, pl_id)
    assert pl_state == "create-complete", (
        f"prefix list {pl_id} did not reach 'create-complete', got {pl_state!r}"
    )

    good_stack = ctx.unique_name("sim2real-ec2plneg-")
    good_stack_id = create_stack(ctx, cfn, good_stack, _template(pl_id, "10.98.0.0/16"))
    good_status = wait_stack(cfn, good_stack_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE"
    )
    outputs = stack_outputs(cfn, good_stack_id)
    rules = ec2.describe_security_group_rules(
        Filters=[{"Name": "group-id", "Values": [outputs["SgId"]]}]
    )["SecurityGroupRules"]
    ingress_rules = [r for r in rules if not r["IsEgress"]]
    assert len(ingress_rules) == 1, (
        f"expected exactly one ingress rule on {outputs['SgId']!r}, EC2 reports {ingress_rules!r}"
    )
    assert ingress_rules[0]["PrefixListId"] == pl_id, (
        f"expected PrefixListId {pl_id!r}, EC2 reports {ingress_rules[0]['PrefixListId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
