"""deploy-ec2-security-group-egress-invalid-port-range-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-security-group-egress-invalid-port-range-rejected-and-rolled-back"
GROUP = "deploy-ec2-resource-sweep"
SERVICES = ["cloudformation", "ec2"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_VPC_CIDR = "10.110.0.0/16"
_RULE_CIDR = "10.0.0.0/8"
_IS_EGRESS = True
# The handler reason; the Request ID and SDK Attempt Count vary per call and are masked.
_REJECTED = (
    "Invalid TCP/UDP port range(100:50) (Service: Ec2, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "InvalidRequest",
)



def _template(tag_value: str, vpc_cidr: str, from_port: int, to_port: int) -> str:
    """A VPC, a security group in it and one tcp egress rule over ``from_port``-``to_port``."""
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": vpc_cidr, "Tags": t}},
            "Group": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {"GroupDescription": "sim2real egress group",
                                "VpcId": {"Ref": "Vpc"}, "Tags": t},
            },
            "Egress": {
                "Type": "AWS::EC2::SecurityGroupEgress",
                "Properties": {
                    "GroupId": {"Fn::GetAtt": ["Group", "GroupId"]},
                    "IpProtocol": "tcp", "FromPort": from_port, "ToPort": to_port,
                    "CidrIp": _RULE_CIDR,
                },
            },
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "GroupId": {"Value": {"Fn::GetAtt": ["Group", "GroupId"]}},
            "RuleId": {"Value": {"Ref": "Egress"}},
        },
    })


def _physical_ids(cfn, stack_id: str, resource_type: str) -> list[str]:
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    return [r["PhysicalResourceId"] for r in resources if r["ResourceType"] == resource_type]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::EC2::SecurityGroupEgress with FromPort above ToPort fails with EC2's
    exact error and the rollback deletes the group and VPC; the same template with the ports in
    order deploys a rule EC2 reads back with its protocol, ports and CIDR.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-securitygroupegress.html
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    bad_stack = ctx.unique_name("sim2real-ec2egressbad-")

    bad_stack_id = create_stack(ctx, cfn, bad_stack, _template(CHECK, _VPC_CIDR, 100, 50))

    status = wait_stack(cfn, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )
    got_error = handler_reason(failed_reason(stack_events(cfn, bad_stack_id), "Egress"), ctx.account)
    assert got_error == _REJECTED, (
        f"CREATE_FAILED reason: expected {_REJECTED!r}, got {got_error!r}"
    )

    vpc_ids = _physical_ids(cfn, bad_stack_id, "AWS::EC2::VPC")
    group_ids = _physical_ids(cfn, bad_stack_id, "AWS::EC2::SecurityGroup")
    assert len(vpc_ids) == 1 and len(group_ids) == 1, (
        f"expected exactly one VPC and one group, got vpcs={vpc_ids!r} groups={group_ids!r}"
    )
    vpc_id, group_id = vpc_ids[0], group_ids[0]

    # The rollback itself removed the group and VPC, before this check deletes the stack.
    group_gone = ("InvalidGroup.NotFound", f"The security group '{group_id}' does not exist")
    expect_error(lambda: ec2.describe_security_groups(GroupIds=[group_id]), *group_gone)
    vpc_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), *vpc_gone)
    delete_stack(cfn, bad_stack_id)

    # Positive control: the identical template with FromPort 50 and ToPort 100 deploys the rule
    # (the rejected stack and its VPC are gone, so the control reuses the same CIDR).
    good_stack = ctx.unique_name("sim2real-ec2egressgood-")
    good_stack_id = create_stack(ctx, cfn, good_stack, _template(CHECK, _VPC_CIDR, 50, 100))
    good_status = wait_stack(cfn, good_stack_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE"
    )
    outputs = stack_outputs(cfn, good_stack_id)
    rules = []
    for page in ec2.get_paginator("describe_security_group_rules").paginate(
            Filters=[{"Name": "group-id", "Values": [outputs["GroupId"]]}]):
        rules.extend(page["SecurityGroupRules"])
    got_rules = sorted(
        (r["IpProtocol"], r["FromPort"], r["ToPort"], r.get("CidrIpv4"), r["IsEgress"])
        for r in rules
    )
    # The group carries only the templated rule: EC2's default allow-all egress rule is gone.
    want_rules = [("tcp", 50, 100, _RULE_CIDR, _IS_EGRESS)]
    assert got_rules == want_rules, (
        f"control group {outputs['GroupId']!r} rules: expected {want_rules!r}, "
        f"EC2 reports {got_rules!r}"
    )
    rule_ids = [r["SecurityGroupRuleId"] for r in rules
                if r["IpProtocol"] == "tcp" and r["IsEgress"] is _IS_EGRESS]
    assert rule_ids == [outputs["RuleId"]], (
        f"Ref of the rule {outputs['RuleId']!r}, EC2 reports the tcp rule ids {rule_ids!r}"
    )
    groups = [(g["VpcId"], g["Description"]) for g in ec2.describe_security_groups(
        GroupIds=[outputs["GroupId"]])["SecurityGroups"]]
    assert groups == [(outputs["VpcId"], "sim2real egress group")], (
        f"control group (VpcId, Description) {groups!r}, expected the stack's VPC and the "
        f"template's description"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
