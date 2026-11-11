"""deploy-cfn-rds-db-subnet-group-cross-vpc-subnets-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-rds-db-subnet-group-cross-vpc-subnets-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "rds"]

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

_CIDR_A = "10.92.0.0/16"
_CIDR_B = "10.93.0.0/16"
_DESCRIPTION = "sim2real cross-vpc subnet group"
# The handler reason, account masked; RDS names the two VPCs (in either order).
_CROSS_VPC_FMT = (
    "Subnet has different VPC Id: {} than {} (Service: Rds, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)"
)


def _template(group_name: str, az_a: str, az_b: str, second_subnet: str) -> str:
    """Two VPCs: SubnetA and SubnetA2 in VpcA (two AZs), SubnetB in VpcB. The group takes SubnetA
    and ``second_subnet``, the only difference between the rejected and the control template."""
    def subnet(vpc: str, cidr: str, index: int, az: str) -> dict:
        return {
            "Type": "AWS::EC2::Subnet",
            "Properties": {
                "VpcId": {"Ref": vpc},
                "CidrBlock": {"Fn::Select": [index, {"Fn::Cidr": [cidr, 2, 8]}]},
                "AvailabilityZone": az,
            },
        }

    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "VpcA": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _CIDR_A}},
            "VpcB": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _CIDR_B}},
            "SubnetA": subnet("VpcA", _CIDR_A, 0, az_a),
            "SubnetA2": subnet("VpcA", _CIDR_A, 1, az_b),
            "SubnetB": subnet("VpcB", _CIDR_B, 0, az_b),
            "SubnetGroup": {
                "Type": "AWS::RDS::DBSubnetGroup",
                "Properties": {
                    "DBSubnetGroupName": group_name,
                    "DBSubnetGroupDescription": _DESCRIPTION,
                    "SubnetIds": [{"Ref": "SubnetA"}, {"Ref": second_subnet}],
                },
            },
        },
    })


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource the stack created (from its CREATE_COMPLETE row)."""
    return {
        e["LogicalResourceId"]: e["PhysicalResourceId"]
        for e in stack_events(cfn, stack_id)
        if e["ResourceStatus"] == "CREATE_COMPLETE" and e["PhysicalResourceId"] != stack_id
    }


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DB subnet group whose subnets lie in two VPCs fails its stack with RDS's own error, and
    rollback leaves no group and no VPC; the same template with both subnets in one VPC deploys.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")

    azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )
    assert len(azs) >= 2, f"region offers fewer than two available AZs: {azs!r}"
    az_a, az_b = azs[0], azs[1]

    good_name = ctx.unique_name("sim2real-cfnrds-dbsg-ok-")
    good_stack = ctx.unique_name("sim2real-cfnrds-okstk-")
    bad_name = ctx.unique_name("sim2real-cfnrds-dbsg-bad-")
    bad_stack = ctx.unique_name("sim2real-cfnrds-badstk-")

    good_stack_id = create_stack(ctx, cfn, good_stack, _template(good_name, az_a, az_b, "SubnetA2"))
    bad_stack_id = create_stack(ctx, cfn, bad_stack, _template(bad_name, az_a, az_b, "SubnetB"))

    good_status = wait_stack(cfn, good_stack_id, timeout_s=600.0)
    assert good_status == "CREATE_COMPLETE", (
        f"control stack settled at {good_status!r}, expected CREATE_COMPLETE"
    )
    good_ids = _physical_ids(cfn, good_stack_id)
    groups = rds.describe_db_subnet_groups(DBSubnetGroupName=good_name)["DBSubnetGroups"]
    got_good = [
        (g["DBSubnetGroupName"], g["DBSubnetGroupDescription"], g["VpcId"],
         sorted(s["SubnetIdentifier"] for s in g["Subnets"]))
        for g in groups
    ]
    want_good = [
        (good_name, _DESCRIPTION, good_ids["VpcA"],
         sorted([good_ids["SubnetA"], good_ids["SubnetA2"]]))
    ]
    assert got_good == want_good, f"expected the control group {want_good!r}, got {got_good!r}"

    bad_status = wait_stack(cfn, bad_stack_id, timeout_s=600.0)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"cross-vpc stack settled at {bad_status!r}, expected ROLLBACK_COMPLETE"
    )
    got = handler_reason(failed_reason(stack_events(cfn, bad_stack_id), "SubnetGroup"),
                         ctx.account)
    bad_ids = _physical_ids(cfn, bad_stack_id)
    vpc_a, vpc_b = bad_ids["VpcA"], bad_ids["VpcB"]
    want = [(_CROSS_VPC_FMT.format(*pair), "InvalidRequest")
            for pair in ((vpc_a, vpc_b), (vpc_b, vpc_a))]
    assert got in want, f"SubnetGroup CREATE_FAILED reason {got!r}, expected one of {want!r}"

    group_gone = ("DBSubnetGroupNotFoundFault", f"DB Subnet group '{bad_name}' not found.")
    expect_error(lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=bad_name), *group_gone)
    for vpc_id in (vpc_a, vpc_b):
        vpc_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
        expect_error(lambda vpc_id=vpc_id: ec2.describe_vpcs(VpcIds=[vpc_id]), *vpc_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
