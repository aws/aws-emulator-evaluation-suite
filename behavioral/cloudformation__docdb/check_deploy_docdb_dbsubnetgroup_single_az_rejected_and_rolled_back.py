"""deploy-docdb-dbsubnetgroup-single-az-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-docdb-dbsubnetgroup-single-az-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "docdb"]

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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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


_VPC_CIDR = "10.130.0.0/16"
_DESCRIPTION = "sim2real docdb subnet group"
_REJECTED = (
    "The DB subnet group doesn't meet Availability Zone (AZ) coverage requirement. "
    "Current AZ coverage: <az>. Add subnets to cover at least 2 AZs. "
    "(Service: Rds, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _template(name: str, tag_value: str, subnets: list[str]) -> str:
    """Two subnets in two AZs; the subnet group names ``subnets`` of them (the one variable)."""
    az = [{"Fn::Select": [i, {"Fn::GetAZs": ""}]} for i in range(2)]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
            "SubnetA": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.130.1.0/24",
                               "AvailabilityZone": az[0]},
            },
            "SubnetB": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.130.2.0/24",
                               "AvailabilityZone": az[1]},
            },
            "SubnetGroup": {
                "Type": "AWS::DocDB::DBSubnetGroup",
                "Properties": {
                    "DBSubnetGroupName": name,
                    "DBSubnetGroupDescription": _DESCRIPTION,
                    "SubnetIds": [{"Ref": s} for s in subnets],
                    "Tags": [{"Key": "sim2real-res", "Value": tag_value}],
                },
            },
        },
        "Outputs": {
            "SubnetGroupName": {"Value": {"Ref": "SubnetGroup"}},
            "SubnetA": {"Value": {"Ref": "SubnetA"}},
            "SubnetB": {"Value": {"Ref": "SubnetB"}},
            "AzA": {"Value": {"Fn::GetAtt": ["SubnetA", "AvailabilityZone"]}},
            "AzB": {"Value": {"Fn::GetAtt": ["SubnetB", "AvailabilityZone"]}},
        },
    })


@tags("axis:rejection", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::DocDB::DBSubnetGroup naming subnets in one AZ is refused by DocDB.

    The stack rolls back and DocDB has no group by that name, while the same template naming
    subnets in two AZs deploys and reads back through DocDB.
    """
    docdb = ctx.client("docdb")
    cfn = ctx.client("cloudformation")
    bad_name = ctx.unique_name("sim2real-docdbsg1az-")
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-docdbsg1az-stack-"),
                          _template(bad_name, bad_name, ["SubnetA"]))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    assert rows == [], f"refused by early validation, not by DocDB: {rows!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "SubnetGroup")
    message, code = handler_reason(reason, ctx.account, bad_name)
    # The AZ CloudFormation picked is masked by shape: <region><letter>.
    got = (re.sub(rf"\b{re.escape(ctx.region)}[a-z]\b", "<az>", message), code)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through DocDB, by the name the group would have, before this check deletes.
    db_subnet_groups_gone = (
        "DBSubnetGroupNotFoundFault",
        f"DB Subnet group '{bad_name}' not found.",
    )
    expect_error(lambda: docdb.describe_db_subnet_groups(DBSubnetGroupName=bad_name),
                 *db_subnet_groups_gone)
    delete_stack(cfn, bad_id)

    # Positive control: the same template with SubnetIds covering two AZs.
    good_name = ctx.unique_name("sim2real-docdbsg2az-")
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-docdbsg2az-stack-"),
                           _template(good_name, good_name, ["SubnetA", "SubnetB"]))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    assert out["SubnetGroupName"] == good_name, f"control Ref {out['SubnetGroupName']!r}"
    groups = docdb.describe_db_subnet_groups(DBSubnetGroupName=good_name)["DBSubnetGroups"]
    assert len(groups) == 1, f"DescribeDBSubnetGroups({good_name!r}) returned {groups!r}"
    group = groups[0]
    got = (group["DBSubnetGroupName"], group["DBSubnetGroupDescription"],
           group["SubnetGroupStatus"],
           sorted((s["SubnetIdentifier"], s["SubnetAvailabilityZone"]["Name"])
                  for s in group["Subnets"]))
    want = (good_name, _DESCRIPTION, "Complete",
            sorted([(out["SubnetA"], out["AzA"]), (out["SubnetB"], out["AzB"])]))
    assert got == want, f"control subnet group reads {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
