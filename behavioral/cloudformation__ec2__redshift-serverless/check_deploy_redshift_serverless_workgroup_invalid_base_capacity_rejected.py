"""deploy-redshift-serverless-workgroup-invalid-base-capacity-rejected."""
from __future__ import annotations

import json
import re
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-redshift-serverless-workgroup-invalid-base-capacity-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "redshift-serverless"]

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


_BAD_CAPACITY = 7
_GOOD_CAPACITY = 8
_CREATE_TIMEOUT_S = 1500.0
_REJECTED = (
    "The base capacity must be 2 or 4 in tiny RPU range. (Service: RedshiftServerless, "
    "Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _template(namespace_name: str, workgroup_name: str, base_capacity: int | None) -> str:
    """A VPC, three subnets, an SG, a Namespace and (unless ``None``) a Workgroup."""
    az = [{"Fn::Select": [i, {"Fn::GetAZs": ""}]} for i in range(3)]
    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.2.0.0/16"}},
        **{f"Subnet{x}": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": f"10.2.{i}.0/24", "AvailabilityZone": az[i]}}
           for i, x in enumerate("ABC")},
        "Sg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "GroupDescription": "sim2real redshift-serverless workgroup sg",
            "VpcId": {"Ref": "Vpc"}}},
        "Namespace": {"Type": "AWS::RedshiftServerless::Namespace", "Properties": {
            "NamespaceName": namespace_name, "AdminUsername": "sim2realadmin",
            "AdminUserPassword": {"Ref": "AdminPassword"}, "DbName": "sim2realdb"}},
    }
    outputs = {
        "VpcId": {"Value": {"Ref": "Vpc"}},
        "SgId": {"Value": {"Ref": "Sg"}},
        **{f"Subnet{x}": {"Value": {"Ref": f"Subnet{x}"}} for x in "ABC"},
    }
    if base_capacity is not None:
        resources["Workgroup"] = {"Type": "AWS::RedshiftServerless::Workgroup", "Properties": {
            "WorkgroupName": workgroup_name, "NamespaceName": {"Ref": "Namespace"},
            "BaseCapacity": base_capacity,
            "SubnetIds": [{"Ref": f"Subnet{x}"} for x in "ABC"],
            "SecurityGroupIds": [{"Ref": "Sg"}], "PubliclyAccessible": False}}
        outputs["WorkgroupRef"] = {"Value": {"Ref": "Workgroup"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"AdminPassword": {"Type": "String", "NoEcho": True}},
        "Resources": resources, "Outputs": outputs,
    })


def _await_no_enis(ec2, vpc_id: str, timeout_s: float = 600.0) -> None:
    """Poll until the VPC holds no network interface (the workgroup's endpoint ENIs detach late)."""
    deadline = time.monotonic() + timeout_s
    while True:
        enis = paginate(ec2, "describe_network_interfaces", "NetworkInterfaces",
                        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        if not enis:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"VPC {vpc_id} still holds {len(enis)} ENI(s) after {timeout_s:.0f}s")
        time.sleep(2)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation redshift-serverless Workgroup with BaseCapacity 7 is refused.

    The handler relays the exact reason and the rollback leaves neither workgroup nor namespace,
    while the same template with BaseCapacity 8 deploys and reads back through the service.
    """
    ctx.verify_account_safety()
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    rs = ctx.client("redshift-serverless")
    params = [{"ParameterKey": "AdminPassword",
               "ParameterValue": f"Sim2{secrets.token_hex(12)}Rl9"}]

    bad_ns = ctx.unique_name("sim2real-cfn-ns-bad-")
    bad_wg = ctx.unique_name("sim2real-cfn-wg-bad-")
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-stk-bad-"),
                          _template(bad_ns, bad_wg, _BAD_CAPACITY), Parameters=params)
    status = wait_stack(cfn, bad_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "ROLLBACK_COMPLETE", f"BaseCapacity={_BAD_CAPACITY} ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Workgroup"), ctx.account,
                         bad_ns, bad_wg)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"
    # Rollback absence through redshift-serverless, before this check's own delete.
    expect_error(lambda: rs.get_workgroup(workgroupName=bad_wg),
                 *("ResourceNotFoundException", f"Serverless workgroup {bad_wg} not found."))
    expect_error(lambda: rs.get_namespace(namespaceName=bad_ns),
                 *("ResourceNotFoundException", f"Serverless namespace {bad_ns} not found."))
    delete_stack(cfn, bad_id)

    # Positive control: the same template with only BaseCapacity valid.
    good_ns = ctx.unique_name("sim2real-cfn-ns-good-")
    good_wg = ctx.unique_name("sim2real-cfn-wg-good-")
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-stk-good-"),
                           _template(good_ns, good_wg, _GOOD_CAPACITY), Parameters=params)
    status = wait_stack(cfn, good_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "CREATE_COMPLETE", f"positive control stack ended {status!r}"
    out = stack_outputs(cfn, good_id)
    listed = [w["workgroupName"] for w in paginate(rs, "list_workgroups", "workgroups")
              if w["workgroupName"] == good_wg]
    assert listed == [out["WorkgroupRef"]], f"ListWorkgroups for {good_wg!r}: {listed!r}"
    wg = rs.get_workgroup(workgroupName=good_wg)["workgroup"]
    got = (wg["status"], wg["baseCapacity"], wg["namespaceName"], sorted(wg["subnetIds"]),
           wg["securityGroupIds"], wg["publiclyAccessible"])
    want = ("AVAILABLE", _GOOD_CAPACITY, good_ns, sorted(out[f"Subnet{x}"] for x in "ABC"),
            [out["SgId"]], False)
    assert got == want, f"control workgroup reads {got!r}, expected {want!r}"

    # Tear the control down in order: the workgroup first, its endpoint ENIs drain, then the rest.
    cfn.update_stack(StackName=good_id, TemplateBody=_template(good_ns, good_wg, None),
                     Parameters=[{"ParameterKey": "AdminPassword", "UsePreviousValue": True}])
    status = wait_stack(cfn, good_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "UPDATE_COMPLETE", f"workgroup-removing update ended {status!r}"
    _await_no_enis(ec2, out["VpcId"])
    delete_stack(cfn, good_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
