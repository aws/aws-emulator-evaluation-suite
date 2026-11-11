"""deploy-redshift-serverless-workgroup-snapshot-provisions-and-tombstones."""
from __future__ import annotations

import json
import re
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-redshift-serverless-workgroup-snapshot-provisions-and-tombstones"
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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


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


_ADMIN_USERNAME = "sim2realadmin"
_DB_NAME = "sim2realdb"
_BASE_CAPACITY = 8
_RETENTION_DAYS = 1
_CREATE_TIMEOUT_S = 1500.0


def _template(namespace_name: str, workgroup_name: str, snapshot_name: str,
              with_children: bool = True) -> str:
    az = [{"Fn::Select": [i, {"Fn::GetAZs": ""}]} for i in range(3)]
    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {
            "CidrBlock": "10.0.0.0/16", "EnableDnsSupport": True, "EnableDnsHostnames": True}},
        **{f"Subnet{x}": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": f"10.0.{i}.0/24", "AvailabilityZone": az[i]}}
           for i, x in enumerate("ABC")},
        "Sg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "GroupDescription": "sim2real redshift-serverless workgroup sg",
            "VpcId": {"Ref": "Vpc"}}},
        "Namespace": {"Type": "AWS::RedshiftServerless::Namespace", "Properties": {
            "NamespaceName": namespace_name, "AdminUsername": _ADMIN_USERNAME,
            "AdminUserPassword": {"Ref": "AdminPassword"}, "DbName": _DB_NAME}},
    }
    outputs = {
        "VpcId": {"Value": {"Ref": "Vpc"}},
        "SgId": {"Value": {"Ref": "Sg"}},
        **{f"Subnet{x}": {"Value": {"Ref": f"Subnet{x}"}} for x in "ABC"},
        "NamespaceRef": {"Value": {"Ref": "Namespace"}},
        "NamespaceId": {"Value": {"Fn::GetAtt": ["Namespace", "Namespace.NamespaceId"]}},
        "NamespaceArn": {"Value": {"Fn::GetAtt": ["Namespace", "Namespace.NamespaceArn"]}},
    }
    if with_children:
        resources["Workgroup"] = {"Type": "AWS::RedshiftServerless::Workgroup", "Properties": {
            "WorkgroupName": workgroup_name, "NamespaceName": {"Ref": "Namespace"},
            "BaseCapacity": _BASE_CAPACITY,
            "SubnetIds": [{"Ref": f"Subnet{x}"} for x in "ABC"],
            "SecurityGroupIds": [{"Ref": "Sg"}], "PubliclyAccessible": False}}
        resources["Snapshot"] = {"Type": "AWS::RedshiftServerless::Snapshot",
                                 "DependsOn": "Workgroup", "Properties": {
            "SnapshotName": snapshot_name, "NamespaceName": {"Ref": "Namespace"},
            "RetentionPeriod": _RETENTION_DAYS}}
        outputs.update({
            "WorkgroupRef": {"Value": {"Ref": "Workgroup"}},
            "WorkgroupId": {"Value": {"Fn::GetAtt": ["Workgroup", "Workgroup.WorkgroupId"]}},
            "WorkgroupArn": {"Value": {"Fn::GetAtt": ["Workgroup", "Workgroup.WorkgroupArn"]}},
            "SnapshotRef": {"Value": {"Ref": "Snapshot"}},
            "SnapshotArn": {"Value": {"Fn::GetAtt": ["Snapshot", "Snapshot.SnapshotArn"]}},
        })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"AdminPassword": {"Type": "String", "NoEcho": True}},
        "Resources": resources, "Outputs": outputs,
    })


def _masked_error(fn, account: str) -> tuple[str, str]:
    """``(code, message with the account masked)`` of the error ``fn()`` must raise."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], masked(exc.response["Error"]["Message"], account)
    raise AssertionError(f"expected an error but the call succeeded: {result!r}")


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


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation redshift-serverless Namespace, Workgroup and Snapshot read back.

    Every Ref, GetAtt and templated property matches; an update dropping the Workgroup and
    Snapshot removes both while the Namespace stays, and deleting the stack removes it.
    """
    ctx.verify_account_safety()
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    rs = ctx.client("redshift-serverless")
    namespace_name = ctx.unique_name("sim2real-cfn-ns-")
    workgroup_name = ctx.unique_name("sim2real-cfn-wg-")
    snapshot_name = ctx.unique_name("sim2real-cfn-snap-")
    password = f"Sim2{secrets.token_hex(12)}Rl9"
    names = (namespace_name, workgroup_name, snapshot_name)
    params = [{"ParameterKey": "AdminPassword", "ParameterValue": password}]

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-stk-"), _template(*names),
                            Parameters=params)
    status = wait_stack(cfn, stack_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    assert "AdminPassword" not in json.dumps(out), "no Output carries the admin password"
    assert (out["NamespaceRef"], out["WorkgroupRef"], out["SnapshotRef"]) == names, (
        f"Refs {(out['NamespaceRef'], out['WorkgroupRef'], out['SnapshotRef'])!r}"
    )

    # Refs against independent listings, then every templated property and GetAtt.
    listed = [n["namespaceArn"] for n in paginate(rs, "list_namespaces", "namespaces")
              if n["namespaceName"] == namespace_name]
    assert listed == [out["NamespaceArn"]], f"ListNamespaces for {namespace_name!r}: {listed!r}"
    ns = rs.get_namespace(namespaceName=namespace_name)["namespace"]
    got = (ns["adminUsername"], ns["dbName"], ns["namespaceId"], ns["namespaceArn"])
    want = (_ADMIN_USERNAME, _DB_NAME, out["NamespaceId"], out["NamespaceArn"])
    assert got == want, f"namespace reads {got!r}, expected {want!r}"

    listed = [w["workgroupArn"] for w in paginate(rs, "list_workgroups", "workgroups")
              if w["workgroupName"] == workgroup_name]
    assert listed == [out["WorkgroupArn"]], f"ListWorkgroups for {workgroup_name!r}: {listed!r}"
    wg = rs.get_workgroup(workgroupName=workgroup_name)["workgroup"]
    got = (wg["namespaceName"], wg["baseCapacity"], sorted(wg["subnetIds"]), wg["securityGroupIds"],
           wg["publiclyAccessible"], wg["workgroupId"], wg["status"])
    want = (namespace_name, _BASE_CAPACITY, sorted(out[f"Subnet{x}"] for x in "ABC"), [out["SgId"]],
            False, out["WorkgroupId"], "AVAILABLE")
    assert got == want, f"workgroup reads {got!r}, expected {want!r}"
    for attribute, key in (("enableDnsSupport", "EnableDnsSupport"),
                           ("enableDnsHostnames", "EnableDnsHostnames")):
        value = ec2.describe_vpc_attribute(VpcId=out["VpcId"], Attribute=attribute)[key]["Value"]
        assert value is True, f"VPC {attribute} reads {value!r}"

    listed = [s["snapshotArn"] for s in paginate(rs, "list_snapshots", "snapshots",
                                                 namespaceName=namespace_name)
              if s["snapshotName"] == snapshot_name]
    assert listed == [out["SnapshotArn"]], f"ListSnapshots for {snapshot_name!r}: {listed!r}"
    snap = rs.get_snapshot(snapshotName=snapshot_name)["snapshot"]
    got = (snap["namespaceName"], snap["snapshotRetentionPeriod"], snap["status"])
    assert got == (namespace_name, _RETENTION_DAYS, "AVAILABLE"), f"snapshot reads {got!r}"

    # The children's own deletes: an update dropping them while the namespace still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(*names, with_children=False),
                     Parameters=[{"ParameterKey": "AdminPassword", "UsePreviousValue": True}])
    status = wait_stack(cfn, stack_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    expect_error(lambda: rs.get_workgroup(workgroupName=workgroup_name),
                 *("ResourceNotFoundException", f"Serverless workgroup {workgroup_name} not found."))
    got = _masked_error(lambda: rs.get_snapshot(snapshotName=snapshot_name), ctx.account)
    want = ("ResourceNotFoundException",
            f"The snapshot {snapshot_name} was not found. Please Check whether the snapshot "
            f"exists and is owned by or shared with account <account>.")
    assert got == want, f"GetSnapshot after the update: {got!r}, expected {want!r}"
    assert rs.get_namespace(namespaceName=namespace_name)["namespace"]["namespaceArn"] == (
        out["NamespaceArn"]), "the namespace survives the update"

    _await_no_enis(ec2, out["VpcId"])
    delete_stack(cfn, stack_id)
    expect_error(lambda: rs.get_namespace(namespaceName=namespace_name),
                 *("ResourceNotFoundException", f"Serverless namespace {namespace_name} not found."))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
