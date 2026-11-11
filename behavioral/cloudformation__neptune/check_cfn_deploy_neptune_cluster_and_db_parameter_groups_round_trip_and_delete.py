"""cfn-deploy-neptune-cluster-and-db-parameter-groups-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-neptune-cluster-and-db-parameter-groups-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "neptune"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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

_FAMILY = "neptune1.3"
_CLUSTER_PARAM = "neptune_streams_expiry_days"
_CLUSTER_VALUE = "30"
_INSTANCE_PARAM = "neptune_query_timeout"
_INSTANCE_VALUE = "120000"
_CLUSTER_DESCRIPTION = "sim2real neptune cluster parameter group"
_DB_DESCRIPTION = "sim2real neptune db parameter group"


def _template(cluster_name: str, db_name: str, tag_value: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ClusterParamGroup": {
                "Type": "AWS::Neptune::DBClusterParameterGroup",
                "Properties": {
                    "Name": cluster_name,
                    "Family": _FAMILY,
                    "Description": _CLUSTER_DESCRIPTION,
                    "Parameters": {_CLUSTER_PARAM: _CLUSTER_VALUE},
                    "Tags": t,
                },
            },
            "DbParamGroup": {
                "Type": "AWS::Neptune::DBParameterGroup",
                "Properties": {
                    "Name": db_name,
                    "Family": _FAMILY,
                    "Description": _DB_DESCRIPTION,
                    "Parameters": {_INSTANCE_PARAM: _INSTANCE_VALUE},
                    "Tags": t,
                },
            },
        },
        "Outputs": {
            "ClusterParamGroupName": {"Value": {"Ref": "ClusterParamGroup"}},
            "DbParamGroupName": {"Value": {"Ref": "DbParamGroup"}},
        },
    })


def _find_param(params: list[dict], name: str) -> dict:
    for p in params:
        if p["ParameterName"] == name:
            return p
    raise AssertionError(f"parameter {name!r} not present in {[p['ParameterName'] for p in params]!r}")


def _assert_tagged(nep, arn: str, want: dict) -> None:
    tags_ = nep.list_tags_for_resource(ResourceName=arn)["TagList"]
    found = {t["Key"]: t["Value"] for t in tags_ if not t["Key"].startswith("aws:")}
    assert found == want, f"expected tags {want!r} on the group, Neptune reports {tags_!r}"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Neptune::DBClusterParameterGroup and AWS::Neptune::DBParameterGroup
    read back through Neptune's own Describe calls with the declared family and parameter
    values; deleting the stack removes both, which Neptune then refuses by name.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-neptune-dbclusterparametergroup.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-neptune-dbparametergroup.html
    """
    nep = ctx.client("neptune")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-nep-pg-")
    cluster_name = ctx.unique_name("sim2real-nep-cpg-")
    db_name = ctx.unique_name("sim2real-nep-dpg-")

    stack_id = create_stack(ctx, cfn, stack, _template(cluster_name, db_name, CHECK))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    want_tags = {"sim2real": stack, "sim2real-check": CHECK}
    cluster_ref, db_ref = outputs["ClusterParamGroupName"], outputs["DbParamGroupName"]
    assert cluster_ref == cluster_name, (
        f"expected ClusterParamGroup's Ref to equal its Name {cluster_name!r}, got {cluster_ref!r}"
    )
    assert db_ref == db_name, (
        f"expected DbParamGroup's Ref to equal its Name {db_name!r}, got {db_ref!r}"
    )

    cluster_groups = nep.describe_db_cluster_parameter_groups(
        DBClusterParameterGroupName=cluster_ref
    )["DBClusterParameterGroups"]
    assert len(cluster_groups) == 1, (
        f"DescribeDBClusterParameterGroups({cluster_ref!r}) returned {len(cluster_groups)} groups"
    )
    cg = cluster_groups[0]
    assert cg["DBClusterParameterGroupName"] == cluster_name, (
        f"expected name {cluster_name!r}, Neptune reports {cg['DBClusterParameterGroupName']!r}"
    )
    assert cg["DBParameterGroupFamily"] == _FAMILY, (
        f"expected family {_FAMILY!r}, Neptune reports {cg['DBParameterGroupFamily']!r}"
    )
    assert cg["Description"] == _CLUSTER_DESCRIPTION, (
        f"expected Description {_CLUSTER_DESCRIPTION!r}, Neptune reports {cg['Description']!r}"
    )
    _assert_tagged(nep, cg["DBClusterParameterGroupArn"], want_tags)

    cluster_params = paginate(
        nep, "describe_db_cluster_parameters", "Parameters", DBClusterParameterGroupName=cluster_ref
    )
    cp = _find_param(cluster_params, _CLUSTER_PARAM)
    assert cp["ParameterValue"] == _CLUSTER_VALUE, (
        f"expected {_CLUSTER_PARAM!r} to read back {_CLUSTER_VALUE!r}, Neptune reports "
        f"{cp['ParameterValue']!r}"
    )

    db_groups = nep.describe_db_parameter_groups(DBParameterGroupName=db_ref)["DBParameterGroups"]
    assert len(db_groups) == 1, (
        f"DescribeDBParameterGroups({db_ref!r}) returned {len(db_groups)} groups"
    )
    dg = db_groups[0]
    assert dg["DBParameterGroupName"] == db_name, (
        f"expected name {db_name!r}, Neptune reports {dg['DBParameterGroupName']!r}"
    )
    assert dg["DBParameterGroupFamily"] == _FAMILY, (
        f"expected family {_FAMILY!r}, Neptune reports {dg['DBParameterGroupFamily']!r}"
    )
    assert dg["Description"] == _DB_DESCRIPTION, (
        f"expected Description {_DB_DESCRIPTION!r}, Neptune reports {dg['Description']!r}"
    )
    _assert_tagged(nep, dg["DBParameterGroupArn"], want_tags)

    db_params = paginate(nep, "describe_db_parameters", "Parameters", DBParameterGroupName=db_ref)
    dp = _find_param(db_params, _INSTANCE_PARAM)
    assert dp["ParameterValue"] == _INSTANCE_VALUE, (
        f"expected {_INSTANCE_PARAM!r} to read back {_INSTANCE_VALUE!r}, Neptune reports "
        f"{dp['ParameterValue']!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)
    cluster_gone = ("DBParameterGroupNotFound", f"DBClusterParameterGroup not found: {cluster_ref}")
    expect_error(
        lambda: nep.describe_db_cluster_parameter_groups(DBClusterParameterGroupName=cluster_ref),
        *cluster_gone,
    )
    db_gone = ("DBParameterGroupNotFound", f"DBParameterGroup not found: {db_ref}")
    expect_error(lambda: nep.describe_db_parameter_groups(DBParameterGroupName=db_ref), *db_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
