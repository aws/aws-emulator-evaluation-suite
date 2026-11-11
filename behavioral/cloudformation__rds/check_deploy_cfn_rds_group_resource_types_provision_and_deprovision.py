"""deploy-cfn-rds-group-resource-types-provision-and-deprovision."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-rds-group-resource-types-provision-and-deprovision"
GROUP = "deploy"
SERVICES = ["cloudformation", "rds"]

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


def _good_template(names: dict[str, str]) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ParamGroup": {
                "Type": "AWS::RDS::DBParameterGroup",
                "Properties": {
                    "DBParameterGroupName": names["param_group"],
                    "Family": "mysql8.0",
                    "Description": "sim2real mysql8.0 parameter group",
                    "Parameters": {"autocommit": "0"},
                },
            },
            "ClusterParamGroup": {
                "Type": "AWS::RDS::DBClusterParameterGroup",
                "Properties": {
                    "DBClusterParameterGroupName": names["cluster_param_group"],
                    "Family": "aurora-mysql8.0",
                    "Description": "sim2real aurora-mysql8.0 cluster parameter group",
                    "Parameters": {"autocommit": "1"},
                },
            },
            "OptionGroup": {
                "Type": "AWS::RDS::OptionGroup",
                "Properties": {
                    "OptionGroupName": names["option_group"],
                    "EngineName": "mysql",
                    "MajorEngineVersion": "8.0",
                    "OptionGroupDescription": "sim2real mysql8.0 option group",
                },
            },
            "GlobalCluster": {
                "Type": "AWS::RDS::GlobalCluster",
                "Properties": {
                    "GlobalClusterIdentifier": names["global_cluster"],
                    "Engine": "aurora-mysql",
                    "DeletionProtection": False,
                },
            },
        },
        "Outputs": {
            "ParamGroupNameOut": {"Value": {"Ref": "ParamGroup"}},
            "ParamGroupArnOut": {"Value": {"Fn::GetAtt": ["ParamGroup", "DBParameterGroupArn"]}},
            "ClusterParamGroupNameOut": {"Value": {"Ref": "ClusterParamGroup"}},
            "OptionGroupNameOut": {"Value": {"Ref": "OptionGroup"}},
            "GlobalClusterIdOut": {"Value": {"Ref": "GlobalCluster"}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Four RDS group resource types deployed by CloudFormation read back through RDS with the
    stack's Ref/GetAtt values and are gone through RDS's own not-found faults after stack delete.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-globalcluster.html
    """
    cf = ctx.client("cloudformation")
    rds = ctx.client("rds")

    names = {
        "param_group": ctx.unique_name("sim2real-cfnrds-pg-"),
        "cluster_param_group": ctx.unique_name("sim2real-cfnrds-cpg-"),
        "option_group": ctx.unique_name("sim2real-cfnrds-og-"),
        "global_cluster": ctx.unique_name("sim2real-cfnrds-gc-"),
    }
    stack_name = ctx.unique_name("sim2real-cfnrds-stk-")

    stack_id = create_stack(ctx, cf, stack_name, _good_template(names))
    status = wait_stack(cf, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack settled at {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cf, stack_id))!r}"
    )
    outputs = stack_outputs(cf, stack_id)

    pgs = rds.describe_db_parameter_groups(DBParameterGroupName=names["param_group"])[
        "DBParameterGroups"
    ]
    assert len(pgs) == 1, f"DescribeDBParameterGroups by name returned {len(pgs)} groups"
    pg = pgs[0]
    assert pg["DBParameterGroupFamily"] == "mysql8.0", f"family was {pg['DBParameterGroupFamily']!r}"
    assert pg["Description"] == "sim2real mysql8.0 parameter group", f"description was {pg['Description']!r}"
    assert pg["DBParameterGroupArn"] == outputs["ParamGroupArnOut"], (
        f"RDS Arn {pg['DBParameterGroupArn']!r} != stack GetAtt output {outputs['ParamGroupArnOut']!r}"
    )
    assert outputs["ParamGroupNameOut"] == names["param_group"], outputs["ParamGroupNameOut"]
    pg_params = {
        p["ParameterName"]: p["ParameterValue"]
        for p in paginate(rds, "describe_db_parameters", "Parameters",
                          DBParameterGroupName=names["param_group"], Source="user")
    }
    assert pg_params == {"autocommit": "0"}, f"user parameters were {pg_params!r}"

    cpgs = rds.describe_db_cluster_parameter_groups(
        DBClusterParameterGroupName=names["cluster_param_group"]
    )["DBClusterParameterGroups"]
    assert len(cpgs) == 1, f"DescribeDBClusterParameterGroups by name returned {len(cpgs)} groups"
    cpg = cpgs[0]
    assert cpg["DBClusterParameterGroupName"] == outputs["ClusterParamGroupNameOut"], (
        f"RDS name {cpg['DBClusterParameterGroupName']!r} differs from the stack Ref"
    )
    assert cpg["DBParameterGroupFamily"] == "aurora-mysql8.0", (
        f"cluster family was {cpg['DBParameterGroupFamily']!r}"
    )
    assert cpg["Description"] == "sim2real aurora-mysql8.0 cluster parameter group", (
        f"cluster description was {cpg['Description']!r}"
    )
    assert outputs["ClusterParamGroupNameOut"] == names["cluster_param_group"], (
        outputs["ClusterParamGroupNameOut"]
    )
    cpg_params = {
        p["ParameterName"]: p["ParameterValue"]
        for p in paginate(rds, "describe_db_cluster_parameters", "Parameters",
                          DBClusterParameterGroupName=names["cluster_param_group"], Source="user")
    }
    assert cpg_params == {"autocommit": "1"}, f"cluster user parameters were {cpg_params!r}"
    cpg_tags = {t["Key"]: t["Value"] for t in rds.list_tags_for_resource(
        ResourceName=cpg["DBClusterParameterGroupArn"])["TagList"]
        if not t["Key"].startswith("aws:")}
    assert cpg_tags == {"sim2real": stack_name}, f"cluster parameter group tags {cpg_tags!r}"

    ogs = rds.describe_option_groups(OptionGroupName=names["option_group"])["OptionGroupsList"]
    assert len(ogs) == 1, f"DescribeOptionGroups by name returned {len(ogs)} groups"
    og = ogs[0]
    assert og["OptionGroupName"] == outputs["OptionGroupNameOut"], (
        f"RDS name {og['OptionGroupName']!r} differs from the stack Ref"
    )
    assert og["EngineName"] == "mysql", f"option group engine was {og['EngineName']!r}"
    assert og["MajorEngineVersion"] == "8.0", f"option group major version was {og['MajorEngineVersion']!r}"
    assert og["OptionGroupDescription"] == "sim2real mysql8.0 option group", (
        f"option group description was {og['OptionGroupDescription']!r}"
    )
    assert outputs["OptionGroupNameOut"] == names["option_group"], outputs["OptionGroupNameOut"]

    gcs = rds.describe_global_clusters(GlobalClusterIdentifier=names["global_cluster"])[
        "GlobalClusters"
    ]
    assert len(gcs) == 1, f"DescribeGlobalClusters by identifier returned {len(gcs)} clusters"
    gc = gcs[0]
    assert gc["GlobalClusterIdentifier"] == outputs["GlobalClusterIdOut"], (
        f"RDS identifier {gc['GlobalClusterIdentifier']!r} differs from the stack Ref"
    )
    assert gc["DeletionProtection"] is False, (
        f"global cluster DeletionProtection was {gc['DeletionProtection']!r}, expected False"
    )
    assert gc["Engine"] == "aurora-mysql", f"global cluster engine was {gc['Engine']!r}"
    assert gc["GlobalClusterMembers"] == [], f"a fresh global cluster must have no members: {gc['GlobalClusterMembers']!r}"
    assert outputs["GlobalClusterIdOut"] == names["global_cluster"], outputs["GlobalClusterIdOut"]
    endpoint_label = gc["Endpoint"].split(".", 1)[0]
    assert endpoint_label == names["global_cluster"], (
        f"RDS minted global cluster endpoint {gc['Endpoint']!r} whose leading label "
        f"{endpoint_label!r} does not match the identifier {names['global_cluster']!r}"
    )

    delete_stack(cf, stack_id)

    pg_not_found = ("DBParameterGroupNotFound", f"DBParameterGroup not found: {names['param_group']}")
    expect_error(lambda: rds.describe_db_parameter_groups(DBParameterGroupName=names["param_group"]),
                 *pg_not_found)

    cpg_not_found = ("DBParameterGroupNotFound",
                     f"DBClusterParameterGroup not found: {names['cluster_param_group']}")
    expect_error(lambda: rds.describe_db_cluster_parameter_groups(
        DBClusterParameterGroupName=names["cluster_param_group"]), *cpg_not_found)

    og_not_found = ("OptionGroupNotFoundFault",
                    f"Specified OptionGroupName: {names['option_group']} not found.")
    expect_error(lambda: rds.describe_option_groups(OptionGroupName=names["option_group"]),
                 *og_not_found)

    gc_not_found = ("GlobalClusterNotFoundFault",
                    f"Global cluster '{names['global_cluster']}' not found")
    expect_error(lambda: rds.describe_global_clusters(GlobalClusterIdentifier=names["global_cluster"]),
                 *gc_not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
