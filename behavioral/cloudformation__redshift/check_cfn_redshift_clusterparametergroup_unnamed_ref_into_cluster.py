"""cfn-redshift-clusterparametergroup-unnamed-ref-into-cluster."""

from __future__ import annotations

import json
import re
import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-redshift-clusterparametergroup-unnamed-ref-into-cluster"
GROUP = "deploy"
SERVICES = ["cloudformation", "redshift"]

# ---- CloudFormation helpers ----

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
_DELETE_BUDGET_S = 900.0
_NODE_TYPES = ("ra3.large", "ra3.xlplus", "dc2.large")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def wait_stack(ctx, cf, stack_id, terminal=_TERMINAL, timeout_s=900.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"stack {stack_id} still {status!r}: the run budget ended first; not graded"
                )
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(ctx, cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(ctx, cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        ctx, cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic()
    )
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        failed = [
            (e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in events
            if e["ResourceStatus"] == "DELETE_FAILED"
        ]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(ctx, cf, name, stack_id=None):
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
                "ValidationError",
                f"Stack with id {name} does not exist",
            ):
                return
            raise
    delete_stack(ctx, cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    The cleanup is registered before the call: a stack AWS accepted is deleted even if the call
    raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(ctx, cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page."""
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _generate_password() -> str:
    alphabet = string.ascii_letters + string.digits
    body = "".join(secrets.choice(alphabet) for _ in range(20))
    return "Aa1" + body


def _node_type(rs) -> str:
    offered, marker = set(), None
    while True:
        resp = rs.describe_orderable_cluster_options(**({"Marker": marker} if marker else {}))
        offered |= {
            o["NodeType"]
            for o in resp["OrderableClusterOptions"]
            if o.get("ClusterType") == "single-node"
        }
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((t for t in _NODE_TYPES if t in offered), None)
    assert chosen, (
        f"none of {_NODE_TYPES!r} is orderable single-node here; offered {sorted(offered)!r}"
    )
    return chosen


# ---- Check-specific: the template, then run(). ----


def _template(cluster_id: str, node_type: str, admin_password: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ParamGroup": {
                    "Type": "AWS::Redshift::ClusterParameterGroup",
                    "Properties": {
                        "Description": "sim2real behavioral cluster parameter group",
                        "ParameterGroupFamily": "redshift-1.0",
                        "Parameters": [{"ParameterName": "require_ssl", "ParameterValue": "true"}],
                    },
                },
                "Cluster": {
                    "Type": "AWS::Redshift::Cluster",
                    "Properties": {
                        "ClusterIdentifier": cluster_id,
                        "ClusterType": "single-node",
                        "NodeType": node_type,
                        "DBName": "dev",
                        "MasterUsername": "s2radmin",
                        "MasterUserPassword": admin_password,
                        "ClusterParameterGroupName": {"Ref": "ParamGroup"},
                        "PubliclyAccessible": False,
                    },
                },
            },
            "Outputs": {
                "ParamGroupRef": {"Value": {"Ref": "ParamGroup"}},
            },
        }
    )


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An unnamed AWS::Redshift::ClusterParameterGroup consumed by a single-node Cluster's
    ClusterParameterGroupName {Ref} reaches CREATE_COMPLETE; Ref is the generated
    "<stack>-paramgroup-<suffix>" name, holding require_ssl=true, that the cluster reports.
    """
    rs = ctx.client("redshift")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cfnrs-pgref-")
    cluster_id = ctx.unique_name("sim2real-cfnrs-cl-").lower().replace("_", "-")
    node_type = _node_type(rs)
    admin_password = _generate_password()

    stack_id = create_stack(ctx, cfn, stack, _template(cluster_id, node_type, admin_password))
    status = wait_stack(ctx, cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"
    outputs = stack_outputs(cfn, stack_id)
    pg_name = outputs["ParamGroupRef"]
    # CloudFormation names an unnamed group "<stack name>-<logical id>-<12 alphanumerics>",
    # lower-cased as Redshift stores parameter group names.
    assert re.fullmatch(re.escape(f"{stack}-paramgroup-") + r"[a-z0-9]{12}", pg_name), (
        f"expected the generated name {stack}-paramgroup-<12 alphanumerics>, got {pg_name!r}"
    )

    pgs = paginate(
        rs, "describe_cluster_parameter_groups", "ParameterGroups", ParameterGroupName=pg_name
    )
    got = [(g["ParameterGroupName"], g["ParameterGroupFamily"]) for g in pgs]
    want = [(pg_name, "redshift-1.0")]
    assert got == want, f"parameter groups {got!r}, expected {want!r}"
    user_params = paginate(
        rs, "describe_cluster_parameters", "Parameters", ParameterGroupName=pg_name, Source="user"
    )
    got = [(p["ParameterName"], p["ParameterValue"]) for p in user_params]
    assert got == [("require_ssl", "true")], f"user parameters {got!r}, expected require_ssl=true"

    cluster = rs.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    cluster_pgs = [g["ParameterGroupName"] for g in cluster["ClusterParameterGroups"]]
    assert cluster_pgs == [pg_name], (
        f"cluster's ClusterParameterGroups names {cluster_pgs!r}, expected the Ref value [{pg_name!r}]"
    )

    delete_stack(ctx, cfn, stack_id)
    _PG_GONE = ("ClusterParameterGroupNotFound", f"ClusterParameterGroup {pg_name} not found.")
    expect_error(
        lambda: rs.describe_cluster_parameter_groups(ParameterGroupName=pg_name), *_PG_GONE
    )
    _CLUSTER_GONE = ("ClusterNotFound", f"Cluster {cluster_id} not found.")
    expect_error(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id), *_CLUSTER_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
