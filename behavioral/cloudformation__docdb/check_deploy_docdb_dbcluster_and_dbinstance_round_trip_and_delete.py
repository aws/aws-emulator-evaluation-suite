"""deploy-docdb-dbcluster-and-dbinstance-round-trip-and-delete."""

from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-docdb-dbcluster-and-dbinstance-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "docdb"]

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
_DELETE_BUDGET_S = 900.0  # per stack; a cluster+instance delete can run long


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0, ctx=None):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone". With ``ctx`` the
    deadline is capped by the run budget, and a wait the budget ended is not graded.
    """
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(
                    f"stack {stack_id} reaching a terminal status: the run budget ended first; "
                    f"not graded"
                )
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id, timeout_s=_DELETE_BUDGET_S):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + timeout_s
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
        events = stack_events(cf, stack_id)
        starts = [
            i
            for i, e in enumerate(events)
            if e.get("PhysicalResourceId") == stack_id
            and e["ResourceStatus"] == "DELETE_IN_PROGRESS"
        ]
        failed = [
            (e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in events[starts[-1] if starts else 0 :]
            if e["ResourceStatus"] == "DELETE_FAILED"
        ]
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
                "ValidationError",
                f"Stack with id {name} does not exist",
            ):
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
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
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

_ENGINE = "docdb"
_INSTANCE_CLASS = "db.t3.medium"  # the cheapest orderable class for docdb
_ADMIN_USERNAME = "simadmin"
_SUBNET_DESCRIPTION = "sim2real docdb cluster and instance deploy check"

#: A DocDB cluster plus one instance takes many minutes to reach 'available', and to tear down.
_CREATE_BUDGET_S = 1800.0
_DELETE_BUDGET_S_LOCAL = 900.0


def _template() -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"},
                "MasterUserPassword": {"Type": "String", "NoEcho": True},
                "ClusterIdentifier": {"Type": "String"},
                "InstanceIdentifier": {"Type": "String"},
            },
            "Resources": {
                "SubnetGroup": {
                    "Type": "AWS::DocDB::DBSubnetGroup",
                    "Properties": {
                        "DBSubnetGroupDescription": _SUBNET_DESCRIPTION,
                        "SubnetIds": {"Ref": "SubnetIds"},
                    },
                },
                "Cluster": {
                    "Type": "AWS::DocDB::DBCluster",
                    "DeletionPolicy": "Delete",
                    "UpdateReplacePolicy": "Delete",
                    "Properties": {
                        "DBClusterIdentifier": {"Ref": "ClusterIdentifier"},
                        "MasterUsername": _ADMIN_USERNAME,
                        "MasterUserPassword": {"Ref": "MasterUserPassword"},
                        "DBSubnetGroupName": {"Ref": "SubnetGroup"},
                        "StorageEncrypted": True,
                        "DeletionProtection": False,
                        "Tags": [
                            {"Key": "sim2real-cluster", "Value": {"Ref": "ClusterIdentifier"}}
                        ],
                    },
                },
                "Instance": {
                    "Type": "AWS::DocDB::DBInstance",
                    "DeletionPolicy": "Delete",
                    "UpdateReplacePolicy": "Delete",
                    "Properties": {
                        "DBInstanceIdentifier": {"Ref": "InstanceIdentifier"},
                        "DBInstanceClass": _INSTANCE_CLASS,
                        "DBClusterIdentifier": {"Ref": "Cluster"},
                        "Tags": [
                            {"Key": "sim2real-instance", "Value": {"Ref": "InstanceIdentifier"}}
                        ],
                    },
                },
            },
            "Outputs": {
                "ClusterRef": {"Value": {"Ref": "Cluster"}},
                "InstanceRef": {"Value": {"Ref": "Instance"}},
            },
        }
    )


def _own_tags(docdb, arn):
    """A resource's tags without CloudFormation's aws:* system tags."""
    return {
        t["Key"]: t["Value"]
        for t in docdb.list_tags_for_resource(ResourceName=arn)["TagList"]
        if not t["Key"].startswith("aws:")
    }


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A stack's AWS::DocDB::DBCluster and AWS::DocDB::DBInstance read back through DocDB with the
    template's instance class, engine, admin user, encryption and deletion protection; deleting
    the stack removes both, which DocDB then refuses by identifier, and leaves no cluster snapshot.
    """
    docdb = ctx.client("docdb")
    cfn = ctx.client("cloudformation")
    net = ctx.network()
    assert len(net.subnet_ids) >= 2, (
        f"need >=2 subnets for a DB subnet group, got {net.subnet_ids!r}"
    )

    cluster_id = ctx.unique_name("sim2real-docdbci-cl-")
    instance_id = ctx.unique_name("sim2real-docdbci-in-")
    stack_name = ctx.unique_name("sim2real-docdbci-stk-")
    params = [
        {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(net.subnet_ids)},
        {"ParameterKey": "MasterUserPassword", "ParameterValue": secrets.token_urlsafe(24)},
        {"ParameterKey": "ClusterIdentifier", "ParameterValue": cluster_id},
        {"ParameterKey": "InstanceIdentifier", "ParameterValue": instance_id},
    ]
    stack_id = create_stack(ctx, cfn, stack_name, _template(), Parameters=params)
    status = wait_stack(cfn, stack_id, timeout_s=_CREATE_BUDGET_S, ctx=ctx)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    assert outputs["ClusterRef"] == cluster_id, (
        f"Ref(Cluster) {outputs['ClusterRef']!r} != the template's DBClusterIdentifier {cluster_id!r}"
    )
    assert outputs["InstanceRef"] == instance_id, (
        f"Ref(Instance) {outputs['InstanceRef']!r} != the template's DBInstanceIdentifier "
        f"{instance_id!r}"
    )

    # Ref against an independent read: the instance's own identifier, every page.
    instances = [
        i
        for i in paginate(
            docdb, "describe_db_instances", "DBInstances", DBInstanceIdentifier=instance_id
        )
        if i["DBInstanceIdentifier"] == instance_id
    ]
    assert len(instances) == 1, f"DescribeDBInstances named {instance_id!r}: {instances!r}"
    instance = instances[0]
    got = {
        k: instance[k]
        for k in ("DBInstanceClass", "DBClusterIdentifier", "Engine", "DBInstanceStatus")
    }
    want = {
        "DBInstanceClass": _INSTANCE_CLASS,
        "DBClusterIdentifier": cluster_id,
        "Engine": _ENGINE,
        "DBInstanceStatus": "available",
    }
    assert got == want, f"DescribeDBInstances reports {got!r}, expected {want!r}"

    instance_tags = _own_tags(docdb, instance["DBInstanceArn"])
    assert instance_tags == {"sim2real": stack_name, "sim2real-instance": instance_id}, (
        f"instance tags {instance_tags!r}"
    )

    clusters = [
        c
        for c in paginate(
            docdb, "describe_db_clusters", "DBClusters", DBClusterIdentifier=cluster_id
        )
        if c["DBClusterIdentifier"] == cluster_id
    ]
    assert len(clusters) == 1, f"DescribeDBClusters named {cluster_id!r}: {clusters!r}"
    cluster = clusters[0]
    got = {
        k: cluster[k]
        for k in ("MasterUsername", "StorageEncrypted", "DeletionProtection", "Engine")
    }
    want = {
        "MasterUsername": _ADMIN_USERNAME,
        "StorageEncrypted": True,
        "DeletionProtection": False,
        "Engine": _ENGINE,
    }
    assert got == want, f"DescribeDBClusters reports {got!r}, expected {want!r}"
    cluster_tags = _own_tags(docdb, clusters[0]["DBClusterArn"])
    assert cluster_tags == {"sim2real": stack_name, "sim2real-cluster": cluster_id}, (
        f"cluster tags {cluster_tags!r}"
    )

    delete_stack(cfn, stack_id, timeout_s=_DELETE_BUDGET_S_LOCAL)
    instance_gone = ("DBInstanceNotFound", f"DBInstance {instance_id} not found.")
    expect_error(
        lambda: docdb.describe_db_instances(DBInstanceIdentifier=instance_id), *instance_gone
    )
    cluster_gone = ("DBClusterNotFoundFault", f"DBCluster {cluster_id} not found.")
    expect_error(lambda: docdb.describe_db_clusters(DBClusterIdentifier=cluster_id), *cluster_gone)
    snapshots = paginate(
        docdb, "describe_db_cluster_snapshots", "DBClusterSnapshots", DBClusterIdentifier=cluster_id
    )
    assert snapshots == [], f"the deleted cluster left snapshots: {snapshots!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
