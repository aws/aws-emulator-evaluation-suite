"""deploy-docdb-dbcluster-invalid-engine-version-rejected-and-rolled-back."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-docdb-dbcluster-invalid-engine-version-rejected-and-rolled-back"
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
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
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
    """The masked message of a registry-handler failure reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names)


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

_SUBNET_DESCRIPTION = "sim2real docdb cluster engine version check"
_INVALID_ENGINE_VERSION = "99.9.9"
_REJECTED = (
    "Cannot find version 99.9.9 for docdb "
    "(Service: Rds, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)"
)


def _template(tag_value: str, cluster_id: str, engine_version: str, subnet_ids: list[str]) -> str:
    t = [{"Key": "sim2real-res", "Value": tag_value}]
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "SubnetGroup": {
                    "Type": "AWS::DocDB::DBSubnetGroup",
                    "Properties": {
                        "DBSubnetGroupDescription": _SUBNET_DESCRIPTION,
                        "SubnetIds": subnet_ids,
                        "Tags": t,
                    },
                },
                "Cluster": {
                    "Type": "AWS::DocDB::DBCluster",
                    "DeletionPolicy": "Delete",
                    "UpdateReplacePolicy": "Delete",
                    "Properties": {
                        "DBClusterIdentifier": cluster_id,
                        "EngineVersion": engine_version,
                        "MasterUsername": "simadmin",
                        "MasterUserPassword": "Sim2RealCheck9987",
                        "DBSubnetGroupName": {"Ref": "SubnetGroup"},
                        "Tags": t,
                    },
                },
            },
            "Outputs": {
                "ClusterRef": {"Value": {"Ref": "Cluster"}},
            },
        }
    )


def _latest_engine_version(docdb) -> str:
    """The highest ``docdb`` EngineVersion this region currently offers."""
    versions = [
        v["EngineVersion"]
        for v in paginate(docdb, "describe_db_engine_versions", "DBEngineVersions", Engine="docdb")
    ]
    assert versions, "DescribeDBEngineVersions(Engine='docdb') returned nothing"
    return sorted(versions, key=lambda v: tuple(int(p) for p in v.split(".")))[-1]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::DocDB::DBCluster naming an EngineVersion DocDB does not offer fails, rolls back and
    leaves no cluster; the same template at the latest offered version deploys, reads back, and
    leaves no cluster and no cluster snapshot once its stack is deleted."""
    docdb = ctx.client("docdb")
    cfn = ctx.client("cloudformation")
    net = ctx.network()
    assert len(net.subnet_ids) >= 2, f"need >=2 subnets for a subnet group, got {net.subnet_ids!r}"
    subnet_ids = list(net.subnet_ids)
    bad_cluster_id = ctx.unique_name("sim2real-docdbev-cl-")
    bad_tag = ctx.unique_name("sim2real-docdbev-res-")
    bad_id = create_stack(
        ctx,
        cfn,
        ctx.unique_name("sim2real-docdbev-stack-"),
        _template(bad_tag, bad_cluster_id, _INVALID_ENGINE_VERSION, subnet_ids),
    )
    status = wait_stack(cfn, bad_id, timeout_s=300.0, ctx=ctx)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "Cluster")
    message = handler_reason(reason, ctx.account, bad_cluster_id)
    assert message == _REJECTED, f"handler reason {message!r}, expected {_REJECTED!r}"

    clusters_gone = ("DBClusterNotFoundFault", f"DBCluster {bad_cluster_id} not found.")
    expect_error(
        lambda: docdb.describe_db_clusters(DBClusterIdentifier=bad_cluster_id), *clusters_gone
    )
    delete_stack(cfn, bad_id)

    # Positive control: the same template naming the latest version docdb actually offers.
    good_cluster_id = ctx.unique_name("sim2real-docdbev-cl-")
    good_tag = ctx.unique_name("sim2real-docdbev-res-")
    engine_version = _latest_engine_version(docdb)
    good_id = create_stack(
        ctx,
        cfn,
        ctx.unique_name("sim2real-docdbev-stack-"),
        _template(good_tag, good_cluster_id, engine_version, subnet_ids),
    )
    status = wait_stack(cfn, good_id, timeout_s=900.0, ctx=ctx)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    assert out["ClusterRef"] == good_cluster_id, f"control Ref {out['ClusterRef']!r}"
    clusters = [
        c
        for c in paginate(
            docdb, "describe_db_clusters", "DBClusters", DBClusterIdentifier=good_cluster_id
        )
        if c["DBClusterIdentifier"] == good_cluster_id
    ]
    assert len(clusters) == 1, f"DescribeDBClusters({good_cluster_id!r}): {clusters!r}"
    assert clusters[0]["EngineVersion"] == engine_version, (
        f"control cluster EngineVersion {clusters[0]['EngineVersion']!r}, expected "
        f"{engine_version!r}"
    )

    delete_stack(cfn, good_id)
    good_gone = ("DBClusterNotFoundFault", f"DBCluster {good_cluster_id} not found.")
    expect_error(
        lambda: docdb.describe_db_clusters(DBClusterIdentifier=good_cluster_id), *good_gone
    )
    snapshots = paginate(
        docdb,
        "describe_db_cluster_snapshots",
        "DBClusterSnapshots",
        DBClusterIdentifier=good_cluster_id,
    )
    assert snapshots == [], f"the deleted control cluster left snapshots: {snapshots!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
