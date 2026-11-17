"""cfn-redshift-cluster-nonexistent-clusterparametergroupname-rejected."""

from __future__ import annotations

import json
import re
import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-redshift-cluster-nonexistent-clusterparametergroupname-rejected"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page."""
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


def wait_stack(ctx, cf, stack_id, terminal=_TERMINAL, timeout_s=900.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it."""
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


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def delete_stack(ctx, cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice."""
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
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns."""
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
    """CreateStack tagged sim2real=<name>; cleanup registered before the call."""
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(ctx, cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count and account."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    return text.replace(account, "<account>")


def handler_reason(reason, account):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account), m["code"]


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


def _template(cluster_id: str, node_type: str, admin_password: str, pg_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Cluster": {
                    "Type": "AWS::Redshift::Cluster",
                    "Properties": {
                        "ClusterIdentifier": cluster_id,
                        "ClusterType": "single-node",
                        "NodeType": node_type,
                        "DBName": "dev",
                        "MasterUsername": "s2radmin",
                        "MasterUserPassword": admin_password,
                        "ClusterParameterGroupName": pg_name,
                        "PubliclyAccessible": False,
                    },
                },
            },
        }
    )


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Redshift::Cluster naming a ClusterParameterGroupName that does not
    exist is refused with Redshift's exact reason and DescribeClusters reports ClusterNotFound
    for that identifier; the same template naming the default parameter group deploys.
    """
    rs = ctx.client("redshift")
    cfn = ctx.client("cloudformation")
    node_type = _node_type(rs)

    bad_stack = ctx.unique_name("sim2real-cfnrs-badcl-")
    bad_cluster_id = ctx.unique_name("sim2real-cfnrs-badcl-").lower().replace("_", "-")
    bad_pg_name = ctx.unique_name("sim2real-cfnrs-nosuch-pg-").lower().replace("_", "-")
    bad_id = create_stack(
        ctx, cfn, bad_stack, _template(bad_cluster_id, node_type, _generate_password(), bad_pg_name)
    )
    status = wait_stack(ctx, cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Cluster"), ctx.account)
    want = (
        f"ClusterParameterGroup not found: {bad_pg_name} (Service: Redshift, Status Code: 404, "
        "Request ID: <id>) (SDK Attempt Count: <n>)",
        "InvalidRequest",
    )
    assert got == want, f"handler reason {got!r}, expected {want!r}"
    got = _error(lambda: rs.describe_clusters(ClusterIdentifier=bad_cluster_id))
    want = ("ClusterNotFound", f"Cluster {bad_cluster_id} not found.")
    assert got == want, f"DescribeClusters of the rejected cluster: {got!r}, expected {want!r}"
    delete_stack(ctx, cfn, bad_id)

    # Positive control: the same template naming the account's always-present default group.
    good_stack = ctx.unique_name("sim2real-cfnrs-okcl-")
    good_cluster_id = ctx.unique_name("sim2real-cfnrs-okcl-").lower().replace("_", "-")
    good_id = create_stack(
        ctx,
        cfn,
        good_stack,
        _template(good_cluster_id, node_type, _generate_password(), "default.redshift-2.0"),
    )
    status = wait_stack(ctx, cfn, good_id)
    if status != "CREATE_COMPLETE":
        reasons = [
            (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
            for e in stack_events(cfn, good_id)
            if e["ResourceStatus"].endswith("FAILED")
        ]
        raise AssertionError(
            f"control stack: expected CREATE_COMPLETE, got {status!r}: {reasons!r}"
        )
    cluster = rs.describe_clusters(ClusterIdentifier=good_cluster_id)["Clusters"][0]
    cluster_pgs = [g["ParameterGroupName"] for g in cluster["ClusterParameterGroups"]]
    assert cluster_pgs == ["default.redshift-2.0"], (
        f"control cluster's ClusterParameterGroups names {cluster_pgs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
