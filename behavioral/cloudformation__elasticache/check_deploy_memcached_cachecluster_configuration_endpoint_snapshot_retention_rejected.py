"""deploy-memcached-cachecluster-configuration-endpoint-snapshot-retention-rejected."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-memcached-cachecluster-configuration-endpoint-snapshot-retention-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "elasticache"]

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

_VPC_CIDR = "10.213.0.0/16"
_SUBNET_CIDRS = ["10.213.1.0/24", "10.213.2.0/24"]
_NODE_TYPE = "cache.t3.micro"
_CREATE_TIMEOUT_S = 1500.0


def _cluster_resources(cluster_name: str, subnet_group_name: str, extra_props: dict) -> dict:
    """A private VPC, two subnets, an SG, a subnet group and a one-node memcached cluster."""
    az = [{"Fn::Select": [i, {"Fn::GetAZs": ""}]} for i in range(2)]
    props = {
        "ClusterName": cluster_name,
        "Engine": "memcached",
        "CacheNodeType": _NODE_TYPE,
        "NumCacheNodes": 1,
        "CacheSubnetGroupName": {"Ref": "SubnetGroup"},
        "VpcSecurityGroupIds": [{"Ref": "SecurityGroup"}],
    }
    props.update(extra_props)
    return {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
        "SubnetA": {
            "Type": "AWS::EC2::Subnet",
            "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "CidrBlock": _SUBNET_CIDRS[0],
                "AvailabilityZone": az[0],
            },
        },
        "SubnetB": {
            "Type": "AWS::EC2::Subnet",
            "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "CidrBlock": _SUBNET_CIDRS[1],
                "AvailabilityZone": az[1],
            },
        },
        "SecurityGroup": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "GroupDescription": "sim2real throwaway cache security group",
            },
        },
        "SubnetGroup": {
            "Type": "AWS::ElastiCache::SubnetGroup",
            "Properties": {
                "CacheSubnetGroupName": subnet_group_name,
                "Description": "sim2real throwaway subnet group",
                "SubnetIds": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
            },
        },
        "Cluster": {"Type": "AWS::ElastiCache::CacheCluster", "Properties": props},
    }


def _template(cluster_name: str, subnet_group_name: str, extra_props: dict | None = None) -> str:
    resources = _cluster_resources(cluster_name, subnet_group_name, extra_props or {})
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": resources,
            "Outputs": {
                "ClusterId": {"Value": {"Ref": "Cluster"}},
                "ConfigurationEndpointAddress": {
                    "Value": {"Fn::GetAtt": ["Cluster", "ConfigurationEndpoint.Address"]},
                },
            },
        }
    )


_REJECTED = (
    "Engine does not support snapshotting. Snapshot retention limit parameter should not be "
    "specified. (Service: ElastiCache, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation memcached CacheCluster's GetAtt ConfigurationEndpoint.Address is the
    address ElastiCache itself reports for the cluster; the same shape with a snapshot
    retention limit, which memcached does not support, is refused and no cluster is created."""
    cfn = ctx.client("cloudformation")
    ec = ctx.client("elasticache")

    # Positive control: a plain memcached cluster, read back through ElastiCache.
    good_cluster = ctx.unique_name("sim2real-ecmc-")
    good_sng = ctx.unique_name("sim2real-ecmc-")
    good_id = create_stack(
        ctx, cfn, ctx.unique_name("sim2real-ecmc-"), _template(good_cluster, good_sng)
    )
    status = wait_stack(cfn, good_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    cluster = ec.describe_cache_clusters(CacheClusterId=good_cluster, ShowCacheNodeInfo=True)[
        "CacheClusters"
    ][0]
    got_address = cluster["ConfigurationEndpoint"]["Address"]
    assert got_address == out["ConfigurationEndpointAddress"], (
        f"GetAtt ConfigurationEndpoint.Address was {out['ConfigurationEndpointAddress']!r}, "
        f"ElastiCache reports {got_address!r}"
    )
    assert cluster["Engine"] == "memcached", f"expected memcached, got {cluster['Engine']!r}"

    # Negative: the same shape, asking memcached for a snapshot retention limit.
    bad_cluster = ctx.unique_name("sim2real-ecmc-")
    bad_sng = ctx.unique_name("sim2real-ecmc-")
    bad_id = create_stack(
        ctx,
        cfn,
        ctx.unique_name("sim2real-ecmc-"),
        _template(bad_cluster, bad_sng, {"SnapshotRetentionLimit": 5}),
    )
    status = wait_stack(cfn, bad_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Cluster"), ctx.account)
    assert got == _REJECTED, f"Cluster reason {got!r}, expected {_REJECTED!r}"
    expect_error(
        lambda: ec.describe_cache_clusters(CacheClusterId=bad_cluster),
        "CacheClusterNotFound",
        f"CacheCluster not found: {bad_cluster}",
    )

    delete_stack(cfn, good_id)
    expect_error(
        lambda: ec.describe_cache_clusters(CacheClusterId=good_cluster),
        "CacheClusterNotFound",
        f"CacheCluster not found: {good_cluster}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
