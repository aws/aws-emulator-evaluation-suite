"""deploy-rds-db-cluster-endpoint-round-trip-and-delete."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-rds-db-cluster-endpoint-round-trip-and-delete"
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


def _template(with_endpoint: bool = True) -> str:
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"},
            "MasterUserPassword": {"Type": "String", "NoEcho": True},
            "ClusterIdentifier": {"Type": "String"},
            "EndpointIdentifier": {"Type": "String"},
        },
        "Resources": {
            "SubnetGroup": {
                "Type": "AWS::RDS::DBSubnetGroup",
                "Properties": {
                    "DBSubnetGroupDescription": "sim2real behavioral deploy check",
                    "SubnetIds": {"Ref": "SubnetIds"},
                },
            },
            "Cluster": {
                "Type": "AWS::RDS::DBCluster",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "Engine": "aurora-mysql",
                    "DBClusterIdentifier": {"Ref": "ClusterIdentifier"},
                    "MasterUsername": "simadmin",
                    "MasterUserPassword": {"Ref": "MasterUserPassword"},
                    "DBSubnetGroupName": {"Ref": "SubnetGroup"},
                    "BackupRetentionPeriod": 1,
                    "StorageEncrypted": True,
                    "Tags": [{"Key": "sim2real-cluster", "Value": {"Ref": "ClusterIdentifier"}}],
                },
            },
        },
        "Outputs": {
            "ClusterRef": {"Value": {"Ref": "Cluster"}},
            "ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "DBClusterArn"]}},
        },
    }
    if with_endpoint:
        template["Resources"]["Endpoint"] = {
            "Type": "AWS::RDS::DBClusterEndpoint",
            "Properties": {
                "DBClusterEndpointIdentifier": {"Ref": "EndpointIdentifier"},
                "DBClusterIdentifier": {"Ref": "Cluster"},
                "CustomEndpointType": "ANY",
                "Tags": [{"Key": "sim2real-endpoint", "Value": {"Ref": "EndpointIdentifier"}}],
            },
        }
        template["Outputs"].update({
            "EndpointArn": {"Value": {"Ref": "Endpoint"}},
            "EndpointAddress": {"Value": {"Fn::GetAtt": ["Endpoint", "Endpoint"]}},
            "EndpointTypeAttr": {"Value": {"Fn::GetAtt": ["Endpoint", "EndpointType"]}},
            "EndpointResourceId": {
                "Value": {"Fn::GetAtt": ["Endpoint", "DBClusterEndpointResourceIdentifier"]}
            },
        })
    return json.dumps(template)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


#: An Aurora cluster with no instance takes minutes to create and to delete.
_CLUSTER_CREATE_S = 1200.0
_CLUSTER_DELETE_S = 900.0


def _endpoints(rds, endpoint_id):
    """DescribeDBClusterEndpoints filters by identifier: a missing endpoint is an empty list."""
    return paginate(rds, "describe_db_cluster_endpoints", "DBClusterEndpoints",
                    DBClusterEndpointIdentifier=endpoint_id)


def _own_tags(rds, arn):
    """A resource's tags without CloudFormation's aws:* system tags."""
    return {t["Key"]: t["Value"]
            for t in rds.list_tags_for_resource(ResourceName=arn)["TagList"]
            if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::RDS::DBClusterEndpoint over an Aurora MySQL cluster reaches
    'available' in RDS with Ref, GetAtts, CustomEndpointType and tags matching; an update dropping
    it removes it while the cluster answers, and the stack delete removes the cluster.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbclusterendpoint.html
    """
    cfn = ctx.client("cloudformation")
    rds = ctx.client("rds")
    net = ctx.network()
    assert len(net.subnet_ids) >= 2, f"need >=2 subnets for a DB subnet group, got {net.subnet_ids!r}"

    cluster_id = ctx.unique_name("sim2real-rdsce-cl-")
    endpoint_id = ctx.unique_name("sim2real-rdsce-ep-")
    stack_name = ctx.unique_name("sim2real-rdsce-stk-")
    params = [
        {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(net.subnet_ids)},
        {"ParameterKey": "MasterUserPassword", "ParameterValue": secrets.token_urlsafe(24)},
        {"ParameterKey": "ClusterIdentifier", "ParameterValue": cluster_id},
        {"ParameterKey": "EndpointIdentifier", "ParameterValue": endpoint_id},
    ]
    stack_id = create_stack(ctx, cfn, stack_name, _template(), Parameters=params)
    status = wait_stack(cfn, stack_id, timeout_s=_CLUSTER_CREATE_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    clusters = paginate(rds, "describe_db_clusters", "DBClusters", DBClusterIdentifier=cluster_id)
    got = [(c["DBClusterIdentifier"], c["DBClusterArn"]) for c in clusters]
    assert got == [(outputs["ClusterRef"], outputs["ClusterArn"])], (
        f"DescribeDBClusters {got!r}, Ref/GetAtt {(outputs['ClusterRef'], outputs['ClusterArn'])!r}"
    )
    cluster_create_time = clusters[0]["ClusterCreateTime"]

    # The endpoint, read independently by its declared identifier.
    endpoints = _endpoints(rds, endpoint_id)
    assert len(endpoints) == 1, f"expected exactly one endpoint named {endpoint_id!r}, got {endpoints!r}"
    ep = endpoints[0]
    expected_arn = f"arn:{partition}:rds:{ctx.region}:{ctx.account}:cluster-endpoint:{endpoint_id}"
    got = {k: ep.get(k) for k in ("DBClusterEndpointArn", "DBClusterIdentifier",
                                  "CustomEndpointType", "Endpoint", "EndpointType",
                                  "DBClusterEndpointResourceIdentifier", "Status")}
    want = {"DBClusterEndpointArn": outputs["EndpointArn"], "DBClusterIdentifier": cluster_id,
            "CustomEndpointType": "ANY", "Endpoint": outputs["EndpointAddress"],
            "EndpointType": outputs["EndpointTypeAttr"],
            "DBClusterEndpointResourceIdentifier": outputs["EndpointResourceId"],
            "Status": "available"}
    assert got == want, f"DescribeDBClusterEndpoints {got!r}, expected {want!r}"
    assert outputs["EndpointArn"] == expected_arn, (
        f"Ref(Endpoint) {outputs['EndpointArn']!r} != the documented ARN {expected_arn!r}"
    )

    # Template tags plus the propagated stack tag, CloudFormation's aws:* tags dropped.
    for arn, key, value in ((clusters[0]["DBClusterArn"], "sim2real-cluster", cluster_id),
                            (ep["DBClusterEndpointArn"], "sim2real-endpoint", endpoint_id)):
        got_tags = _own_tags(rds, arn)
        assert got_tags == {"sim2real": stack_name, key: value}, f"tags of {arn!r}: {got_tags!r}"

    # Child first: an update dropping the endpoint empties its filter while the same cluster
    # (ClusterCreateTime) still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(with_endpoint=False),
                     Parameters=params)
    status = wait_stack(cfn, stack_id, timeout_s=_CLUSTER_CREATE_S)
    assert status == "UPDATE_COMPLETE", f"endpoint-removing update ended {status!r}"
    left = _poll_until(lambda: _endpoints(rds, endpoint_id), lambda e: e == [],
                       timeout_s=300.0, description=f"endpoint {endpoint_id} gone")
    assert left == [], f"endpoint {endpoint_id!r} still listed after the update: {left!r}"
    after = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert after["ClusterCreateTime"] == cluster_create_time, f"cluster after the update {after!r}"

    # The cluster's delete can outlast the helpers' per-stack budget: wait for it explicitly.
    cfn.delete_stack(StackName=stack_id)
    status = wait_stack(cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, _CLUSTER_DELETE_S)
    assert status == "DELETE_COMPLETE", (
        f"stack delete ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    gone = ("DBClusterNotFoundFault", f"DBCluster {cluster_id} not found.")
    expect_error(lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
