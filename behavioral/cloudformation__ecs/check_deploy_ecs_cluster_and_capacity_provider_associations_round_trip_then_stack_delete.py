"""deploy-ecs-cluster-and-capacity-provider-associations-round-trip-then-stack-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-ecs-cluster-and-capacity-provider-associations-round-trip-then-stack-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecs"]

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


# ---- Check-specific: the template, then run(). ----

def _template(cluster_name, with_assoc=True):
    resources = {"Cluster": {"Type": "AWS::ECS::Cluster", "Properties": {
        "ClusterName": cluster_name,
        "Tags": [{"Key": "sim2real-cluster", "Value": cluster_name}],
    }}}
    outputs = {
        "ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "Arn"]}},
        "ClusterNameOut": {"Value": {"Ref": "Cluster"}},
    }
    if with_assoc:
        resources["CPAssoc"] = {
            "Type": "AWS::ECS::ClusterCapacityProviderAssociations", "Properties": {
                "Cluster": {"Ref": "Cluster"},
                "CapacityProviders": ["FARGATE", "FARGATE_SPOT"],
                "DefaultCapacityProviderStrategy": [
                    {"CapacityProvider": "FARGATE", "Weight": 1, "Base": 0},
                ],
            }}
        outputs["CPAssocClusterOut"] = {"Value": {"Ref": "CPAssoc"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ECS cluster and its capacity-provider association read back through ECS.

    An update dropping the association empties it on the same ACTIVE cluster, and the stack
    delete leaves the cluster in ECS's documented INACTIVE tombstone.
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")

    stack = ctx.unique_name("sim2real-cfnecs-cl-")
    cluster_name = ctx.unique_name("sim2real-cfnecs-cl-c-")

    stack_id = create_stack(ctx, cfn, stack, _template(cluster_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    assert out["ClusterNameOut"] == cluster_name, (
        f"Ref Cluster {out['ClusterNameOut']!r} != template ClusterName {cluster_name!r}"
    )
    assert out["CPAssocClusterOut"] == cluster_name, (
        f"Ref CPAssoc {out['CPAssocClusterOut']!r} != {cluster_name!r}"
    )
    cluster_arn = out["ClusterArn"]

    # Ref against an independent read (ListClusters, paginated), never a read keyed by the Ref.
    all_arns = paginate(ecs, "list_clusters", "clusterArns", maxResults=100)
    assert cluster_arn in all_arns, f"ListClusters does not list {cluster_arn!r}"

    described = ecs.describe_clusters(
        clusters=[cluster_arn], include=["TAGS"]
    )["clusters"]
    assert len(described) == 1, f"DescribeClusters({cluster_arn!r}) returned {described!r}"
    cluster = described[0]
    # Read-only GetAtt == service value; the echoed Ref == the service's own clusterName too.
    assert cluster["clusterArn"] == cluster_arn, (
        f"DescribeClusters clusterArn {cluster['clusterArn']!r} != GetAtt {cluster_arn!r}"
    )
    assert cluster["clusterName"] == cluster_name, (
        f"DescribeClusters clusterName {cluster['clusterName']!r} != {cluster_name!r}"
    )
    assert cluster["status"] == "ACTIVE", f"freshly-created cluster status {cluster['status']!r}"

    # Every templated property, through the owning service: the capacity-provider association.
    assert sorted(cluster["capacityProviders"]) == ["FARGATE", "FARGATE_SPOT"], (
        f"capacityProviders {cluster['capacityProviders']!r}"
    )
    assert cluster["defaultCapacityProviderStrategy"] == [
        {"capacityProvider": "FARGATE", "weight": 1, "base": 0}
    ], f"defaultCapacityProviderStrategy {cluster['defaultCapacityProviderStrategy']!r}"

    cluster_tags = {t["key"]: t["value"] for t in cluster.get("tags", [])
                    if not t["key"].startswith("aws:")}
    assert cluster_tags == {"sim2real": stack, "sim2real-cluster": cluster_name}, (
        f"cluster tags {cluster_tags!r}"
    )

    # The child alone: an update dropping the association empties it on the same cluster.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(cluster_name, with_assoc=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"association-removing update ended {status!r}"
    kept = ecs.describe_clusters(clusters=[cluster_arn])["clusters"]
    got_kept = [(c["status"], c["capacityProviders"], c["defaultCapacityProviderStrategy"])
                for c in kept]
    assert got_kept == [("ACTIVE", [], [])], f"after dropping the association: {got_kept!r}"

    delete_stack(cfn, stack_id)

    # Gone, through ECS's own documented tombstone: DescribeClusters still answers (never a
    # ClusterNotFoundException for a cluster that existed) but reports status INACTIVE, and
    # ListClusters no longer lists it.
    after = ecs.describe_clusters(clusters=[cluster_arn])["clusters"]
    assert len(after) == 1, f"DescribeClusters({cluster_arn!r}) after delete returned {after!r}"
    assert after[0]["status"] == "INACTIVE", (
        f"deleted cluster status {after[0]['status']!r}, expected the documented 'INACTIVE'"
    )
    all_arns_after = paginate(ecs, "list_clusters", "clusterArns", maxResults=100)
    assert cluster_arn not in all_arns_after, f"ListClusters still lists deleted {cluster_arn!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
