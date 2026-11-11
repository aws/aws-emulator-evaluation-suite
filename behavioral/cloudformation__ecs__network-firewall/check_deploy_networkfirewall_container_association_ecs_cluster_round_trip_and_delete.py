"""deploy-networkfirewall-container-association-ecs-cluster-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-networkfirewall-container-association-ecs-cluster-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecs", "network-firewall"]

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

#: A container association create or delete usually settles in seconds but has outlasted 540 s.
#: The create and the association-dropping update share this one deadline; with the in-body
#: delete_stack (600 s) the body stays at 1740 s, inside the suite's 1800 s.
_ASSOC_WAIT_S = 1140.0

def _template(cluster_name, assoc_name, cluster_arn=None, with_assoc=True):
    """``cluster_arn`` overrides the association's ClusterArn (default: the stack's cluster)."""
    resources = {"Cluster": {"Type": "AWS::ECS::Cluster", "Properties": {
        "ClusterName": cluster_name, "Tags": [{"Key": "sim2real-ca", "Value": cluster_name}]}}}
    outputs = {"ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "Arn"]}}}
    if with_assoc:
        resources["Assoc"] = {"Type": "AWS::NetworkFirewall::ContainerAssociation", "Properties": {
            "ContainerAssociationName": assoc_name,
            "Type": "ECS",
            "ContainerMonitoringConfigurations": [
                {"ClusterArn": cluster_arn or {"Fn::GetAtt": ["Cluster", "Arn"]}}],
            "Tags": [{"Key": "sim2real-ca", "Value": assoc_name}],
        }}
        outputs["AssocArn"] = {"Value": {"Ref": "Assoc"}}
        outputs["AssocStatus"] = {"Value": {"Fn::GetAtt": ["Assoc", "Status"]}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _own_tags(tag_list, key="Key", value="Value"):
    return {t[key]: t[value] for t in tag_list or [] if not t[key].startswith("aws:")}


def _listed(nfw, name):
    return [a["Arn"] for a in paginate(nfw, "list_container_associations",
                                       "ContainerAssociations") if a["Name"] == name]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Network Firewall container association for an ECS cluster reads back ACTIVE.

    An update dropping the association removes it while the cluster stays ACTIVE, and deleting
    the stack leaves the cluster INACTIVE.
    """
    cf = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    nfw = ctx.client("network-firewall")
    stack = ctx.unique_name("sim2real-nfwrca-")
    cluster_name = ctx.unique_name("sim2real-nfwrcacluster-")
    assoc_name = ctx.unique_name("sim2real-nfwrcaassoc-")

    stack_id = create_stack(ctx, cf, stack, _template(cluster_name, assoc_name))
    deadline = time.monotonic() + _ASSOC_WAIT_S
    status = wait_stack(cf, stack_id, timeout_s=deadline - time.monotonic())
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    # Ref against an independent ListContainerAssociations by the declared name.
    assert _listed(nfw, assoc_name) == [out["AssocArn"]], (
        f"ListContainerAssociations {_listed(nfw, assoc_name)!r}, Ref {out['AssocArn']!r}"
    )
    got = nfw.describe_container_association(ContainerAssociationName=assoc_name)
    have = (got["ContainerAssociationName"], got["ContainerAssociationArn"], got["Type"],
            [c["ClusterArn"] for c in got["ContainerMonitoringConfigurations"]],
            got["Status"], out["AssocStatus"], _own_tags(got.get("Tags")))
    want = (assoc_name, out["AssocArn"], "ECS", [out["ClusterArn"]], "ACTIVE", "ACTIVE",
            {"sim2real": stack, "sim2real-ca": assoc_name})
    assert have == want, f"DescribeContainerAssociation {have!r}, expected {want!r}"
    clusters = ecs.describe_clusters(clusters=[out["ClusterArn"]], include=["TAGS"])["clusters"]
    got_cl = [(c["clusterName"], c["status"], _own_tags(c.get("tags"), "key", "value"))
              for c in clusters]
    assert got_cl == [(cluster_name, "ACTIVE", {"sim2real": stack, "sim2real-ca": cluster_name})], (
        f"cluster {got_cl!r}"
    )

    # The association alone: an update dropping it removes it while the cluster stays ACTIVE.
    cf.update_stack(StackName=stack_id,
                    TemplateBody=_template(cluster_name, assoc_name, with_assoc=False))
    status = wait_stack(cf, stack_id, timeout_s=deadline - time.monotonic())
    assert status == "UPDATE_COMPLETE", f"association-removing update ended {status!r}"
    not_found = (
        "ResourceNotFoundException",
        f"Container association '{assoc_name}' does not exist"
    )
    expect_error(
        lambda: nfw.describe_container_association(ContainerAssociationName=assoc_name),
        *not_found,
    )
    assert _listed(nfw, assoc_name) == [], f"dropped association listed: {_listed(nfw, assoc_name)!r}"
    kept = [c["status"] for c in ecs.describe_clusters(clusters=[out["ClusterArn"]])["clusters"]]
    assert kept == ["ACTIVE"], f"cluster after the update reads {kept!r}"

    delete_stack(cf, stack_id)
    final = [c["status"] for c in ecs.describe_clusters(clusters=[out["ClusterArn"]])["clusters"]]
    assert final == ["INACTIVE"], f"deleted cluster reads {final!r}, expected ['INACTIVE']"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
