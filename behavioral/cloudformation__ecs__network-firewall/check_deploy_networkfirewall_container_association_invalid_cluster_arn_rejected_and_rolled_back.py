"""deploy-networkfirewall-container-association-invalid-cluster-arn-rejected-and-rolled-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-networkfirewall-container-association-invalid-cluster-arn-rejected-and-rolled-back"
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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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

_BAD_CLUSTER_ARN = "not-an-arn"
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


def _listed(nfw, name):
    return [a["Arn"] for a in paginate(nfw, "list_container_associations",
                                       "ContainerAssociations") if a["Name"] == name]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation container association whose ClusterArn is malformed fails early validation.

    The validation row names the property path and no association exists, while the same
    template naming the stack's own cluster deploys ACTIVE.
    """
    cf = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    nfw = ctx.client("network-firewall")
    good_cluster = ctx.unique_name("sim2real-nfwrcagoodcluster-")
    good_assoc = ctx.unique_name("sim2real-nfwrcagoodassoc-")
    bad_cluster = ctx.unique_name("sim2real-nfwrcabadcluster-")
    bad_assoc = ctx.unique_name("sim2real-nfwrcabadassoc-")

    # Positive control: the same template, ClusterArn naming the stack's own cluster.
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-nfwrcagood-"),
                           _template(good_cluster, good_assoc))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    out = stack_outputs(cf, good_id)
    assert _listed(nfw, good_assoc) == [out["AssocArn"]], f"control {_listed(nfw, good_assoc)!r}"
    control = nfw.describe_container_association(ContainerAssociationName=good_assoc)
    got = ([c["ClusterArn"] for c in control["ContainerMonitoringConfigurations"]],
           control["Status"])
    assert got == ([out["ClusterArn"]], "ACTIVE"), f"control association reads {got!r}"
    clusters = [c["status"] for c in ecs.describe_clusters(clusters=[out["ClusterArn"]])["clusters"]]
    assert clusters == ["ACTIVE"], f"control cluster reads {clusters!r}"

    # The one bad property: ClusterArn is not an ARN.
    bad_id = create_stack(ctx, cf, ctx.unique_name("sim2real-nfwrcabad-"),
                          _template(bad_cluster, bad_assoc, _BAD_CLUSTER_ARN))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = [r for r in validation_rows(cf, bad_id) if r[3] == "FAIL"]
    want = [("Assoc", "PROPERTY_VALIDATION", "FAILED", "FAIL",
             f"Property value [{_BAD_CLUSTER_ARN}] does not match pattern: ^arn:aws",
             "/Resources/Assoc/Properties/ContainerMonitoringConfigurations/0/ClusterArn")]
    assert rows == want, f"validation rows {rows!r}, expected {want!r}"

    # Rollback absence through Network Firewall, BEFORE this check deletes the stack.
    assert _listed(nfw, bad_assoc) == [], f"rejected association listed: {_listed(nfw, bad_assoc)!r}"
    not_found = (
        "ResourceNotFoundException",
        f"Container association '{bad_assoc}' does not exist"
    )
    expect_error(
        lambda: nfw.describe_container_association(ContainerAssociationName=bad_assoc),
        *not_found,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
