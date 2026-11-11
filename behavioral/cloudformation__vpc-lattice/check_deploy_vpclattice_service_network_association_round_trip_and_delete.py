"""deploy-vpclattice-service-network-association-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-vpclattice-service-network-association-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "vpc-lattice"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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

def _template(sn_name, svc_name, with_assoc=True):
    t = [{"Key": "sim2real-resource", "Value": svc_name}]
    resources = {
        "Sn": {"Type": "AWS::VpcLattice::ServiceNetwork",
               "Properties": {"Name": sn_name, "Tags": t}},
        "Svc": {"Type": "AWS::VpcLattice::Service", "Properties": {"Name": svc_name, "Tags": t}},
    }
    outputs = {
        "SnArn": {"Value": {"Ref": "Sn"}},
        "SnId": {"Value": {"Fn::GetAtt": ["Sn", "Id"]}},
        "SvcArn": {"Value": {"Ref": "Svc"}},
        "SvcId": {"Value": {"Fn::GetAtt": ["Svc", "Id"]}},
        "SvcDns": {"Value": {"Fn::GetAtt": ["Svc", "DnsEntry.DomainName"]}},
    }
    if with_assoc:
        resources["Assoc"] = {
            "Type": "AWS::VpcLattice::ServiceNetworkServiceAssociation",
            "Properties": {"ServiceNetworkIdentifier": {"Ref": "Sn"},
                           "ServiceIdentifier": {"Ref": "Svc"}, "Tags": t},
        }
        outputs["AssocArn"] = {"Value": {"Ref": "Assoc"}}
        outputs["AssocId"] = {"Value": {"Fn::GetAtt": ["Assoc", "Id"]}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _own_tags(vl, arn):
    tags_map = vl.list_tags_for_resource(resourceArn=arn).get("tags", {})
    return {k: v for k, v in tags_map.items() if not k.startswith("aws:")}


def _listed_arns(vl, op, name, **kw):
    return [i["arn"] for i in paginate(vl, op, "items", **kw) if i.get("name") == name]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation VPC Lattice service network, service and their association read back.

    Ref, GetAtt, names, linkage and tags match VPC Lattice; an update dropping the association
    removes it while both parents answer, and the stack delete removes the service and network.
    """
    vl = ctx.client("vpc-lattice")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-vpclattice-assoc-stack-")
    sn_name = ctx.unique_name("sim2real-vpclattice-sn-")
    svc_name = ctx.unique_name("sim2real-vpclattice-svc-")

    stack_id = create_stack(ctx, cfn, stack, _template(sn_name, svc_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    prefix = f"arn:{partition}:vpc-lattice:{ctx.region}:{ctx.account}"
    sn_arn, sn_id = out["SnArn"], out["SnId"]
    svc_arn, svc_id = out["SvcArn"], out["SvcId"]
    assoc_arn, assoc_id = out["AssocArn"], out["AssocId"]
    want_tags = {"sim2real": stack, "sim2real-resource": svc_name}

    # Ref == the ARN an independent listing reports for each templated name, and the
    # documented ARN format.
    assert _listed_arns(vl, "list_service_networks", sn_name) == [sn_arn], "service network Ref"
    assert _listed_arns(vl, "list_services", svc_name) == [svc_arn], "service Ref"
    want_arns = (f"{prefix}:servicenetwork/{sn_id}", f"{prefix}:service/{svc_id}")
    assert (sn_arn, svc_arn) == want_arns, (
        f"(service network, service) ARNs {(sn_arn, svc_arn)!r}, expected {want_arns!r}"
    )
    sn = vl.get_service_network(serviceNetworkIdentifier=sn_arn)
    assert (sn["id"], sn["name"]) == (sn_id, sn_name), f"GetServiceNetwork reads {sn!r}"
    svc = vl.get_service(serviceIdentifier=svc_arn)
    got = (svc["id"], svc["name"], svc["status"], svc["dnsEntry"]["domainName"])
    assert got == (svc_id, svc_name, "ACTIVE", out["SvcDns"]), f"GetService reads {got!r}"

    # Association: Ref == the one association listed for the network; linkage and status match.
    assocs = [a["arn"] for a in paginate(vl, "list_service_network_service_associations",
                                         "items", serviceNetworkIdentifier=sn_arn)]
    assert assocs == [assoc_arn], f"associations of the network {assocs!r}, Ref {assoc_arn!r}"
    want_arn = f"{prefix}:servicenetworkserviceassociation/{assoc_id}"
    assert assoc_arn == want_arn, f"association ARN {assoc_arn!r}, expected {want_arn!r}"
    assoc = vl.get_service_network_service_association(
        serviceNetworkServiceAssociationIdentifier=assoc_arn)
    got = {k: assoc[k] for k in ("status", "serviceId", "serviceNetworkId", "serviceArn",
                                 "serviceNetworkArn")}
    want = {"status": "ACTIVE", "serviceId": svc_id, "serviceNetworkId": sn_id,
            "serviceArn": svc_arn, "serviceNetworkArn": sn_arn}
    assert got == want, f"association reads {got!r}, expected {want!r}"
    for arn in (sn_arn, svc_arn, assoc_arn):
        assert _own_tags(vl, arn) == want_tags, f"{arn} tags {_own_tags(vl, arn)!r}"

    # Child first: an update dropping the association removes it while both parents answer.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(sn_name, svc_name, False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"association-dropping update ended {status!r}"
    until_raises(lambda: vl.get_service_network_service_association(
        serviceNetworkServiceAssociationIdentifier=assoc_id))
    gone = ("ResourceNotFoundException", f"Association {assoc_id} cannot be found.")
    expect_error(lambda: vl.get_service_network_service_association(
        serviceNetworkServiceAssociationIdentifier=assoc_id), *gone)
    left = paginate(vl, "list_service_network_service_associations", "items",
                    serviceNetworkIdentifier=sn_arn)
    assert left == [], f"associations of the network after the update: {left!r}"
    created = vl.get_service(serviceIdentifier=svc_arn)["createdAt"]
    assert created == svc["createdAt"], (
        f"service after the update reads createdAt {created!r}, before {svc['createdAt']!r}"
    )
    created = vl.get_service_network(serviceNetworkIdentifier=sn_arn)["createdAt"]
    assert created == sn["createdAt"], (
        f"service network after the update reads createdAt {created!r}, before {sn['createdAt']!r}"
    )

    delete_stack(cfn, stack_id)
    gone = ("ResourceNotFoundException", f"Service {svc_id} cannot be found.")
    expect_error(lambda: vl.get_service(serviceIdentifier=svc_id), *gone)
    gone = ("ResourceNotFoundException", f"ServiceNetwork {sn_id} cannot be found.")
    expect_error(lambda: vl.get_service_network(serviceNetworkIdentifier=sn_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
