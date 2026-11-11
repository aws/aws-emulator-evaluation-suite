"""deploy-route53-cidrcollection-delegationset-trafficpolicy-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-route53-cidrcollection-delegationset-trafficpolicy-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "route53"]

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

_TP_DOCUMENT = {
    "AWSPolicyFormatVersion": "2015-10-01",
    "RecordType": "A",
    "Endpoints": {"endpoint-1": {"Type": "value", "Value": "203.0.113.9"}},
    "StartEndpoint": "endpoint-1",
}


def _template(cidr_name: str, tp_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Cidr": {
                "Type": "AWS::Route53::CidrCollection",
                "Properties": {
                    "Name": cidr_name,
                    "Locations": [{"LocationName": "loc1", "CidrList": ["192.0.2.0/24"]}],
                },
            },
            "Deleg": {"Type": "AWS::Route53::DelegationSet", "Properties": {}},
            "Tp": {
                "Type": "AWS::Route53::TrafficPolicy",
                "Properties": {"Name": tp_name, "Document": json.dumps(_TP_DOCUMENT)},
            },
        },
        "Outputs": {
            "CidrRef": {"Value": {"Ref": "Cidr"}},
            "CidrId": {"Value": {"Fn::GetAtt": ["Cidr", "Id"]}},
            "DelegRef": {"Value": {"Ref": "Deleg"}},
            "DelegId": {"Value": {"Fn::GetAtt": ["Deleg", "Id"]}},
            "TpRef": {"Value": {"Ref": "Tp"}},
            "TpId": {"Value": {"Fn::GetAtt": ["Tp", "Id"]}},
            "TpType": {"Value": {"Fn::GetAtt": ["Tp", "Type"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack's AWS::Route53::CidrCollection, AWS::Route53::DelegationSet and
    AWS::Route53::TrafficPolicy each read back through Route53's own API with the declared
    properties and documented Ref forms, and deleting the stack removes each from Route53.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-cidrcollection.html
    """
    route53 = ctx.client("route53")
    cfn = ctx.client("cloudformation")
    cidr_name = ctx.unique_name("sim2realr53cc")
    tp_name = ctx.unique_name("sim2realr53tp")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-r53misc-"),
                            _template(cidr_name, tp_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    cidr_id, deleg_id, tp_id = outputs["CidrId"], outputs["DelegId"], outputs["TpId"]

    # CidrCollection: Ref and GetAtt Id == the Id ListCidrCollections pages out for the name.
    matches = [c for c in paginate(route53, "list_cidr_collections", "CidrCollections")
               if c["Name"] == cidr_name]
    assert len(matches) == 1, f"ListCidrCollections by name: {matches!r}"
    assert (outputs["CidrRef"], cidr_id) == (matches[0]["Id"], matches[0]["Id"]), (
        f"CidrCollection Ref/GetAtt Id {(outputs['CidrRef'], cidr_id)!r}, listed {matches[0]!r}"
    )
    blocks = paginate(route53, "list_cidr_blocks", "CidrBlocks", CollectionId=cidr_id)
    got = [(b["LocationName"], b["CidrBlock"]) for b in blocks]
    assert got == [("loc1", "192.0.2.0/24")], f"ListCidrBlocks {got!r}"

    # DelegationSet and TrafficPolicy: Ref is the documented ARN of the id Route53 returns.
    deleg = route53.get_reusable_delegation_set(Id=deleg_id)["DelegationSet"]
    got = (deleg["Id"], len(deleg["NameServers"]), outputs["DelegRef"])
    want = (f"/delegationset/{deleg_id}", 4, f"arn:{partition}:route53:::delegationset/{deleg_id}")
    assert got == want, f"delegation set (Id, name server count, Ref) {got!r}, expected {want!r}"

    tp = route53.get_traffic_policy(Id=tp_id, Version=1)["TrafficPolicy"]
    got = (tp["Id"], tp["Name"], tp["Type"], json.loads(tp["Document"]), outputs["TpRef"])
    want = (tp_id, tp_name, outputs["TpType"], _TP_DOCUMENT,
            f"arn:{partition}:route53:::trafficpolicy/{tp_id}")
    assert got == want, f"traffic policy reads {got!r}, expected {want!r}"

    delete_stack(cfn, stack_id)
    expect_error(lambda: route53.list_cidr_blocks(CollectionId=cidr_id),
                 *("NoSuchCidrCollectionException", ""))
    expect_error(lambda: route53.get_reusable_delegation_set(Id=deleg_id),
                 *("NoSuchDelegationSet", deleg_id))
    remaining = route53.list_traffic_policy_versions(Id=tp_id)["TrafficPolicies"]
    assert remaining == [], f"ListTrafficPolicyVersions({tp_id!r}) after delete: {remaining!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
