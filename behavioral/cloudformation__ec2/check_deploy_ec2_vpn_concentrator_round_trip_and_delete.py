"""deploy-ec2-vpn-concentrator-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-ec2-vpn-concentrator-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

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

_ATTACHMENT_LAG_S = 180.0  # EC2 clears the VPN concentrator's TGW attachment asynchronously


def _concentrator_attachments(ec2, tgw_id):
    return [(a["TransitGatewayAttachmentId"], a["State"]) for a in paginate(
        ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments",
        Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]},
                 {"Name": "resource-type", "Values": ["vpn-concentrator"]}])]


def _delete_stack_waiting_for_attachment(cf, ec2, stack_id):
    """Delete the stack, retrying exactly the documented transient order gap: the VPN
    concentrator's own delete tombstones instantly, but its transit-gateway attachment clears
    asynchronously and CloudFormation's single TransitGateway delete attempt does not wait for
    it, so the first delete can end DELETE_FAILED with 'non-deleted vpn-concentrator attachment'.
    """
    try:
        delete_stack(cf, stack_id)
        return
    except AssertionError as exc:
        if "non-deleted vpn-concentrator attachment" not in str(exc):
            raise
    tgw_id = cf.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="Tgw"
    )["StackResourceDetail"]["PhysicalResourceId"]
    deadline = time.monotonic() + _ATTACHMENT_LAG_S
    while True:
        attachments = _concentrator_attachments(ec2, tgw_id)
        if all(state == "deleted" for _, state in attachments):
            break
        if time.monotonic() > deadline:
            raise AssertionError(
                f"tgw {tgw_id!r} vpn-concentrator attachment never cleared: {attachments!r}"
            )
        time.sleep(5)
    delete_stack(cf, stack_id)


def _template(name, with_concentrator=True):
    resources = {"Tgw": {"Type": "AWS::EC2::TransitGateway", "Properties": {}}}
    outputs = {"TgwRef": {"Value": {"Ref": "Tgw"}}}
    if with_concentrator:
        resources["Concentrator"] = {"Type": "AWS::EC2::VPNConcentrator", "Properties": {
            "Type": "ipsec.1", "TransitGatewayId": {"Ref": "Tgw"},
            "Tags": [{"Key": "sim2real-vc", "Value": name}],
        }}
        outputs.update({
            "ConcentratorRef": {"Value": {"Ref": "Concentrator"}},
            "AttachmentId": {"Value": {"Fn::GetAtt": ["Concentrator",
                                                      "TransitGatewayAttachmentId"]}},
        })
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation VPNConcentrator on its TransitGateway reads back through EC2 by the stack
    tag with its templated Type, gateway, attachment and tags; an update dropping it leaves the
    documented 'deleted' state while the gateway answers, and the stack delete removes the gateway.
    """
    cf = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stack = ctx.unique_name("sim2real-ec2vpnconc-")

    # create_stack registers the plain delete before the call; the attachment-aware delete is
    # registered next, so it runs first (LIFO) and leaves the plain one nothing to do.
    stack_id = create_stack(ctx, cf, stack, _template(stack))
    ctx.on_cleanup(lambda: _delete_stack_waiting_for_attachment(cf, ec2, stack_id))
    status = wait_stack(cf, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    tgw_ref, vc_ref, attachment_id = out["TgwRef"], out["ConcentratorRef"], out["AttachmentId"]

    # Ref against an independent read (filtered by the stack's own tag), never a read by the Ref.
    concentrators = paginate(ec2, "describe_vpn_concentrators", "VpnConcentrators",
                             Filters=[{"Name": "tag:sim2real", "Values": [stack]}])
    got = [(c["VpnConcentratorId"], c["Type"], c["TransitGatewayId"],
            c["TransitGatewayAttachmentId"], c["State"],
            {t["Key"]: t["Value"] for t in c.get("Tags", []) if not t["Key"].startswith("aws:")})
           for c in concentrators]
    assert got == [(vc_ref, "ipsec.1", tgw_ref, attachment_id, "available",
                    {"sim2real": stack, "sim2real-vc": stack})], f"vpn concentrators {got!r}"
    assert _concentrator_attachments(ec2, tgw_ref) == [(attachment_id, "available")], (
        f"gateway attachments {_concentrator_attachments(ec2, tgw_ref)!r}"
    )

    # The concentrator's own delete: an update drops it while the same gateway still answers.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(stack, False))
    status = wait_stack(cf, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"concentrator-removing update ended {status!r}"
    after_vc = paginate(ec2, "describe_vpn_concentrators", "VpnConcentrators",
                        VpnConcentratorIds=[vc_ref])
    assert [c["State"] for c in after_vc] == ["deleted"], f"concentrator after update {after_vc!r}"
    tgws = paginate(ec2, "describe_transit_gateways", "TransitGateways",
                    TransitGatewayIds=[tgw_ref])
    assert [g["State"] for g in tgws] == ["available"], f"gateway after the update {tgws!r}"

    _delete_stack_waiting_for_attachment(cf, ec2, stack_id)
    after_tgw = paginate(ec2, "describe_transit_gateways", "TransitGateways",
                         TransitGatewayIds=[tgw_ref])
    assert [g["State"] for g in after_tgw] == ["deleted"], f"gateway after delete {after_tgw!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
