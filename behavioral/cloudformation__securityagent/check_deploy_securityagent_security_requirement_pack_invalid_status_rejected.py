"""deploy-securityagent-security-requirement-pack-invalid-status-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-securityagent-security-requirement-pack-invalid-status-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "securityagent"]

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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

_VALIDATION_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
    "with resource and property details, resolve each error, then retry the operation."
)


def _template(pack_name: str, status: str) -> str:
    props = {"Name": pack_name}
    if status is not None:
        props["Status"] = status
    return json.dumps({
        "Resources": {
            "SRP": {"Type": "AWS::SecurityAgent::SecurityRequirementPack", "Properties": props},
        },
        "Outputs": {
            "SRPRef": {"Value": {"Ref": "SRP"}},
            "SRPPackId": {"Value": {"Fn::GetAtt": ["SRP", "PackId"]}},
        },
    })


def _pack_ids_named(sa, name: str) -> list[str]:
    """Ids of every listed security requirement pack called ``name``, across all pages."""
    packs = paginate(sa, "list_security_requirement_packs", "securityRequirementPackSummaries")
    return [p["packId"] for p in packs if p["name"] == name]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::SecurityAgent::SecurityRequirementPack with a Status outside the
    registry's enum is rejected before any resource is created, and the stack rolls back; the
    identical template with a valid Status still deploys and reads back through SecurityAgent."""
    cf = ctx.client("cloudformation")
    sa = ctx.client("securityagent")

    bad_stack_name = ctx.unique_name("sim2real-behav-cfn-sa-srp-bad-")
    bad_pack_name = ctx.unique_name("sim2real-behav-cfn-sa-srp-bad-")
    bad_stack_id = create_stack(ctx, cf, bad_stack_name, _template(bad_pack_name, "ARCHIVED"))
    status = wait_stack(cf, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    reason = failed_reason(stack_events(cf, bad_stack_id), bad_stack_name)
    assert reason == _VALIDATION_REASON, f"expected the template-validation reason, got {reason!r}"

    found = validation_rows(cf, bad_stack_id)
    want = [("SRP", "PROPERTY_VALIDATION", "FAILED", "FAIL",
             "ARCHIVED is not a valid enum value. Supported values: [ENABLED, DISABLED]",
             "/Resources/SRP/Properties/Status")]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"

    resources = cf.describe_stack_resources(StackName=bad_stack_id)["StackResources"]
    assert resources == [], f"expected no resource to have been created, got {resources!r}"

    listed = _pack_ids_named(sa, bad_pack_name)
    assert listed == [], f"expected no pack named {bad_pack_name!r} after the rejection, listed {listed!r}"

    # Positive control: the identical template, with a valid Status, deploys and reads back.
    good_stack_name = ctx.unique_name("sim2real-behav-cfn-sa-srp-good-")
    good_pack_name = ctx.unique_name("sim2real-behav-cfn-sa-srp-good-")
    good_stack_id = create_stack(ctx, cf, good_stack_name, _template(good_pack_name, "ENABLED"))
    good_status = wait_stack(cf, good_stack_id)
    assert good_status == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {good_status!r}: "
        f"{decisive_rows(stack_events(cf, good_stack_id))!r}"
    )

    good_outputs = stack_outputs(cf, good_stack_id)
    pack_id = good_outputs["SRPRef"]
    listed = _pack_ids_named(sa, good_pack_name)
    assert listed == [pack_id] and good_outputs["SRPPackId"] == pack_id, (
        f"ListSecurityRequirementPacks ids named {good_pack_name!r}: {listed!r}; Ref {pack_id!r}, "
        f"GetAtt PackId {good_outputs['SRPPackId']!r}"
    )
    got_pack = sa.get_security_requirement_pack(packId=pack_id)
    assert got_pack["name"] == good_pack_name, (
        f"expected the control pack {good_pack_name!r} to exist, got {got_pack!r}"
    )
    assert got_pack["status"] == "ENABLED", f"expected the control pack status ENABLED, got {got_pack['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
