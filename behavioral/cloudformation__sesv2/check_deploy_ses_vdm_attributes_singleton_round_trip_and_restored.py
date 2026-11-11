"""deploy-ses-vdm-attributes-singleton-round-trip-and-restored."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-ses-vdm-attributes-singleton-round-trip-and-restored"
GROUP = "deploy"
SERVICES = ["cloudformation", "sesv2"]

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

_GOOD_TEMPLATE_BODY = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Vdm:
    Type: AWS::SES::VdmAttributes
    Properties:
      DashboardAttributes:
        EngagementMetrics: DISABLED
      GuardianAttributes:
        OptimizedSharedDelivery: DISABLED
Outputs:
  VdmRefOut:
    Value: !Ref Vdm
"""

#: The account's VDM state while no VdmAttributes resource or other writer has set it.
_DISABLED = {"VdmEnabled": "DISABLED"}


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:ses-account",
)
def run(ctx) -> None:
    """A VdmAttributes singleton deployed by CloudFormation sets the account's dashboard and
    guardian preferences, its Ref names the account, and deleting the stack resets them."""
    cf = ctx.client("cloudformation")
    sesv2 = ctx.client("sesv2")

    prior = sesv2.get_account().get("VdmAttributes")
    assert prior in (None, _DISABLED), (
        f"precondition: the account's VdmAttributes must be unset or {_DISABLED!r} before this "
        f"account-singleton check runs, found {prior!r}"
    )

    def _restore_prior() -> None:
        sesv2.put_account_vdm_attributes(VdmAttributes=prior or _DISABLED)

    ctx.on_cleanup(_restore_prior)

    good_stack = ctx.unique_name("sim2real-cfn-vdm-")
    stack_id = create_stack(ctx, cf, good_stack, _GOOD_TEMPLATE_BODY)
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack create ended in {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )

    outputs = stack_outputs(cf, stack_id)
    expected_ref = f"VdmAttributes_for_{ctx.account}"
    assert outputs["VdmRefOut"] == expected_ref, (
        f"expected Ref {expected_ref!r}, got {outputs['VdmRefOut']!r}"
    )

    vdm = sesv2.get_account()["VdmAttributes"]
    assert vdm == {
        "VdmEnabled": "ENABLED",
        "DashboardAttributes": {"EngagementMetrics": "DISABLED"},
        "GuardianAttributes": {"OptimizedSharedDelivery": "DISABLED"},
    }, f"unexpected VdmAttributes after deploy: {vdm!r}"

    delete_stack(cf, stack_id)

    vdm_after = sesv2.get_account().get("VdmAttributes")
    assert vdm_after == _DISABLED, f"expected VdmAttributes reset to {_DISABLED!r}, got {vdm_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
