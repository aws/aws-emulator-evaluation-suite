"""deploy-ses-vdm-attributes-invalid-value-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ses-vdm-attributes-invalid-value-rejected"
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

_TEMPLATE_BODY = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Vdm:
    Type: AWS::SES::VdmAttributes
    Properties:
      DashboardAttributes:
        EngagementMetrics: {engagement}
      GuardianAttributes:
        OptimizedSharedDelivery: DISABLED
"""

#: The account's VDM state while no VdmAttributes resource or other writer has set it.
_DISABLED = {"VdmEnabled": "DISABLED"}
_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)
_STACK_GONE = "Stack with id {} does not exist"


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
    "resource:account-singleton:ses-account",
)
def run(ctx) -> None:
    """A VdmAttributes EngagementMetrics outside ENABLED|DISABLED fails template validation and never
    reaches the account; the same template with a valid value deploys and sets the account's VDM."""
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

    bad_stack = ctx.unique_name("sim2real-cfn-vdm-bad-")
    bad_id = create_stack(ctx, cf, bad_stack, _TEMPLATE_BODY.format(engagement="BOGUS"))
    bad_status = wait_stack(cf, bad_id)
    assert bad_status == "ROLLBACK_COMPLETE", f"stack create ended in {bad_status!r}, not ROLLBACK_COMPLETE"

    reason = failed_reason(stack_events(cf, bad_id), bad_stack)
    assert reason == _STACK_REASON, f"the stack's CREATE_FAILED reason was {reason!r}"
    found = validation_rows(cf, bad_id)
    want = [(
        "Vdm", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        "Property value [BOGUS] does not match pattern: ENABLED|DISABLED",
        "/Resources/Vdm/Properties/DashboardAttributes/EngagementMetrics",
    )]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"

    # Before the stack's own delete: the rejected value never reached the account.
    vdm_untouched = sesv2.get_account().get("VdmAttributes")
    assert vdm_untouched == prior, (
        f"the rejected stack changed VdmAttributes from {prior!r} to {vdm_untouched!r}"
    )

    delete_stack(cf, bad_id)
    stack_gone = ("ValidationError", _STACK_GONE.format(bad_stack))
    expect_error(lambda: cf.describe_stacks(StackName=bad_stack), *stack_gone)

    # Positive control: the same template with a valid EngagementMetrics deploys and applies.
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfn-vdm-good-"),
                           _TEMPLATE_BODY.format(engagement="DISABLED"))
    good_status = wait_stack(cf, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"control stack ended in {good_status!r}: {decisive_rows(stack_events(cf, good_id))!r}"
    )
    vdm = sesv2.get_account()["VdmAttributes"]
    assert vdm == {
        "VdmEnabled": "ENABLED",
        "DashboardAttributes": {"EngagementMetrics": "DISABLED"},
        "GuardianAttributes": {"OptimizedSharedDelivery": "DISABLED"},
    }, f"unexpected VdmAttributes after the control deploy: {vdm!r}"

    delete_stack(cf, good_id)
    vdm_after = sesv2.get_account().get("VdmAttributes")
    assert vdm_after == _DISABLED, f"expected VdmAttributes reset to {_DISABLED!r}, got {vdm_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
