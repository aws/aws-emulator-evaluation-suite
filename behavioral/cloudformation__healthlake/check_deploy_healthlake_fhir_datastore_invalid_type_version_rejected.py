"""deploy-healthlake-fhir-datastore-invalid-type-version-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-healthlake-fhir-datastore-invalid-type-version-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "healthlake"]

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

_CREATE_TIMEOUT_S = 2400.0

_INVALID_VERSION = (
    "Datastore", "PROPERTY_VALIDATION", "FAILED", "FAIL",
    "R5 is not a valid enum value. Supported values: [R4]",
    "/Resources/Datastore/Properties/DatastoreTypeVersion",
)
_CREATE_FAILED_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)


def _template(type_version: str, name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Datastore": {
                "Type": "AWS::HealthLake::FHIRDatastore",
                "Properties": {
                    "DatastoreTypeVersion": type_version,
                    "DatastoreName": name,
                    "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
                },
            }
        },
        "Outputs": {"DatastoreId": {"Value": {"Ref": "Datastore"}}},
    })


def _datastore_names(healthlake) -> set[str]:
    """Every DatastoreName ListFHIRDatastores reports, following NextToken to the end."""
    names: set[str] = set()
    kwargs: dict = {}
    while True:
        page = healthlake.list_fhir_datastores(**kwargs)
        names |= {d["DatastoreName"] for d in page["DatastorePropertiesList"]}
        token = page.get("NextToken")
        if not token:
            return names
        kwargs = {"NextToken": token}


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::HealthLake::FHIRDatastore with an unsupported DatastoreTypeVersion
    fails early validation naming that property and creates no datastore; the identical template
    with DatastoreTypeVersion R4 deploys, reaches ACTIVE and reads back.

    Reference: https://docs.aws.amazon.com/healthlake/latest/devguide/working-with-FHIR-healthlake.html
    """
    cfn = ctx.client("cloudformation")
    healthlake = ctx.client("healthlake")

    good_stack = ctx.unique_name("sim2real-hlcfn-ok-")
    good_name = ctx.unique_name("sim2real-hlcfn-ok-ds-")
    bad_stack = ctx.unique_name("sim2real-hlcfn-bad-")
    bad_name = ctx.unique_name("sim2real-hlcfn-bad-ds-")

    # Positive control: the identical shape with a supported DatastoreTypeVersion.
    good_stack_id = create_stack(ctx, cfn, good_stack, _template("R4", good_name))
    good_status = wait_stack(cfn, good_stack_id, timeout_s=_CREATE_TIMEOUT_S)
    assert good_status == "CREATE_COMPLETE", (
        f"control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, good_stack_id))!r}"
    )
    good_outputs = stack_outputs(cfn, good_stack_id)
    good_id = good_outputs["DatastoreId"]
    good_described = healthlake.describe_fhir_datastore(DatastoreId=good_id)["DatastoreProperties"]
    assert good_described["DatastoreStatus"] == "ACTIVE", (
        f"control datastore {good_id!r}: expected ACTIVE, got {good_described['DatastoreStatus']!r}"
    )
    assert good_described["DatastoreTypeVersion"] == "R4", (
        f"control datastore: expected DatastoreTypeVersion R4, "
        f"got {good_described['DatastoreTypeVersion']!r}"
    )
    assert good_described["DatastoreName"] == good_name, (
        f"control datastore: expected DatastoreName {good_name!r}, got {good_described['DatastoreName']!r}"
    )

    # The one thing broken: an unsupported DatastoreTypeVersion.
    bad_stack_id = create_stack(ctx, cfn, bad_stack, _template("R5", bad_name))
    bad_status = wait_stack(cfn, bad_stack_id, timeout_s=_CREATE_TIMEOUT_S)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"expected bad stack {bad_stack!r} to end ROLLBACK_COMPLETE, got {bad_status!r}"
    )

    events = stack_events(cfn, bad_stack_id)
    create_failed = [
        e for e in events
        if e["LogicalResourceId"] == bad_stack and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(create_failed) == 1, (
        f"expected exactly one stack-level CREATE_FAILED event, found {len(create_failed)}: "
        f"{create_failed!r}"
    )
    reason = create_failed[0]["ResourceStatusReason"]
    assert reason == _CREATE_FAILED_REASON, (
        f"expected CREATE_FAILED reason {_CREATE_FAILED_REASON!r}, got {reason!r}"
    )

    # The one validation error names the bad property and its allowed values.
    found = validation_rows(cfn, bad_stack_id)
    assert found == [_INVALID_VERSION], (
        f"validation errors of the create: expected {[_INVALID_VERSION]!r}, got {found!r}"
    )

    # The resource handler was never invoked: the logical resource has no entry at all.
    resource_absent = ("ValidationError", f"Resource Datastore does not exist for stack {bad_stack}")
    expect_error(
        lambda: cfn.describe_stack_resource(StackName=bad_stack, LogicalResourceId="Datastore"),
        *resource_absent,
    )

    # Effect-absent through HealthLake itself: the bad template's intended name was never created,
    # while the control's name is present (an absence assert that can fail).
    names = _datastore_names(healthlake)
    assert bad_name not in names, f"{bad_name!r} unexpectedly appears in HealthLake's own datastores"
    assert good_name in names, (
        f"expected the control datastore {good_name!r} among HealthLake's own datastores {names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
