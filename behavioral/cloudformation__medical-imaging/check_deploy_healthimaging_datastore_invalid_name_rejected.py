"""deploy-healthimaging-datastore-invalid-name-rejected."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "deploy-healthimaging-datastore-invalid-name-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "medical-imaging"]

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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


# ---- Check-specific: the template, then run(). ----

_PATTERN = "^[A-Za-z0-9._/#-]+$"


def _template(datastore_name):
    return f"""
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Store:
    Type: AWS::HealthImaging::Datastore
    Properties:
      DatastoreName: "{datastore_name}"
Outputs:
  Id:
    Value: !Ref Store
"""


def _wait_left_creating(mi, datastore_id, timeout_s=300.0):
    deadline = time.monotonic() + timeout_s
    while True:
        props = mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]
        if props["datastoreStatus"] != "CREATING":
            return props
        if time.monotonic() > deadline:
            raise AssertionError(f"datastore did not leave CREATING, last={props!r}")
        time.sleep(5)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A HealthImaging data store whose DatastoreName breaks the type's naming pattern fails early
    validation on that property and no data store of the trimmed name exists, while the same
    template with a valid name provisions an ACTIVE store.
    """
    cfn = ctx.client("cloudformation")
    mi = ctx.client("medical-imaging")
    good_name = ctx.unique_name("sim2real-hi-ds-good-")
    bad_base = ctx.unique_name("sim2real-hi-ds-bad-")

    # Positive control: the same template, DatastoreName given a valid value.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-hi-good-"),
                           _template(good_name))
    status = wait_stack(cfn, good_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    good_ref = stack_outputs(cfn, good_id)["Id"]
    props = _wait_left_creating(mi, good_ref)
    got = (props["datastoreName"], props["datastoreStatus"])
    assert got == (good_name, "ACTIVE"), f"control datastore reads {got!r}"

    # Only the DatastoreName changes: a trailing space, which the type's pattern forbids.
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-hi-bad-"),
                          _template(bad_base + " "))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = [row[:4] + (masked(row[4], ctx.account, bad_base),) + row[5:]
            for row in validation_rows(cfn, bad_id)]
    want = [("Store", "PROPERTY_VALIDATION", "FAILED", "FAIL",
             f"Property value [<name> ] does not match pattern: {_PATTERN}",
             "/Resources/Store/Properties/DatastoreName")]
    assert rows == want, f"validation rows {rows!r}, expected {want!r}"

    # Rollback absence through HealthImaging by a name that could exist, before any delete.
    listed = {d["datastoreName"]: d["datastoreId"]
              for d in paginate(mi, "list_datastores", "datastoreSummaries")}
    assert listed.get(good_name) == good_ref, (
        f"the control datastore {good_name!r} lists as {listed.get(good_name)!r}, Ref {good_ref!r}"
    )
    assert bad_base not in listed and bad_base + " " not in listed, (
        f"a datastore of the rejected name exists: {listed.get(bad_base)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
