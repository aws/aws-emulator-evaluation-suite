"""cfn-personalize-datasetgroup-schema-dataset-eventtracker-read-back-then-deleted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-personalize-datasetgroup-schema-dataset-eventtracker-read-back-then-deleted"
GROUP = "deploy"
SERVICES = ["cloudformation", "personalize"]

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

_INTERACTIONS_SCHEMA = {
    "type": "record",
    "name": "Interactions",
    "namespace": "com.amazonaws.personalize.schema",
    "fields": [
        {"name": "USER_ID", "type": "string"},
        {"name": "ITEM_ID", "type": "string"},
        {"name": "TIMESTAMP", "type": "long"},
        {"name": "EVENT_TYPE", "type": "string"},
    ],
    "version": "1.0",
}


def _template(dg_name, schema_name, ds_name, et_name, with_tracker=True):
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "DatasetGroup": {
                "Type": "AWS::Personalize::DatasetGroup",
                "Properties": {"Name": dg_name},
            },
            "Schema": {
                "Type": "AWS::Personalize::Schema",
                "Properties": {"Name": schema_name, "Schema": json.dumps(_INTERACTIONS_SCHEMA)},
            },
            "Dataset": {
                "Type": "AWS::Personalize::Dataset",
                "Properties": {
                    "Name": ds_name,
                    "DatasetType": "Interactions",
                    "DatasetGroupArn": {"Ref": "DatasetGroup"},
                    "SchemaArn": {"Ref": "Schema"},
                },
            },
            "EventTracker": {
                "Type": "AWS::Personalize::EventTracker",
                "DependsOn": "Dataset",
                "Properties": {"Name": et_name, "DatasetGroupArn": {"Ref": "DatasetGroup"}},
            },
        },
        "Outputs": {
            "DatasetGroupRef": {"Value": {"Ref": "DatasetGroup"}},
            "SchemaRef": {"Value": {"Ref": "Schema"}},
            "DatasetRef": {"Value": {"Ref": "Dataset"}},
            "EventTrackerRef": {"Value": {"Ref": "EventTracker"}},
            "EventTrackerTrackingId": {"Value": {"Fn::GetAtt": ["EventTracker", "TrackingId"]}},
        },
    }
    if not with_tracker:
        del template["Resources"]["EventTracker"]
        template["Outputs"] = {k: v for k, v in template["Outputs"].items()
                               if not k.startswith("EventTracker")}
    return json.dumps(template)


def _one(rows, name, arn_key):
    """The ARN of the single entry named ``name`` in a paged list."""
    found = [r[arn_key] for r in rows if r["name"] == name]
    assert len(found) == 1, f"expected one entry named {name!r}, got {found!r}"
    return found[0]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Personalize DatasetGroup, Schema, Dataset and EventTracker are real: each
    Ref is the ARN Personalize lists by name and each reads back the template's values; an update
    dropping the tracker removes it first, and the stack delete removes the rest from Personalize.
    """
    cfn = ctx.client("cloudformation")
    personalize = ctx.client("personalize")
    dg_name = ctx.unique_name("sim2real-behav-pz-dg-")
    schema_name = ctx.unique_name("sim2real-behav-pz-schema-")
    ds_name = ctx.unique_name("sim2real-behav-pz-ds-")
    et_name = ctx.unique_name("sim2real-behav-pz-et-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-pzcore-"),
                            _template(dg_name, schema_name, ds_name, et_name))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    # Each Ref against the paged list entry of its declared name, never a read keyed by the Ref.
    dg_arn = _one(paginate(personalize, "list_dataset_groups", "datasetGroups"), dg_name,
                  "datasetGroupArn")
    schema_arn = _one(paginate(personalize, "list_schemas", "schemas"), schema_name, "schemaArn")
    ds_arn = _one(paginate(personalize, "list_datasets", "datasets", datasetGroupArn=dg_arn),
                  ds_name, "datasetArn")
    et_arn = _one(paginate(personalize, "list_event_trackers", "eventTrackers",
                           datasetGroupArn=dg_arn), et_name, "eventTrackerArn")
    got = (outputs["DatasetGroupRef"], outputs["SchemaRef"], outputs["DatasetRef"],
           outputs["EventTrackerRef"])
    assert got == (dg_arn, schema_arn, ds_arn, et_arn), (
        f"Refs {got!r}, listed {(dg_arn, schema_arn, ds_arn, et_arn)!r}"
    )

    dg = personalize.describe_dataset_group(datasetGroupArn=dg_arn)["datasetGroup"]
    assert (dg["name"], dg["status"]) == (dg_name, "ACTIVE"), f"dataset group reads {dg!r}"
    schema = personalize.describe_schema(schemaArn=schema_arn)["schema"]
    got = (schema["name"], json.loads(schema["schema"]))
    assert got == (schema_name, _INTERACTIONS_SCHEMA), f"schema reads {got!r}"
    ds = personalize.describe_dataset(datasetArn=ds_arn)["dataset"]
    got = (ds["name"], ds["datasetType"], ds["datasetGroupArn"], ds["schemaArn"], ds["status"])
    assert got == (ds_name, "INTERACTIONS", dg_arn, schema_arn, "ACTIVE"), f"dataset reads {got!r}"
    et = personalize.describe_event_tracker(eventTrackerArn=et_arn)["eventTracker"]
    got = (et["name"], et["datasetGroupArn"], et["trackingId"])
    assert got == (et_name, dg_arn, outputs["EventTrackerTrackingId"]), (
        f"event tracker (name, group, trackingId) {got!r}, GetAtt TrackingId "
        f"{outputs['EventTrackerTrackingId']!r}"
    )

    # The tracker's own delete: an update dropping it while its dataset group still answers.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(dg_name, schema_name, ds_name, et_name,
                                            with_tracker=False))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"tracker-removing update ended {status!r}"
    until_raises(lambda: personalize.describe_event_tracker(eventTrackerArn=et_arn))
    expect_error(lambda: personalize.describe_event_tracker(eventTrackerArn=et_arn),
                 *("ResourceNotFoundException", f"Resource Arn {et_arn} does not exist."))
    dg = personalize.describe_dataset_group(datasetGroupArn=dg_arn)["datasetGroup"]
    assert dg["status"] == "ACTIVE", f"the dataset group after the tracker update reads {dg!r}"

    delete_stack(cfn, stack_id)
    for read, message in (
        (lambda: personalize.describe_dataset(datasetArn=ds_arn),
         f"The given dataset does not exist: {ds_arn}"),
        (lambda: personalize.describe_schema(schemaArn=schema_arn),
         f"Resource Arn {schema_arn} does not exist."),
        (lambda: personalize.describe_dataset_group(datasetGroupArn=dg_arn),
         f"The given dataset group does not exist: {dg_arn}"),
    ):
        until_raises(read)
        gone = ("ResourceNotFoundException", message)
        expect_error(read, *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
