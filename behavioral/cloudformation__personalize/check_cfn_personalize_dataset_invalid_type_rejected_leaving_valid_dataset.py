"""cfn-personalize-dataset-invalid-type-rejected-leaving-valid-dataset."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-personalize-dataset-invalid-type-rejected-leaving-valid-dataset"
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


def _template(dg_name, schema_name, ds_name, dataset_type):
    return json.dumps({
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
                    "DatasetType": dataset_type,
                    "DatasetGroupArn": {"Ref": "DatasetGroup"},
                    "SchemaArn": {"Ref": "Schema"},
                },
            },
        },
        "Outputs": {"DatasetRef": {"Value": {"Ref": "Dataset"}}},
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack whose AWS::Personalize::Dataset names a DatasetType outside the enum fails early
    validation on that property and creates no dataset group or schema, while the same template
    with DatasetType Interactions deploys and its dataset is left untouched.
    """
    cfn = ctx.client("cloudformation")
    personalize = ctx.client("personalize")
    dg_name_a = ctx.unique_name("sim2real-behav-pz-dg-a-")
    schema_name_a = ctx.unique_name("sim2real-behav-pz-schema-a-")
    ds_name_a = ctx.unique_name("sim2real-behav-pz-ds-a-")
    dg_name_b = ctx.unique_name("sim2real-behav-pz-dg-b-")
    schema_name_b = ctx.unique_name("sim2real-behav-pz-schema-b-")
    ds_name_b = ctx.unique_name("sim2real-behav-pz-ds-b-")

    # Positive control: the same template, DatasetType given a valid value.
    stack_a = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-pzdsbad-ok-"),
                           _template(dg_name_a, schema_name_a, ds_name_a, "Interactions"))
    status = wait_stack(cfn, stack_a, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    ds_ref = stack_outputs(cfn, stack_a)["DatasetRef"]

    groups = {g["name"]: g["datasetGroupArn"]
              for g in paginate(personalize, "list_dataset_groups", "datasetGroups")}
    schemas = {s["name"]: s["schemaArn"] for s in paginate(personalize, "list_schemas", "schemas")}
    assert dg_name_a in groups and schema_name_a in schemas, (
        f"control dataset group / schema not listed: {groups.get(dg_name_a)!r}, "
        f"{schemas.get(schema_name_a)!r}"
    )
    listed = [d["datasetArn"] for d in paginate(personalize, "list_datasets", "datasets",
                                                datasetGroupArn=groups[dg_name_a])
              if d["name"] == ds_name_a]
    assert listed == [ds_ref], f"ListDatasets by name {listed!r}, Ref {ds_ref!r}"
    before = personalize.describe_dataset(datasetArn=ds_ref)["dataset"]
    got = (before["name"], before["datasetType"], before["datasetGroupArn"], before["schemaArn"],
           before["status"])
    want = (ds_name_a, "INTERACTIONS", groups[dg_name_a], schemas[schema_name_a], "ACTIVE")
    assert got == want, f"control dataset reads {got!r}, expected {want!r}"

    stack_b = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-pzdsbad-bad-"),
                           _template(dg_name_b, schema_name_b, ds_name_b, "Bogus"))
    status = wait_stack(cfn, stack_b)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, stack_b)
    want_rows = [("Dataset", "PROPERTY_VALIDATION", "FAILED", "FAIL",
                  "Bogus is not a valid enum value. Supported values: [Interactions, Items, Users]",
                  "/Resources/Dataset/Properties/DatasetType")]
    assert rows == want_rows, f"validation rows {rows!r}, expected {want_rows!r}"

    # Rollback absence through Personalize, by the names stack B would have used, before any
    # delete; the control's are listed by the same reads.
    groups = {g["name"] for g in paginate(personalize, "list_dataset_groups", "datasetGroups")}
    schemas = {s["name"] for s in paginate(personalize, "list_schemas", "schemas")}
    got = (dg_name_b in groups, schema_name_b in schemas, dg_name_a in groups,
           schema_name_a in schemas)
    assert got == (False, False, True, True), (
        f"(B group, B schema, A group, A schema) listed: {got!r}"
    )

    # The control's dataset is the same dataset, unchanged (server-minted timestamps).
    after = personalize.describe_dataset(datasetArn=ds_ref)["dataset"]
    keys = ("datasetArn", "status", "creationDateTime", "lastUpdatedDateTime")
    assert {k: after[k] for k in keys} == {k: before[k] for k in keys}, (
        f"the control dataset changed: {before!r} -> {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
