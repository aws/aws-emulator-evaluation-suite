"""deploy-dataexchange-data-set-invalid-asset-type-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-dataexchange-data-set-invalid-asset-type-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "dataexchange"]

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

_BAD_ASSET_TYPE = "NOT_A_REAL_ASSET_TYPE"
_GOOD_ASSET_TYPE = "S3_SNAPSHOT"
_SUPPORTED = "[S3_SNAPSHOT, REDSHIFT_DATA_SHARE, API_GATEWAY_API, S3_DATA_ACCESS, LAKE_FORMATION_DATA_PERMISSION]"


def _template(asset_type: str, name: str, description: str) -> str:
    return json.dumps({
        "Resources": {
            "DS": {
                "Type": "AWS::DataExchange::DataSet",
                "Properties": {
                    "AssetType": asset_type,
                    "Description": description,
                    "Name": name,
                },
            },
        },
        "Outputs": {
            "DSRef": {"Value": {"Ref": "DS"}},
            "DSId": {"Value": {"Fn::GetAtt": ["DS", "Id"]}},
        },
    })


_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
    "with resource and property details, resolve each error, then retry the operation."
)
_VALIDATION = (
    "DS", "PROPERTY_VALIDATION", "FAILED", "FAIL",
    f"{_BAD_ASSET_TYPE} is not a valid enum value. Supported values: {_SUPPORTED}",
    "/Resources/DS/Properties/AssetType",
)


def _owned(dx, name):
    """Every OWNED data set named ``name``, across all pages."""
    return [d for d in paginate(dx, "list_data_sets", "DataSets", Origin="OWNED") if d["Name"] == name]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation DataExchange DataSet with an AssetType outside the enum fails early validation.

    The validation row names the property and reason and no data set of that name exists, while
    the same template with S3_SNAPSHOT deploys and reads back through DataExchange.
    """
    cfn = ctx.client("cloudformation")
    dx = ctx.client("dataexchange")
    good_name = ctx.unique_name("sim2real-behav-cfn-dxneg-")
    bad_name = ctx.unique_name("sim2real-behav-cfn-dxneg-")
    description = "sim2real behavioral negative check data set"

    # Positive control: the same template, AssetType given a valid value.
    good_id = create_stack(ctx, cfn, good_name, _template(_GOOD_ASSET_TYPE, good_name, description))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    out = stack_outputs(cfn, good_id)
    listed = [(d["Arn"], d["Id"]) for d in _owned(dx, good_name)]
    assert listed == [(out["DSRef"], out["DSId"])], f"OWNED data sets named {good_name!r}: {listed!r}"
    control = dx.get_data_set(DataSetId=out["DSId"])
    got = (control["Name"], control["AssetType"], control["Description"])
    assert got == (good_name, _GOOD_ASSET_TYPE, description), f"control GetDataSet {got!r}"

    bad_id = create_stack(ctx, cfn, bad_name, _template(_BAD_ASSET_TYPE, bad_name, description))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"invalid-asset-type stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    assert rows == [_VALIDATION], f"validation rows {rows!r}, expected {[_VALIDATION]!r}"
    failed = [(e["ResourceType"], e.get("ResourceStatusReason")) for e in stack_events(cfn, bad_id)
              if e["ResourceStatus"] == "CREATE_FAILED"]
    assert failed == [("AWS::CloudFormation::Stack", _STACK_REASON)], f"CREATE_FAILED rows {failed!r}"
    assert _owned(dx, bad_name) == [], f"a data set named {bad_name!r} exists after the rejection"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
