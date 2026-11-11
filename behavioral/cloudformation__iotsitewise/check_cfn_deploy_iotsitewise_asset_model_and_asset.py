"""cfn-deploy-iotsitewise-asset-model-and-asset."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-iotsitewise-asset-model-and-asset"

GROUP = "deploy"

SERVICES = ["cloudformation", "iotsitewise"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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

#: An asset model with one Attribute property, and an asset of that model, wired by Ref/GetAtt.
_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: IoTSiteWise asset model and asset provisioned through CloudFormation

Resources:
  AssetModel:
    Type: AWS::IoTSiteWise::AssetModel
    Properties:
      AssetModelName: !Sub '${AWS::StackName}-model'
      AssetModelProperties:
        - LogicalId: OperatorAttr
          Name: Operator
          DataType: STRING
          Type:
            TypeName: Attribute
            Attribute:
              DefaultValue: north-dock

  Asset:
    Type: AWS::IoTSiteWise::Asset
    Properties:
      AssetName: !Sub '${AWS::StackName}-asset'
      AssetModelId: !Ref AssetModel

Outputs:
  AssetModelId:
    Value: !Ref AssetModel
  AssetModelArn:
    Value: !GetAtt AssetModel.AssetModelArn
  AssetId:
    Value: !Ref Asset
  AssetArn:
    Value: !GetAtt Asset.AssetArn
"""


@tags("axis:happy-path", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Deploy an AssetModel+Asset via CFN; prove both through IoTSiteWise, then prove deletion."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-xsvc-stk-")
    stack_id = create_stack(ctx, cfn, name, _TEMPLATE)
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"Stack {name} ended in {status}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    model_name = f"{name}-model"
    asset_name = f"{name}-asset"
    outputs = stack_outputs(cfn, stack_id)
    model_id = outputs["AssetModelId"]
    model_arn = outputs["AssetModelArn"]
    asset_id = outputs["AssetId"]
    asset_arn = outputs["AssetArn"]

    sw = ctx.client("iotsitewise")

    model = _poll_until(
        lambda: sw.describe_asset_model(assetModelId=model_id),
        lambda m: m["assetModelStatus"]["state"] != "CREATING",
        timeout_s=180,
        interval_s=3.0,
        description=f"asset model {model_id} leaving CREATING",
    )
    assert model["assetModelStatus"]["state"] == "ACTIVE", (
        f"expected the asset model to reach ACTIVE, got {model['assetModelStatus']!r}"
    )
    assert model["assetModelId"] == model_id, (
        f"expected Ref to equal assetModelId {model_id!r}, got {model['assetModelId']!r}"
    )
    assert model["assetModelArn"] == model_arn, (
        f"expected GetAtt AssetModelArn {model_arn!r}, describe_asset_model returned {model['assetModelArn']!r}"
    )
    assert model["assetModelName"] == model_name, (
        f"expected assetModelName {model_name!r}, got {model['assetModelName']!r}"
    )
    listed_models = [
        m["id"]
        for m in paginate(sw, "list_asset_models", "assetModelSummaries")
        if m["name"] == model_name
    ]
    assert listed_models == [model_id], (
        f"expected ListAssetModels to list {model_name!r} once as Ref {model_id!r}, got {listed_models!r}"
    )
    props = model["assetModelProperties"]
    assert len(props) == 1, f"expected exactly one asset model property, got {props!r}"
    prop = props[0]
    assert prop["name"] == "Operator", f"expected property name 'Operator', got {prop['name']!r}"
    assert prop["dataType"] == "STRING", f"expected dataType 'STRING', got {prop['dataType']!r}"
    assert prop["type"]["attribute"]["defaultValue"] == "north-dock", (
        f"expected the template's attribute default value 'north-dock', got {prop['type']['attribute']!r}"
    )

    asset = _poll_until(
        lambda: sw.describe_asset(assetId=asset_id),
        lambda a: a["assetStatus"]["state"] != "CREATING",
        timeout_s=180,
        interval_s=3.0,
        description=f"asset {asset_id} leaving CREATING",
    )
    assert asset["assetStatus"]["state"] == "ACTIVE", (
        f"expected the asset to reach ACTIVE, got {asset['assetStatus']!r}"
    )
    assert asset["assetId"] == asset_id, (
        f"expected Ref to equal assetId {asset_id!r}, got {asset['assetId']!r}"
    )
    assert asset["assetArn"] == asset_arn, (
        f"expected GetAtt AssetArn {asset_arn!r}, describe_asset returned {asset['assetArn']!r}"
    )
    assert asset["assetModelId"] == model_id, (
        f"expected the asset to reference model {model_id!r}, got {asset['assetModelId']!r}"
    )
    assert asset["assetName"] == asset_name, f"expected assetName {asset_name!r}, got {asset['assetName']!r}"
    listed_assets = [
        a["id"] for a in paginate(sw, "list_assets", "assetSummaries", assetModelId=model_id)
    ]
    assert listed_assets == [asset_id], (
        f"expected ListAssets of the model to list only Ref {asset_id!r}, got {listed_assets!r}"
    )
    asset_props = asset["assetProperties"]
    assert len(asset_props) == 1, f"expected exactly one asset property, got {asset_props!r}"
    asset_prop_id = asset_props[0]["id"]
    prop_value = sw.describe_asset_property(assetId=asset_id, propertyId=asset_prop_id)[
        "assetProperty"
    ]
    assert prop_value["type"]["attribute"]["defaultValue"] == "north-dock", (
        f"expected the asset's property to read back default value 'north-dock', "
        f"got {prop_value['type']['attribute']!r}"
    )

    # Tear down in the body: delete the stack, then prove both resources gone through IoTSiteWise.
    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {name} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=name), *stack_gone)
    asset_gone = ("ResourceNotFoundException", f"Asset with ID {asset_id} not found")
    until_raises(lambda: sw.describe_asset(assetId=asset_id), timeout_s=120.0)
    expect_error(lambda: sw.describe_asset(assetId=asset_id), *asset_gone)
    model_gone = ("ResourceNotFoundException", f"Asset Model with ID {model_id} not found")
    until_raises(lambda: sw.describe_asset_model(assetModelId=model_id), timeout_s=120.0)
    expect_error(lambda: sw.describe_asset_model(assetModelId=model_id), *model_gone)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
