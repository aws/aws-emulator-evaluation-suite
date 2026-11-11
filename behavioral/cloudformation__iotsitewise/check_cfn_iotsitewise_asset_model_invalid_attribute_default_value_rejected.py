"""cfn-iotsitewise-asset-model-invalid-attribute-default-value-rejected."""

from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "cfn-iotsitewise-asset-model-invalid-attribute-default-value-rejected"

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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: IoTSiteWise asset model with one attribute property

Resources:
  AssetModel:
    Type: AWS::IoTSiteWise::AssetModel
    Properties:
      AssetModelName: !Sub '${{AWS::StackName}}-model'
      AssetModelProperties:
        - LogicalId: OperatorAttr
          Name: Operator
          DataType: {data_type}
          Type:
            TypeName: Attribute
            Attribute:
              DefaultValue: not-a-number

Outputs:
  AssetModelId:
    Value: !Ref AssetModel
"""

#: The positive control: a STRING attribute, which any DefaultValue matches.
_GOOD_TEMPLATE = _TEMPLATE.format(data_type="STRING")

#: The same template with only DataType changed to INTEGER: the DefaultValue is no longer the
#: expected type.
_BAD_TEMPLATE = _TEMPLATE.format(data_type="INTEGER")

#: The forwarded IoT SiteWise refusal, as (masked handler message, HandlerErrorCode).
_REJECTED = (
    "Property Operator Attribute default value is not the expected type. "
    "(Service: IoTSiteWise, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


@tags("axis:rejection", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A DataType/DefaultValue type mismatch is forwarded and rejected; a correct model deploys."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    sw = ctx.client("iotsitewise")
    good_name = ctx.unique_name("sim2real-xsvc-stk-")
    good_id = create_stack(ctx, cfn, good_name, _GOOD_TEMPLATE)
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"Stack {good_name} ended in {status}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    good_model_id = stack_outputs(cfn, good_id)["AssetModelId"]
    model = _poll_until(
        lambda: sw.describe_asset_model(assetModelId=good_model_id),
        lambda m: m["assetModelStatus"]["state"] != "CREATING",
        timeout_s=180,
        interval_s=3.0,
        description=f"positive control asset model {good_model_id} leaving CREATING",
    )
    assert model["assetModelStatus"]["state"] == "ACTIVE", (
        f"positive control: expected ACTIVE, got {model['assetModelStatus']!r}"
    )
    good_model_name = f"{good_name}-model"
    assert model["assetModelName"] == good_model_name, (
        f"positive control: expected assetModelName {good_model_name!r}, got {model['assetModelName']!r}"
    )
    props = model["assetModelProperties"]
    assert len(props) == 1, f"positive control: expected one asset model property, got {props!r}"
    got_prop = (props[0]["name"], props[0]["dataType"], props[0]["type"]["attribute"]["defaultValue"])
    assert got_prop == ("Operator", "STRING", "not-a-number"), (
        f"positive control: expected ('Operator', 'STRING', 'not-a-number'), got {got_prop!r}"
    )

    bad_name = ctx.unique_name("sim2real-xsvc-stk-")
    bad_stack_id = create_stack(ctx, cfn, bad_name, _BAD_TEMPLATE)
    status = wait_stack(cfn, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"expected the bad model to roll the stack back, got {status!r}"
    )
    reason = failed_reason(stack_events(cfn, bad_stack_id), "AssetModel")
    got_reason = handler_reason(reason, ctx.account, bad_name)
    assert got_reason == _REJECTED, f"expected {_REJECTED!r}, got {got_reason!r}"

    # Absence: the rejected model never reached IoTSiteWise, so it cannot appear beside the
    # positive control's, which does.
    names = {m["name"] for m in paginate(sw, "list_asset_models", "assetModelSummaries")}
    assert good_model_name in names, f"expected the positive control's model {good_model_name!r} to be listed"
    bad_model_name = f"{bad_name}-model"
    assert bad_model_name not in names, f"expected no asset model named {bad_model_name!r} after the rollback"


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
