"""deploy-sagemaker-featuregroup-eventtimefeaturename-not-in-definitions-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sagemaker-featuregroup-eventtimefeaturename-not-in-definitions-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "sagemaker"]

# ---- CloudFormation helpers ----

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

_REJECTED = (
    "Invalid request provided: Validation Error: EventTimeFeatureName is not found in "
    "names of FeatureDefinitions.",
    "InvalidRequest",
)
_STACK_GONE = "Stack with id {} does not exist"


def _feature_group(name: str, event_time_feature_name: str) -> dict:
    return {
        "Type": "AWS::SageMaker::FeatureGroup",
        "Properties": {
            "FeatureGroupName": name,
            "RecordIdentifierFeatureName": "id",
            "EventTimeFeatureName": event_time_feature_name,
            "FeatureDefinitions": [
                {"FeatureName": "id", "FeatureType": "String"},
                {"FeatureName": "ts", "FeatureType": "String"},
            ],
            "OnlineStoreConfig": {"EnableOnlineStore": True},
        },
    }


def _template(name: str, event_time_feature_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"FeatureGroup": _feature_group(name, event_time_feature_name)},
        "Outputs": {"FeatureGroupRef": {"Value": {"Ref": "FeatureGroup"}}},
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::SageMaker::FeatureGroup whose EventTimeFeatureName is absent from
    FeatureDefinitions is rejected by SageMaker's own validation and the stack rolls back,
    leaving no feature group behind; the identical mechanism with a valid name still succeeds.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sagemaker-featuregroup.html
    """
    cf = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")
    bad_name = ctx.unique_name("sim2real-behav-fgbad-")
    bad_stack = ctx.unique_name("sim2real-behav-cfn-smbad-")

    bad_id = create_stack(ctx, cf, bad_stack, _template(bad_name, "not-a-declared-feature"))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"

    got = handler_reason(failed_reason(stack_events(cf, bad_id), "FeatureGroup"),
                         ctx.account, bad_name)
    assert got == _REJECTED, f"expected the masked failure reason {_REJECTED!r}, got {got!r}"

    # Absence, asserted before this check's own delete_stack: the rejected create never left a
    # feature group behind for SageMaker to show.
    bad_not_found = ("ResourceNotFound",
                     f"Resource Not Found: Amazon SageMaker can't find a FeatureGroup with name {bad_name}")
    expect_error(lambda: sm.describe_feature_group(FeatureGroupName=bad_name), *bad_not_found)

    delete_stack(cf, bad_id)
    # A deleted stack no longer resolves by name.
    stack_gone = ("ValidationError", _STACK_GONE.format(bad_stack))
    expect_error(lambda: cf.describe_stacks(StackName=bad_stack), *stack_gone)

    # Positive control: the identical mechanism, given a declared EventTimeFeatureName, succeeds
    # and SageMaker reads it back.
    good_name = ctx.unique_name("sim2real-behav-fggood-")
    good_stack = ctx.unique_name("sim2real-behav-cfn-smgood-")
    good_id = create_stack(ctx, cf, good_stack, _template(good_name, "ts"))
    good_status = wait_stack(cf, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}: "
        f"{decisive_rows(stack_events(cf, good_id))!r}"
    )
    good_ref = stack_outputs(cf, good_id)["FeatureGroupRef"]
    assert good_ref == good_name, f"Ref FeatureGroup was {good_ref!r}, expected {good_name!r}"
    control = sm.describe_feature_group(FeatureGroupName=good_name)
    assert control["EventTimeFeatureName"] == "ts", (
        f"expected the control feature group's EventTimeFeatureName 'ts', got "
        f"{control['EventTimeFeatureName']!r}"
    )
    assert control["FeatureGroupStatus"] == "Created", (
        f"expected the control feature group status 'Created', got {control['FeatureGroupStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
