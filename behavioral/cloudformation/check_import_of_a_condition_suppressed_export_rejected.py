"""import-of-a-condition-suppressed-export-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'import-of-a-condition-suppressed-export-rejected'
GROUP = 'stack_exports'
SERVICES = ['cloudformation']

_SETTLED = (
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
)

_PRODUCER = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {"Publish": {"Type": "String", "AllowedValues": ["yes", "no"]}},
    "Conditions": {"Publishing": {"Fn::Equals": [{"Ref": "Publish"}, "yes"]}},
    "Resources": {
        "Marker": {
            "Type": "AWS::SSM::Parameter",
            "Properties": {"Type": "String", "Value": {"Fn::Sub": "${AWS::StackName}-marker"}},
        }
    },
    "Outputs": {},
}


def _producer_body(export: str) -> str:
    """The producer template whose single output, and its export, hang off the condition."""
    doc = json.loads(json.dumps(_PRODUCER))
    doc["Outputs"]["MarkerName"] = {
        "Condition": "Publishing",
        "Value": {"Ref": "Marker"},
        "Export": {"Name": export},
    }
    return json.dumps(doc)


def _consumer_body(export: str) -> str:
    """The consumer template: one parameter fed by Fn::ImportValue, echoed as an output."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Echo": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Type": "String", "Value": {"Fn::ImportValue": export}},
            }
        },
        "Outputs": {"Imported": {"Value": {"Fn::ImportValue": export}}},
    })


def _describe(cf, stack: str):
    """The stack's description, or None once CloudFormation has stopped indexing its name."""
    try:
        return cf.describe_stacks(StackName=stack)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return None
        raise


def _settle(cf, stack: str, *, budget_s: float = 420.0) -> dict:
    """Poll until the stack reports a settled status; raise when the budget runs out."""
    deadline = time.monotonic() + budget_s
    seen = None
    while True:
        described = _describe(cf, stack)
        seen = None if described is None else described["StackStatus"]
        if described is not None and seen in _SETTLED:
            return described
        if described is None:
            raise AssertionError(f"stack {stack!r} vanished while settling, last status {seen!r}")
        if time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack!r} still at {seen!r} after {budget_s}s, no settled status reached"
            )
        time.sleep(3)


def _settle_gone(cf, stack: str, *, budget_s: float = 420.0) -> None:
    """Poll until the stack name is no longer indexed; raise when the budget runs out."""
    deadline = time.monotonic() + budget_s
    while _describe(cf, stack) is not None:
        if time.monotonic() > deadline:
            described = _describe(cf, stack)
            seen = None if described is None else described["StackStatus"]
            raise AssertionError(f"stack {stack!r} still readable after {budget_s}s at {seen!r}")
        time.sleep(3)


def _teardown(cf, stack: str):
    """A cleanup that deletes the stack and waits for it; a failed delete raises."""

    def undo() -> None:
        try:
            cf.delete_stack(StackName=stack)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                return
            raise
        _settle_gone(cf, stack)

    return undo


def _exported_names(cf) -> set:
    """Every export name the account currently holds in this region."""
    names = set()
    token = None
    while True:
        page = cf.list_exports(**({"NextToken": token} if token else {}))
        names.update(e["Name"] for e in page.get("Exports", []))
        token = page.get("NextToken")
        if not token:
            return names


def _outputs(described: dict) -> dict:
    """The stack's outputs as a key -> value mapping."""
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _own_event_reasons(cf, stack: str) -> list:
    """Every status reason the stack's own events carry, newest first."""
    pages = cf.get_paginator("describe_stack_events").paginate(StackName=stack)
    return [
        event.get("ResourceStatusReason")
        for page in pages
        for event in page["StackEvents"]
        if event["LogicalResourceId"] == stack
    ]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A false output Condition publishes no export, so a stack importing that name rolls
    back and builds nothing; flipping the condition true lets the same template import it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/outputs-section-structure.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/intrinsic-function-reference-importvalue.html
    """
    cf = ctx.client("cloudformation")
    export = ctx.unique_name("sim2real-behav-cfnexport-")
    producer = ctx.unique_name("sim2real-behav-cfnproducer-")
    consumer = ctx.unique_name("sim2real-behav-cfnconsumer-")

    cf.create_stack(
        StackName=producer,
        TemplateBody=_producer_body(export),
        Parameters=[{"ParameterKey": "Publish", "ParameterValue": "no"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(cf, producer))
    settled = _settle(cf, producer)
    assert settled["StackStatus"] == "CREATE_COMPLETE", (
        f"producer stack settled at {settled['StackStatus']!r}, expected CREATE_COMPLETE"
        f" ({settled.get('StackStatusReason')!r})"
    )

    suppressed = _outputs(settled)
    assert suppressed == {}, (
        f"the output guarded by a false condition still resolved: {suppressed!r}, expected none"
    )
    assert export not in _exported_names(cf), (
        f"export {export!r} is listed although the output carrying it was conditioned away"
    )

    cf.create_stack(
        StackName=consumer,
        TemplateBody=_consumer_body(export),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(cf, consumer))
    refused = _settle(cf, consumer)
    assert refused["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"importing an unpublished export settled at {refused['StackStatus']!r},"
        f" expected ROLLBACK_COMPLETE ({refused.get('StackStatusReason')!r})"
    )
    reasons = _own_event_reasons(cf, consumer)
    assert f"No export named {export} found. Rollback requested by user." in reasons, (
        f"the rolled back stack reported {reasons!r}"
    )
    assert _outputs(refused) == {}, (
        f"the rolled back stack published outputs {_outputs(refused)!r}, expected none"
    )
    built = {
        r["LogicalResourceId"]: r["ResourceStatus"]
        for r in cf.describe_stack_resources(StackName=consumer)["StackResources"]
    }
    assert "CREATE_COMPLETE" not in built.values(), (
        f"the rolled back stack left a built resource behind: {built!r}"
    )

    cf.update_stack(
        StackName=producer,
        TemplateBody=_producer_body(export),
        Parameters=[{"ParameterKey": "Publish", "ParameterValue": "yes"}],
    )
    published = _settle(cf, producer)
    assert published["StackStatus"] == "UPDATE_COMPLETE", (
        f"publishing update settled at {published['StackStatus']!r}, expected UPDATE_COMPLETE"
        f" ({published.get('StackStatusReason')!r})"
    )
    exported_value = _outputs(published).get("MarkerName")
    assert exported_value, (
        f"the condition is true now, yet the stack's outputs are {_outputs(published)!r}"
    )
    assert export in _exported_names(cf), (
        f"export {export!r} is still unlisted after the condition that guards it became true"
    )

    cf.delete_stack(StackName=consumer)
    _settle_gone(cf, consumer)
    cf.create_stack(
        StackName=consumer,
        TemplateBody=_consumer_body(export),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(cf, consumer))
    accepted = _settle(cf, consumer)
    assert accepted["StackStatus"] == "CREATE_COMPLETE", (
        f"the same import settled at {accepted['StackStatus']!r} once the export existed,"
        f" expected CREATE_COMPLETE ({accepted.get('StackStatusReason')!r})"
    )
    imported = _outputs(accepted).get("Imported")
    assert imported == exported_value, (
        f"the consumer imported {imported!r}, but the producer exports {exported_value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
