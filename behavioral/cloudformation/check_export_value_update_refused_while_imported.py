"""export-value-update-refused-while-imported."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-value-update-refused-while-imported"
GROUP = "ordering"
SERVICES = ["cloudformation"]

STACK_TIMEOUT_S = 240.0
REGISTER_TIMEOUT_S = 180.0
DEREGISTER_TIMEOUT_S = 180.0
_UPDATE_TERMINAL = {
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An exported Output value cannot be CHANGED while another stack imports it; an update that
    leaves the export alone still succeeds, and the change lands once the importer is gone."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    tag = [{"Key": "sim2real-check", "Value": CHECK}]

    export_name = ctx.unique_name("sim2real-cfn-updexport-")
    exporter = ctx.unique_name("sim2real-cfn-updexporter-")
    importer = ctx.unique_name("sim2real-cfn-updimporter-")
    shared_v1 = ctx.unique_name("shared-v1-")
    shared_v2 = ctx.unique_name("shared-v2-")
    bystander_v1 = ctx.unique_name("bystander-v1-")
    bystander_v2 = ctx.unique_name("bystander-v2-")

    exporter_id = cfn.create_stack(
        StackName=exporter,
        TemplateBody=_exporter_template(export_name),
        Parameters=_params(Shared=shared_v1, Bystander=bystander_v1),
        Tags=tag,
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_exporter(cfn, exporter_id, export_name))
    _require_status(cfn, exporter, "CREATE_COMPLETE", {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"})

    exported = _export_value(cfn, export_name)
    assert exported == shared_v1, f"export {export_name!r}: expected {shared_v1!r}, got {exported!r}"

    importer_id = cfn.create_stack(
        StackName=importer, TemplateBody=_importer_template(export_name), Tags=tag
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, importer_id))
    _require_status(cfn, importer, "CREATE_COMPLETE", {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"})

    # Read through SNS, not CloudFormation: the imported value reached the consuming resource.
    consumer_topic = _physical_id(cfn, importer, "Consumer")
    consumer_display = _display_name(sns, consumer_topic)
    assert consumer_display == shared_v1, (
        f"importer's topic DisplayName: expected the imported export value {shared_v1!r}, got "
        f"{consumer_display!r}; the Fn::ImportValue never reached the resource"
    )
    _await_import_registered(cfn, export_name, importer)

    # Positive control: without it, a refused export change is indistinguishable from a stack that
    # refuses every update.
    control = _update(
        cfn, exporter, _exporter_template(export_name), Shared=shared_v1, Bystander=bystander_v2
    )
    assert control["outcome"] == "UPDATE_COMPLETE", (
        f"positive control: an update changing only the NON-exported parameter must reach "
        f"UPDATE_COMPLETE, got {control['outcome']!r} / {control['evidence']!r}"
    )
    exporter_topic = _physical_id(cfn, exporter, "Marker")
    assert _display_name(sns, exporter_topic) == bystander_v2, (
        f"positive control: exporter topic DisplayName should be {bystander_v2!r} after the "
        f"control update, got {_display_name(sns, exporter_topic)!r}"
    )

    refused = _update(
        cfn, exporter, _exporter_template(export_name), Shared=shared_v2, Bystander=bystander_v2
    )
    expected_refusal = {
        "outcome": "UPDATE_ROLLBACK_COMPLETE",
        "evidence": f"Update canceled. Cannot update export {export_name} as it is in use by {importer}.",
    }
    assert refused == expected_refusal, (
        f"changing export {export_name!r} while {importer!r} imports it must be rolled back as "
        f"{expected_refusal!r}, got {refused!r}"
    )

    still = _export_value(cfn, export_name)
    assert still == shared_v1, (
        f"export {export_name!r} must still hold the pre-update value {shared_v1!r} after the "
        f"refused update, got {still!r}"
    )
    assert _display_name(sns, consumer_topic) == shared_v1, (
        f"consumer topic DisplayName must be unchanged at {shared_v1!r} after the refused update, "
        f"got {_display_name(sns, consumer_topic)!r}"
    )

    cfn.delete_stack(StackName=importer)
    _await_gone(cfn, importer_id)
    _await_import_cleared(cfn, export_name, importer)

    restored = _update(
        cfn, exporter, _exporter_template(export_name), Shared=shared_v2, Bystander=bystander_v2
    )
    assert restored["outcome"] == "UPDATE_COMPLETE", (
        f"once no stack imports {export_name!r} the identical update must succeed, got "
        f"{restored['outcome']!r} / {restored['evidence']!r}"
    )
    final = _export_value(cfn, export_name)
    assert final == shared_v2, (
        f"export {export_name!r}: expected the new value {shared_v2!r} after the unblocked update, "
        f"got {final!r}"
    )


def _exporter_template(export_name: str) -> str:
    """Exports one parameter as an Output; a second, non-exported parameter drives an SNS
    DisplayName so the control update has an effect observable outside CloudFormation."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"Shared": {"Type": "String"}, "Bystander": {"Type": "String"}},
            "Resources": {
                "Marker": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": {"Ref": "Bystander"}}}
            },
            "Outputs": {"Exported": {"Value": {"Ref": "Shared"}, "Export": {"Name": export_name}}},
        }
    )


def _importer_template(export_name: str) -> str:
    """Consumes the export inside a RESOURCE property, so the imported value is observable at the
    consuming service and the import is unambiguously registered."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Consumer": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"DisplayName": {"Fn::ImportValue": export_name}},
                }
            },
        }
    )


def _params(**kwargs: str) -> list[dict]:
    return [{"ParameterKey": k, "ParameterValue": v} for k, v in kwargs.items()]


def _status(cfn, stack_name: str) -> str:
    """The stack's status, or "GONE" when DescribeStacks says it does not exist."""
    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ValidationError":
            return "GONE"
        raise


def _poll_status(cfn, stack_name: str, terminal: set[str], *, timeout_s: float, why: str) -> str:
    """Poll until a terminal status; raises on timeout rather than returning the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _status(cfn, stack_name)
        if last in terminal:
            return last
        time.sleep(4.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach any of {sorted(terminal)!r} within {timeout_s}s "
        f"[{why}] (last={last!r})"
    )


def _require_status(cfn, stack_name: str, expected: str, terminal: set[str]) -> None:
    got = _poll_status(cfn, stack_name, terminal, timeout_s=STACK_TIMEOUT_S, why="prerequisite create")
    assert got == expected, f"stack {stack_name!r}: expected {expected!r}, got {got!r}"


def _update(cfn, stack_name: str, template: str, **params: str) -> dict:
    """UpdateStack, returning {"outcome", "evidence"}: the terminal status and, for a rollback, the
    reason on the stack's own UPDATE_ROLLBACK_IN_PROGRESS event; a synchronous error is returned as
    its code and message so the assertion names it."""
    try:
        cfn.update_stack(StackName=stack_name, TemplateBody=template, Parameters=_params(**params))
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"outcome": err.get("Code", "<no code>"), "evidence": err.get("Message", "<no message>")}
    status = _poll_status(
        cfn, stack_name, _UPDATE_TERMINAL, timeout_s=STACK_TIMEOUT_S, why="update terminal"
    )
    if status == "UPDATE_ROLLBACK_COMPLETE":
        return {"outcome": status, "evidence": _event_reason(cfn, stack_name)}
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {"outcome": status, "evidence": stack.get("StackStatusReason")}


def _event_reason(cfn, stack_name: str) -> str:
    """The reason on the stack's most recent stack-level UPDATE_ROLLBACK_IN_PROGRESS event."""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        for event in page["StackEvents"]:
            if (event.get("ResourceType") == "AWS::CloudFormation::Stack"
                    and event.get("ResourceStatus") == "UPDATE_ROLLBACK_IN_PROGRESS"):
                return event.get("ResourceStatusReason") or "<empty reason>"
    return "<no stack-level UPDATE_ROLLBACK_IN_PROGRESS event>"


def _export_value(cfn, export_name: str) -> str:
    for page in cfn.get_paginator("list_exports").paginate():
        for export in page["Exports"]:
            if export["Name"] == export_name:
                return export["Value"]
    raise AssertionError(f"ListExports does not contain {export_name!r}; expected exactly one entry")


def _await_import_registered(cfn, export_name: str, importer: str) -> None:
    """The cross-stack import index is updated asynchronously relative to the importer's
    CREATE_COMPLETE; the refusal under test is keyed off that index, so wait for it."""
    deadline = time.monotonic() + REGISTER_TIMEOUT_S
    last: list[str] = []
    while time.monotonic() < deadline:
        last = _importers(cfn, export_name)
        if importer in last:
            return
        time.sleep(4.0)
    raise AssertionError(
        f"ListImports({export_name!r}) never listed {importer!r} within {REGISTER_TIMEOUT_S}s "
        f"(last={last!r}); the export-in-use guard has nothing to key off"
    )


def _await_import_cleared(cfn, export_name: str, importer: str) -> None:
    deadline = time.monotonic() + DEREGISTER_TIMEOUT_S
    last: list[str] = []
    while time.monotonic() < deadline:
        last = _importers(cfn, export_name)
        if importer not in last:
            return
        time.sleep(4.0)
    raise AssertionError(
        f"ListImports({export_name!r}) still lists the deleted stack {importer!r} after "
        f"{DEREGISTER_TIMEOUT_S}s (last={last!r})"
    )


def _await_gone(cfn, stack_id: str) -> None:
    """Poll the deleted stack by StackId, which keeps answering after the delete completes."""
    got = _poll_status(
        cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, timeout_s=STACK_TIMEOUT_S,
        why="importer delete",
    )
    assert got == "DELETE_COMPLETE", f"stack {stack_id!r}: expected DELETE_COMPLETE, got {got!r}"


def _physical_id(cfn, stack_name: str, logical_id: str) -> str:
    detail = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId=logical_id)
    return detail["StackResourceDetail"]["PhysicalResourceId"]


def _display_name(sns, topic_arn: str) -> str:
    attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert "DisplayName" in attrs, (
        f"topic {topic_arn!r} has no DisplayName attribute; got {sorted(attrs)!r}"
    )
    return attrs["DisplayName"]


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


def _importers(cfn, export_name: str) -> list[str]:
    """The stack names ListImports reports for the export; the not-imported and no-such-export
    refusals are []."""
    try:
        return [name for page in cfn.get_paginator("list_imports").paginate(ExportName=export_name)
                for name in page.get("Imports", [])]
    except ClientError as exc:
        err = exc.response["Error"]
        if err.get("Code") == "ValidationError" and err.get("Message") in (
            f"Export '{export_name}' is not imported by any stack.",
            f"Export '{export_name}' does not exist.",
        ):
            return []
        raise


def _teardown_exporter(cfn, exporter_id: str, export_name: str, *, timeout_s: float = 600.0) -> None:
    """Once ListImports names no importer, delete the exporter by StackId, re-issuing a canceled
    DeleteStack, until DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    if cfn.describe_stacks(StackName=exporter_id)["Stacks"][0]["StackStatus"] == "DELETE_COMPLETE":
        return
    deadline = time.monotonic() + timeout_s
    while True:
        if not _importers(cfn, export_name):
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"export {export_name} still imported {timeout_s}s into teardown")
        time.sleep(5.0)
    issued_from = None
    seen_progress = False
    reissue_at = 0.0
    while True:
        stack = cfn.describe_stacks(StackName=exporter_id)["Stacks"][0]
        status = stack["StackStatus"]
        seen_progress = seen_progress or status == "DELETE_IN_PROGRESS"
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and issued_from is not None and (
            issued_from != "DELETE_FAILED" or seen_progress
        ):
            raise AssertionError(
                f"stack {exporter_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}"
            )
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {exporter_id} still {status} {timeout_s}s into teardown")
        if not status.endswith("_IN_PROGRESS") and (
            issued_from is None or (not status.startswith("DELETE_") and time.monotonic() >= reissue_at)
        ):
            issued_from, seen_progress = status, False
            cfn.delete_stack(StackName=exporter_id)
            reissue_at = time.monotonic() + 20.0
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
