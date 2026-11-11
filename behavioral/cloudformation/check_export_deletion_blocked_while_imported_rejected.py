"""export-deletion-blocked-while-imported-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-deletion-blocked-while-imported-rejected"
GROUP = "ordering"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DeleteStack on a stack whose export another stack imports is accepted and then canceled with
    the export-in-use reason, leaving the stack CREATE_COMPLETE; once the importer is gone the same
    delete succeeds and ListExports omits the export."""
    cfn = ctx.client("cloudformation")
    export_name = ctx.unique_name("sim2real-cfn-lockexport-")
    exporter = ctx.unique_name("sim2real-cfn-lockexporter-")
    importer = ctx.unique_name("sim2real-cfn-lockimporter-")

    exporter_tmpl = json.dumps(
        {
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": "locked"}}},
            "Outputs": {"ExportedValue": {"Value": "locked-value", "Export": {"Name": export_name}}},
        }
    )
    exporter_id = cfn.create_stack(
        StackName=exporter, TemplateBody=exporter_tmpl, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_exporter(cfn, exporter_id, export_name))
    _wait_for_stack_status(cfn, exporter, {"CREATE_COMPLETE", "CREATE_FAILED"}, 300)
    exporter_status = cfn.describe_stacks(StackName=exporter)["Stacks"][0]["StackStatus"]
    assert exporter_status == "CREATE_COMPLETE", f"exporter must reach CREATE_COMPLETE, got {exporter_status}"

    importer_tmpl = json.dumps(
        {
            "Resources": {
                "Topic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"DisplayName": {"Fn::ImportValue": export_name}},
                }
            }
        }
    )
    importer_id = cfn.create_stack(
        StackName=importer, TemplateBody=importer_tmpl, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, importer_id))
    _wait_for_stack_status(cfn, importer, {"CREATE_COMPLETE", "CREATE_FAILED"}, 300)
    importer_status = cfn.describe_stacks(StackName=importer)["Stacks"][0]["StackStatus"]
    assert importer_status == "CREATE_COMPLETE", f"importer must reach CREATE_COMPLETE, got {importer_status}"

    # CloudFormation's cross-stack Exports/Imports index is updated asynchronously
    # relative to the importer's CREATE_COMPLETE -- calling DeleteStack on the
    # exporter before the index reflects the new import can let the delete succeed
    # (the export-in-use guard hasn't "seen" the import yet). Poll ListImports for
    # the export until the importer shows up before attempting the delete.
    import_registered = _wait_for_import_registered(cfn, export_name, importer, 300)
    assert import_registered, (
        f"ListImports never showed {importer} consuming {export_name} within 300s -- "
        "the delete below would not be testing the race it exists to test"
    )

    # cleanups are LIFO: importer's delete_stack (registered last) runs first, THEN
    # exporter's (registered first) -- exactly the order real usage requires, since the
    # exporter cannot be deleted while its export is still imported. They are a
    # fallback teardown for the early-exit paths below; the restore leg at the end of
    # this function performs and ASSERTS the same deletes as part of the check itself.

    # CloudFormation accepts the DeleteStack call, then cancels the delete on the export
    # in use without ever moving the stack off CREATE_COMPLETE: the StatusReason names the
    # export and the importer, and the exporter's resources (and its export) are left intact.
    cfn.delete_stack(StackName=exporter)
    expected = (
        "CREATE_COMPLETE",
        f"Delete canceled. Cannot delete export {export_name} as it is in use by {importer}.",
    )
    got = _wait_for_delete_outcome(cfn, exporter_id, 300)
    assert got == expected, (
        f"deleting a stack whose export is still imported must settle as {expected!r}, got {got!r}"
    )

    # Restore leg: a target that just refuses every DeleteStack on an exporting stack
    # would pass everything above. Remove the importer, wait for CloudFormation's
    # cross-stack index to drop it, then retry the byte-identical DeleteStack call and
    # demand it actually succeeds -- that is what proves the earlier refusal was the
    # import and not some other blocker.
    cfn.delete_stack(StackName=importer)
    importer_end = _wait_for_stack_deleted(cfn, importer_id, 300)
    assert importer_end == "DELETE_COMPLETE", (
        f"importer stack {importer} should delete cleanly once it no longer blocks anything, "
        f"ended {importer_end!r}"
    )
    assert _wait_for_import_deregistered(cfn, export_name, importer, 300), (
        f"ListImports still names {importer} for {export_name} 300s after it was deleted"
    )

    cfn.delete_stack(StackName=exporter)
    exporter_end = _wait_for_stack_deleted(cfn, exporter_id, 300)
    assert exporter_end == "DELETE_COMPLETE", (
        f"deleting the exporter {exporter} must succeed once its export is no longer imported, "
        f"ended {exporter_end!r}"
    )

    exports_after = cfn.list_exports().get("Exports", [])
    assert not any(e["Name"] == export_name for e in exports_after), (
        "a deleted stack's export must no longer be listed once the stack is gone"
    )


def _wait_for_import_registered(cfn, export_name, importer_stack_name, timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if importer_stack_name in _importers(cfn, export_name):
            return True
        time.sleep(4)
    return False


def _wait_for_import_deregistered(cfn, export_name, importer_stack_name, timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if importer_stack_name not in _importers(cfn, export_name):
            return True
        time.sleep(4)
    return False


def _wait_for_stack_deleted(cfn, stack_id, timeout_s):
    """Poll DescribeStacks by StackId until DELETE_COMPLETE or DELETE_FAILED; return that status."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(4)


def _wait_for_delete_outcome(cfn, stack_id, timeout_s):
    """`(status, reason)` once the delete has an outcome: a StackStatusReason on the CREATE_COMPLETE
    stack, or any status other than CREATE_COMPLETE and DELETE_IN_PROGRESS."""
    deadline = time.monotonic() + timeout_s
    got = ("never read", None)
    while time.monotonic() < deadline:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        got = (stack["StackStatus"], stack.get("StackStatusReason"))
        if got[0] not in ("CREATE_COMPLETE", "DELETE_IN_PROGRESS") or (
            got[0] == "CREATE_COMPLETE" and got[1]
        ):
            return got
        time.sleep(2)
    raise AssertionError(f"the delete of {stack_id} had no outcome within {timeout_s}s: {got!r}")


def _wait_for_stack_status(cfn, stack_name, terminal_statuses, timeout_s):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal_statuses:
            return status
        time.sleep(4)
    return status


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
