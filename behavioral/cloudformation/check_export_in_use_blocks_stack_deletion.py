"""export-in-use-blocks-stack-deletion."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-in-use-blocks-stack-deletion"
GROUP = 'stack_outputs'
SERVICES = ['cloudformation']


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _timed_out(ctx, what, timeout_s, last):
    """The error a capped wait ends with: not graded when the run budget ended it, else a failure."""
    if _budget_spent(ctx):
        return TimeoutError(f"{what}: the run budget ended first; not graded")
    return AssertionError(f"{what} within {timeout_s}s (last={last!r})")


def _describe_stack(cf, name):
    stacks = cf.describe_stacks(StackName=name).get("Stacks", [])
    return stacks[0] if stacks else None

def _exports(cf):
    """Every export ListExports reports in the region, across pages."""
    return [e for page in cf.get_paginator("list_exports").paginate() for e in page.get("Exports", [])]

def _wait_stack(ctx, cf, name, targets, timeout_s=180):
    """Poll DescribeStacks until StackStatus is in `targets`; return the stack dict."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    stack = None
    while time.monotonic() < deadline:
        stack = _describe_stack(cf, name)
        if stack is not None and stack.get("StackStatus") in targets:
            return stack
        time.sleep(2)
    raise _timed_out(ctx, f"stack {name} reaching {targets}", timeout_s, stack)

def _wait_stack_deleted(ctx, cf, stack_id, timeout_s=180):
    """Poll DescribeStacks by StackId until DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = _describe_stack(cf, stack_id)["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_id} delete ended {status!r}")
        if time.monotonic() > deadline:
            raise _timed_out(ctx, f"stack {stack_id} reaching DELETE_COMPLETE", timeout_s, status)
        time.sleep(2)

def _wait_delete_outcome(ctx, cf, stack_id, timeout_s):
    """`(status, reason)` once the delete has an outcome: a StackStatusReason on the CREATE_COMPLETE
    stack, or any status other than CREATE_COMPLETE and DELETE_IN_PROGRESS."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    got = ("never read", None)
    while time.monotonic() < deadline:
        stack = _describe_stack(cf, stack_id)
        got = (stack["StackStatus"], stack.get("StackStatusReason"))
        if got[0] not in ("CREATE_COMPLETE", "DELETE_IN_PROGRESS") or (
            got[0] == "CREATE_COMPLETE" and got[1]
        ):
            return got
        time.sleep(2)
    raise _timed_out(ctx, f"the delete of {stack_id} having an outcome", timeout_s, got)

def _wait_import_deregistered(ctx, cf, export_name, importer_name, timeout_s=300):
    """True once ListImports no longer names the importer; False when the wait's own deadline ends
    first, and a run budget that ends it first raises not graded."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if importer_name not in _importers(cf, export_name):
            return True
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"ListImports dropping {importer_name}: the run budget ended first; not graded")
    return False

def _delete_exporter_after_import_dropped(ctx, cf, exporter_id, timeout_s=300):
    """DeleteStack the exporter by StackId, re-issued while the import index still cancels it;
    return DELETE_COMPLETE or DELETE_FAILED."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status, reissue_at = None, 0.0
    while True:
        if (status is None or not status.startswith("DELETE_")) and time.monotonic() >= reissue_at:
            cf.delete_stack(StackName=exporter_id)
            reissue_at = time.monotonic() + 6.0
        time.sleep(2)
        status = _describe_stack(cf, exporter_id)["StackStatus"]
        if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
            return status
        if time.monotonic() > deadline:
            raise _timed_out(ctx, f"exporter {exporter_id} deleting", timeout_s, status)

def _export_template(export_name, value="sim2real-export-value"):
    return json.dumps(
        {
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
            "Outputs": {"ExportedValue": {"Value": value, "Export": {"Name": export_name}}},
        }
    )

def _import_template(export_name):
    return json.dumps(
        {
            "Resources": {
                "Topic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "Tags": [{"Key": "imported", "Value": {"Fn::ImportValue": export_name}}]
                    },
                }
            }
        }
    )


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DeleteStack on a stack whose export a live stack imports is accepted and then canceled with
    the export-in-use reason; once the importer is deleted, the exporter deletes and its export
    disappears from ListExports."""
    cf = ctx.client("cloudformation")
    export_name = ctx.unique_name("sim2real-behav-export-inuse-")
    exporter = ctx.unique_name("sim2real-behav-exporter-inuse-")
    importer = ctx.unique_name("sim2real-behav-importer-inuse-")

    exporter_id = cf.create_stack(
        StackName=exporter, TemplateBody=_export_template(export_name, "sim2real-value-1"))["StackId"]
    ctx.on_cleanup(lambda: _teardown_exporter(cf, exporter_id, export_name))
    _wait_stack(ctx, cf, exporter, {"CREATE_COMPLETE"})

    exports = _exports(cf)
    ours = [e for e in exports if e["Name"] == export_name]
    assert len(ours) == 1, ours
    assert ours[0]["Value"] == "sim2real-value-1"

    importer_id = cf.create_stack(StackName=importer, TemplateBody=_import_template(export_name))["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cf, importer_id))
    imported = _wait_stack(ctx, cf, importer, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})
    assert imported["StackStatus"] == "CREATE_COMPLETE", imported.get("StackStatusReason")

    # ListImports is eventually consistent relative to the importer's CREATE_COMPLETE.
    import_wait_s = _budget_s(ctx, 60)
    import_deadline = time.monotonic() + import_wait_s
    imports = []
    while time.monotonic() < import_deadline:
        imports = cf.list_imports(ExportName=export_name)["Imports"]
        if importer in imports:
            break
        time.sleep(2)
    if importer not in imports and _budget_spent(ctx):
        raise TimeoutError(f"ListImports naming {importer}: the run budget ended first; not graded")
    assert importer in imports, (
        f"{importer} never registered as an importer of {export_name}: {imports}"
    )

    # CloudFormation accepts the DeleteStack call, then cancels the delete on the export in
    # use without ever leaving CREATE_COMPLETE.
    cf.delete_stack(StackName=exporter)
    expected = (
        "CREATE_COMPLETE",
        f"Delete canceled. Cannot delete export {export_name} as it is in use by {importer}.",
    )
    got = _wait_delete_outcome(ctx, cf, exporter_id, timeout_s=120)
    assert got == expected, (
        f"deleting a stack whose export is still imported must settle as {expected!r}, got {got!r}"
    )

    cf.delete_stack(StackName=importer)
    _wait_stack_deleted(ctx, cf, importer_id)
    assert _wait_import_deregistered(ctx, cf, export_name, importer), (
        f"ListImports still names {importer} for {export_name} after it was deleted"
    )
    # The cross-stack import index catches up with the importer's deletion asynchronously;
    # a delete issued before it does is canceled again, so it is re-issued.
    exporter_end = _delete_exporter_after_import_dropped(ctx, cf, exporter_id)
    assert exporter_end == "DELETE_COMPLETE", f"exporter {exporter} delete ended {exporter_end!r}"

    exports_after = _exports(cf)
    assert not any(e["Name"] == export_name for e in exports_after), (
        "a deleted stack's export must not be listed"
    )


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
