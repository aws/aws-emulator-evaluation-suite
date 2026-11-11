"""stack-export-removal-while-imported-rolls-back-producer."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-export-removal-while-imported-rolls-back-producer"
GROUP = "exports"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An update dropping an export another stack imports rolls the producer back with the exact
    in-use reason and leaves the export and its importer intact; dropping an unused export works,
    and the identical update succeeds once the importer is gone.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-exports.html"""
    cfn = ctx.client("cloudformation")
    tok = ctx.unique_name("sim2real-cfn-exportrm-")
    used, spare, value = f"{tok}-used", f"{tok}-spare", f"{tok}-value"
    producer = cfn.create_stack(StackName=f"{tok}-producer", TemplateBody=_producer(used, spare, value),
                                Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _teardown_exporter(cfn, producer, used))
    assert _settle(cfn, producer, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"producer create: {_stack(cfn, producer)!r}"
    consumer_name = f"{tok}-consumer"
    consumer = _create(ctx, cfn, consumer_name, _consumer(used))
    assert _settle(cfn, consumer, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"consumer create: {_stack(cfn, consumer)!r}"

    # Positive control: an export nobody imports is dropped by an ordinary update.
    cfn.update_stack(StackName=producer, TemplateBody=_producer(used, None, value))
    assert _settle(cfn, producer, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_COMPLETE", f"dropping the unused export: {_stack(cfn, producer)!r}"
    assert _exports(cfn, tok) == {used: (producer, value)}, f"exports after the control: {_exports(cfn, tok)!r}"

    # ListImports is updated asynchronously relative to the importer's own CREATE_COMPLETE; the
    # refusal below is keyed off that index, so wait for it to actually name the consumer.
    _poll(lambda: _imports(cfn, used), lambda imps: consumer_name in imps,
          timeout_s=_cap(ctx, _DEADLINE_S), what=f"{used} import registration by {consumer_name}")

    before = len(_events(cfn, producer))
    cfn.update_stack(StackName=producer, TemplateBody=_producer(None, None, value))
    assert _settle(cfn, producer, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_COMPLETE", f"dropping the used export: {_stack(cfn, producer)!r}"
    stack_rows = _of(_rows(_events(cfn, producer)[before:]), _stack(cfn, producer)["StackName"])
    assert stack_rows == [
        ("UPDATE_IN_PROGRESS", "User Initiated"),
        ("UPDATE_ROLLBACK_IN_PROGRESS",
         f"Delete canceled. Cannot delete export {used} as it is in use by {consumer_name}."),
        ("UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS", None),
        ("UPDATE_ROLLBACK_COMPLETE", None),
    ], f"producer stack events of the refused update: {stack_rows!r}"

    assert _exports(cfn, tok) == {used: (producer, value)}, f"the export must survive: {_exports(cfn, tok)!r}"
    assert _imports(cfn, used) == [consumer_name], f"ListImports for {used!r}: {_imports(cfn, used)!r}"
    outputs = {o["OutputKey"]: o["OutputValue"] for o in _stack(cfn, producer).get("Outputs", [])}
    assert outputs == {"Plain": value, "Used": value}, f"producer outputs after the rollback: {outputs!r}"
    seen = {o["OutputKey"]: o["OutputValue"] for o in _stack(cfn, consumer).get("Outputs", [])}
    assert (_stack(cfn, consumer)["StackStatus"], seen) == ("CREATE_COMPLETE", {"Seen": value}), (
        f"the importer must be untouched: {_stack(cfn, consumer)!r}")

    # Restore leg: proves the rollback above was caused by the import, not by some other blocker.
    # Remove the importer, wait for CloudFormation's cross-stack index to drop it, then retry the
    # byte-identical update and demand it now succeeds.
    cfn.delete_stack(StackName=consumer)
    assert _settle(cfn, consumer, timeout_s=_cap(ctx, _DEADLINE_S)) == "DELETE_COMPLETE", f"consumer delete: {_stack(cfn, consumer)!r}"
    _poll(lambda: _imports(cfn, used), lambda imps: consumer_name not in imps,
          timeout_s=_cap(ctx, _DEADLINE_S), what=f"{used} import deregistration after deleting {consumer_name}")

    cfn.update_stack(StackName=producer, TemplateBody=_producer(None, None, value))
    assert _settle(cfn, producer, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_COMPLETE", (
        f"dropping {used!r} once nothing imports it: {_stack(cfn, producer)!r}")
    assert _exports(cfn, tok) == {}, f"exports after the unblocked removal: {_exports(cfn, tok)!r}"


def _producer(used: str | None, spare: str | None, value: str) -> str:
    outputs: dict = {"Plain": {"Value": value}}
    if used:
        outputs["Used"] = {"Value": value, "Export": {"Name": used}}
    if spare:
        outputs["Spare"] = {"Value": value, "Export": {"Name": spare}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09",
                       "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
                       "Outputs": outputs})


def _consumer(export: str) -> str:
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09",
                       "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
                       "Outputs": {"Seen": {"Value": {"Fn::ImportValue": export}}}})


def _exports(cfn, prefix: str) -> dict:
    """This check's exports: name -> (exporting stack id, value)."""
    return {e["Name"]: (e["ExportingStackId"], e["Value"])
            for page in cfn.get_paginator("list_exports").paginate() for e in page["Exports"]
            if e["Name"].startswith(prefix)}


def _imports(cfn, export: str) -> list[str]:
    """Stacks currently importing ``export``; ListImports raises ValidationError when there are none."""
    try:
        return [n for page in cfn.get_paginator("list_imports").paginate(ExportName=export)
                for n in page["Imports"]]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return []
        raise


# ===== helpers =====

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: A stack transition here takes seconds to a few minutes; the bound only stops a hung poll.
_DEADLINE_S = 600.0


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll(probe, done, *, timeout_s: float = _DEADLINE_S, interval_s: float = 3.0, what: str = "condition"):
    """Call ``probe()`` until ``done(result)`` holds and return the result; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(cfn, stack_id: str, timeout_s: float = _DEADLINE_S) -> str:
    """The stack's status once no operation is in progress on it."""
    return _poll(lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=timeout_s, what=f"stack {stack_id} settled")


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE by id; DELETE_FAILED or a timeout raises."""
    status = _stack(cfn, stack_id)["StackStatus"]
    if status == "UPDATE_IN_PROGRESS":
        cfn.cancel_update_stack(StackName=stack_id)
    if status != "CREATE_IN_PROGRESS":
        status = _settle(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _stack(cfn, stack_id)["StackStatus"],
                  lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}")


def _create(ctx, cfn, name: str, body: str, **kw) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(StackName=name, TemplateBody=body, Tags=_TAGS, **kw)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _rows(events: list[dict], *keys: str) -> list[tuple]:
    """``(LogicalResourceId, ResourceStatus, ResourceStatusReason, *keys)`` per event; absent is None."""
    return [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"),
             *(e.get(k) for k in keys)) for e in events]


def _of(rows: list[tuple], logical_id: str) -> list[tuple]:
    """The rows of one logical resource, without the logical id."""
    return [r[1:] for r in rows if r[0] == logical_id]


def _teardown_exporter(cfn, exporter_id: str, export_name: str, *, timeout_s: float = 600.0) -> None:
    """Once ListImports names no importer, delete the exporter by StackId, re-issuing a canceled
    DeleteStack, until DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    if cfn.describe_stacks(StackName=exporter_id)["Stacks"][0]["StackStatus"] == "DELETE_COMPLETE":
        return
    deadline = time.monotonic() + timeout_s
    while True:
        if not _imports(cfn, export_name):
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
