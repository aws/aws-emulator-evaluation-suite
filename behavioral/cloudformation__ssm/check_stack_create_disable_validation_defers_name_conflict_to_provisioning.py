"""stack-create-disable-validation-defers-name-conflict-to-provisioning."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-create-disable-validation-defers-name-conflict-to-provisioning"
GROUP = "stack-create"
SERVICES = ["cloudformation", "ssm"]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A create naming an existing parameter stops in pre-deployment validation before provisioning;
    with DisableValidation the handler attempts it and fails, and SSM's value is untouched both times.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/validate-stack-deployments.html"""
    cfn, ssm = ctx.client("cloudformation"), ctx.client("ssm")
    taken = "/" + ctx.unique_name("sim2real-cfn-cval-")
    ssm.put_parameter(Name=taken, Value="outside", Type="String")
    ctx.on_cleanup(lambda: _delete_parameter(ssm, taken))

    validated = _create(ctx, cfn, ctx.unique_name("sim2real-cfn-cval-on-"), _template(taken))
    assert _settle(cfn, validated, timeout_s=_cap(ctx, _DEADLINE_S)) == "ROLLBACK_COMPLETE", f"validated create ended {_stack(cfn, validated)!r}"
    assert _of(_rows(_events(cfn, validated)), "Param") == [], (
        f"validation must stop the create before Param is provisioned: {_rows(_events(cfn, validated))!r}")
    found = _validation_errors(cfn, validated)
    assert found == [("Param", "AWS::SSM::Parameter", "NAME_CONFLICT_VALIDATION", "FAILED", "FAIL",
                      f"Resource of type 'AWS::SSM::Parameter' with identifier '{taken}' already exists.")], (
        f"validation errors of the create: {found!r}")

    attempted = _create(ctx, cfn, ctx.unique_name("sim2real-cfn-cval-off-"), _template(taken), DisableValidation=True)
    assert _settle(cfn, attempted, timeout_s=_cap(ctx, _DEADLINE_S)) == "ROLLBACK_COMPLETE", f"unvalidated create ended {_stack(cfn, attempted)!r}"
    rows = _of(_rows(_events(cfn, attempted)), "Param")
    statuses = [r[0] for r in rows]
    assert statuses == ["CREATE_IN_PROGRESS", "CREATE_FAILED", "DELETE_COMPLETE"], (
        f"Param event sequence with validation disabled: {statuses!r}; the resource handler attempt never "
        f"provisioned anything for rollback to delete, so there is no DELETE_IN_PROGRESS: {rows!r}")
    assert rows[0][1] is None and rows[2][1] is None, f"CREATE_IN_PROGRESS/DELETE_COMPLETE must carry no reason: {rows!r}"
    assert _create_failed_reason(taken).match(rows[1][1] or ""), (
        f"CREATE_FAILED reason does not match the handler's AlreadyExists message for {taken!r}: {rows[1][1]!r}")
    assert _validation_errors(cfn, attempted) == [], f"validation ran although disabled: {_validation_errors(cfn, attempted)!r}"

    assert ssm.get_parameter(Name=taken)["Parameter"]["Value"] == "outside", (
        f"neither create may touch the existing parameter: {ssm.get_parameter(Name=taken)['Parameter']!r}")


def _template(param: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Param": {"Type": "AWS::SSM::Parameter",
                                "Properties": {"Name": param, "Type": "String", "Value": "stack"}}},
    })


def _delete_parameter(ssm, name: str) -> None:
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


def _create_failed_reason(taken: str) -> re.Pattern:
    """The resource handler's AlreadyExists reason for ``taken``, its RequestToken graded by shape."""
    return re.compile(
        r"^Resource handler returned message: \"Resource of type 'AWS::SSM::Parameter' with identifier '"
        + re.escape(taken)
        + r"' already exists\.\" \(RequestToken: [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}, "
          r"HandlerErrorCode: AlreadyExists\)$")


def _validation_errors(cfn, stack_id: str) -> list[tuple]:
    """``(logical id, type, name, status, mode, reason)`` of each VALIDATION_ERROR operation event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_id}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend((e.get("LogicalResourceId"), e.get("ResourceType"), e.get("ValidationName"),
                    e.get("ValidationStatus"), e.get("ValidationFailureMode"), e.get("ValidationStatusReason"))
                   for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR")
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
