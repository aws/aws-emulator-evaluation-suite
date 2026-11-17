"""cfn-logs-loggroup-deletion-protection-blocks-stack-delete-then-update-or-live-flip-allows-it."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-logs-loggroup-deletion-protection-blocks-stack-delete-then-update-or-live-flip-allows-it"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

_DEADLINE_S = 600.0

_BLOCKED_DELETE = (
    'Resource handler returned message: "Invalid request provided: AWS::Logs::LogGroup" '
    "(RequestToken: <token>, HandlerErrorCode: InvalidRequest)"
)
_CANNOT_UPDATE_DELETE_FAILED = "Stack:{stack_id} is in DELETE_FAILED state and can not be updated."


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:data-plane", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """DeleteStack on a log group with DeletionProtectionEnabled ends DELETE_FAILED with the
    group intact and protected, and UpdateStack is then refused; a twin stack flips protection
    off via UpdateStack and deletes cleanly, and unprotecting the live group lets it retry.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/protecting-log-groups-from-deletion.html
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    ok_name = ctx.unique_name("sim2real-behav-cfnlgdp-ok-")
    ok_id = _create(ctx, logs, cfn, ok_name, _template(ok_name, True))

    name = ctx.unique_name("sim2real-behav-cfnlgdp-")
    stack_id = _create(ctx, logs, cfn, name, _template(name, True))

    for sid, gname in ((ok_id, ok_name), (stack_id, name)):
        assert _settle(cfn, sid) == "CREATE_COMPLETE", f"create ended {_stack(cfn, sid)!r}"
        group = _log_group(logs, gname)
        assert group is not None and group["deletionProtectionEnabled"] is True, (
            f"the template sets DeletionProtectionEnabled: true; live group is {group!r}"
        )

    # Control: flip protection off through UpdateStack, then DeleteStack succeeds.
    cfn.update_stack(StackName=ok_id, TemplateBody=_template(ok_name, False))
    assert _settle(cfn, ok_id) == "UPDATE_COMPLETE", f"update ended {_stack(cfn, ok_id)!r}"
    flipped = _log_group(logs, ok_name)
    assert flipped is not None and flipped["deletionProtectionEnabled"] is False, (
        f"UpdateStack must reach the live group; got {flipped!r}"
    )
    cfn.delete_stack(StackName=ok_id)
    assert _settle(cfn, ok_id) == "DELETE_COMPLETE", f"control delete ended {_stack(cfn, ok_id)!r}"
    assert _log_group(logs, ok_name) is None, "the deleted control group must be gone"

    # The protected stack: DeleteStack is blocked.
    cfn.delete_stack(StackName=stack_id)
    assert _settle(cfn, stack_id) == "DELETE_FAILED", f"blocked delete ended {_stack(cfn, stack_id)!r}"
    rows = [
        (e["ResourceStatus"], _masked(e.get("ResourceStatusReason") or ""))
        for e in _events(cfn, stack_id)
        if e["LogicalResourceId"] == "Group" and e["ResourceStatus"] == "DELETE_FAILED"
    ]
    assert rows == [("DELETE_FAILED", _BLOCKED_DELETE)], (
        f"the blocked delete's reason must name the handler's generic rejection; got {rows!r}"
    )
    still = _log_group(logs, name)
    assert still is not None and still["deletionProtectionEnabled"] is True, (
        f"the blocked delete must leave the group intact and protected; got {still!r}"
    )

    err = _client_error(lambda: cfn.update_stack(StackName=stack_id, TemplateBody=_template(name, False)))
    assert err.get("Code") == "ValidationError", (
        f"UpdateStack on a DELETE_FAILED stack must be refused with ValidationError; got "
        f"{err.get('Code')!r}: {err.get('Message')!r}"
    )
    assert err.get("Message") == _CANNOT_UPDATE_DELETE_FAILED.format(stack_id=stack_id), (
        f"the refusal must name the DELETE_FAILED state; got {err.get('Message')!r}"
    )

    # Recovery the way a customer must: flip protection directly on the live resource, then
    # retry DeleteStack.
    logs.put_log_group_deletion_protection(logGroupIdentifier=name, deletionProtectionEnabled=False)
    unprotected = _log_group(logs, name)
    assert unprotected is not None and unprotected["deletionProtectionEnabled"] is False, (
        f"the direct flip must reach the live group; got {unprotected!r}"
    )
    cfn.delete_stack(StackName=stack_id)
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "DELETE_COMPLETE", (
        f"with protection off the retried delete must succeed; got {_stack(cfn, stack_id)!r}"
    )
    assert _log_group(logs, name) is None, "the deleted group must be gone from CloudWatch Logs"


def _masked(text: str) -> str:
    """``text`` with only its per-call RequestToken replaced."""
    return re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)


def _template(name: str, protected: bool) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": name, "DeletionProtectionEnabled": protected},
            },
        },
    })


def _log_group(logs, name: str) -> dict | None:
    """The log group's own description by exact name, or None if it does not exist."""
    matches = [
        g
        for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name)
        for g in page["logGroups"]
        if g["logGroupName"] == name
    ]
    return matches[0] if matches else None


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _cap(ctx, own_s: float, margin_s: float = 15.0) -> float:
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
    return _poll(
        lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
        timeout_s=timeout_s, what=f"stack {stack_id} settled",
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _force_teardown(logs, cfn, stack_id: str, name: str) -> None:
    """Undo the stack whatever state it was abandoned in: unprotect the live group first,
    then delete the stack; a failure raises."""
    deadline = time.monotonic() + _DEADLINE_S
    while time.monotonic() < deadline:
        group = _log_group(logs, name)
        if group is None:
            break
        if group.get("deletionProtectionEnabled"):
            logs.put_log_group_deletion_protection(
                logGroupIdentifier=name, deletionProtectionEnabled=False
            )
        status = _stack(cfn, stack_id)["StackStatus"]
        if status.endswith("_IN_PROGRESS"):
            time.sleep(3.0)
            continue
        if status != "DELETE_COMPLETE":
            cfn.delete_stack(StackName=stack_id)
        time.sleep(3.0)
    group = _log_group(logs, name)
    if group is not None:
        raise RuntimeError(f"log group {name!r} still exists after teardown: {group!r}")
    status = _stack(cfn, stack_id)["StackStatus"]
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id!r} ended {status!r}, not DELETE_COMPLETE")


def _create(ctx, logs, cfn, name: str, body: str) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=body, Tags=[{"Key": "sim2real", "Value": name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _force_teardown(logs, cfn, stack_id, name))
    return stack_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
