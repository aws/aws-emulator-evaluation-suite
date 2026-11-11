"""cfn-secretsmanager-secret-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-secretsmanager-secret-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "secretsmanager"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: Secrets Manager's refusal of a secret that no longer exists.
_NOT_FOUND = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")


def _template(secret_name: str, description: str, value: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Secret": {
                    "Type": "AWS::SecretsManager::Secret",
                    # Name is create-only, so changing it replaces the secret.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Name": secret_name,
                        "Description": description,
                        "SecretString": value,
                        "Tags": _TAGS,
                    },
                },
            },
            "Outputs": {"SecretArn": {"Value": {"Ref": "Secret"}}},
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation secret reads back as templated, updates in place and survives replacement.

    GetSecretValue serves the value; a value change keeps the secret, a Name change under
    UpdateReplacePolicy Retain keeps the old one readable; delete: ResourceNotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-secretsmanager-secret.html
    """
    cfn = ctx.client("cloudformation")
    sm = ctx.client("secretsmanager")
    first = ctx.unique_name("sim2real-cfnsec-a-")
    second = ctx.unique_name("sim2real-cfnsec-b-")
    stack_name = ctx.unique_name("sim2real-cfnsec-stack-")
    ref = {"stack": stack_name}
    v1, v2 = ctx.unique_name("value-one-"), ctx.unique_name("value-two-")

    # The replaced secret is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_secret(sm, first))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create: CloudFormation's view, Secrets Manager's view, and the value served
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first, "first", v1),
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    first_arn = _physical_ids(cfn, ref["stack"])["Secret"]
    assert _outputs(stack)["SecretArn"] == first_arn, (
        f"Ref Secret {_outputs(stack)['SecretArn']!r} must be the physical id {first_arn!r}"
    )
    _assert_secret(ctx, sm, first, first_arn, "first", v1)

    # ---- 2. in-place: a new value and description, the same secret
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(first, "second", v2), Tags=_TAGS
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Secret"] == first_arn, (
        "an in-place update keeps the secret"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Secret"), first_arn, "Secret")
    _assert_secret(ctx, sm, first, first_arn, "second", v2)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new secret, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(second, "second", v2), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_arn = _physical_ids(cfn, ref["stack"])["Secret"]
    assert second_arn != first_arn, f"the replacement must be a new secret, still {first_arn!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Secret"), first_arn, second_arn, "Secret"
    )
    assert _outputs(stack)["SecretArn"] == second_arn, f"Ref after replacement: {stack!r}"
    _assert_secret(ctx, sm, second, second_arn, "second", v2)
    _assert_secret(ctx, sm, first, first_arn, "second", v2)

    # ---- 4. delete: Secrets Manager no longer knows the stack's secret
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx, lambda: sm.describe_secret(SecretId=second), _NOT_FOUND[0], f"secret {second}"
    )
    assert got == _NOT_FOUND, f"DescribeSecret after the stack delete answered {got!r}"


def _assert_secret(ctx, sm, name: str, arn: str, description: str, value: str) -> None:
    """DescribeSecret and GetSecretValue report the template's secret exactly."""
    described = sm.describe_secret(SecretId=name)
    got = {k: described.get(k) for k in ("ARN", "Name", "Description")}
    want = {"ARN": arn, "Name": name, "Description": description}
    assert got == want, f"DescribeSecret {name}: {got!r}, expected {want!r}"
    assert "DeletedDate" not in described, f"{name} is scheduled for deletion: {described!r}"
    prefix = f"arn:aws:secretsmanager:{ctx.region}:{ctx.account}:secret:{name}-"
    assert arn.startswith(prefix) and len(arn) == len(prefix) + 6, (
        f"the secret ARN {arn!r} must be {prefix!r} followed by its 6-character suffix"
    )
    served = sm.get_secret_value(SecretId=name)
    got = {k: served.get(k) for k in ("ARN", "Name", "SecretString")}
    want = {"ARN": arn, "Name": name, "SecretString": value}
    assert got == want, f"GetSecretValue {name}: {got!r}, expected {want!r}"
    assert served["VersionStages"] == ["AWSCURRENT"], (
        f"GetSecretValue {name} served stages {served['VersionStages']!r}, expected AWSCURRENT"
    )


def _delete_secret(sm, name: str) -> None:
    try:
        sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND[0]:
            raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message.
    """
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done."""
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"])
    _delete_stack(ctx, cfn, stack["StackId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
