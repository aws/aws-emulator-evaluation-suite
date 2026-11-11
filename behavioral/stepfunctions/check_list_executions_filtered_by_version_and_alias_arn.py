"""list-executions-filtered-by-version-and-alias-arn."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-executions-filtered-by-version-and-alias-arn"
GROUP = "execution_lifecycle"
SERVICES = ["stepfunctions"]

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes
    mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_sfn_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY)["Role"][
        "Arn"
    ]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_state_machine(ctx, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    definition = json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Succeed"}}})
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "AccessDeniedException"
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _wait_terminal(sfn, exec_arn, *, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _list_all_executions(sfn, **kwargs):
    items = []
    token = None
    while True:
        call_kwargs = dict(kwargs)
        if token:
            call_kwargs["nextToken"] = token
        resp = sfn.list_executions(**call_kwargs)
        items.extend(resp["executions"])
        token = resp.get("nextToken")
        if not token:
            return items


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "plane:control",
)
def run(ctx) -> None:
    """ListExecutions filtered by a version or alias ARN returns only the executions started
    through that qualified ARN, with the matching Version/AliasArn fields on each item, empty
    (not an error) for a never-created qualified ARN, and still listed after it is deleted."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    v1_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(
        _teardown(
            lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v1_arn),
            "ResourceNotFound",
        )
    )

    alias_name = ctx.unique_name("sim2real-behav-alias-")
    alias_arn = sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}]
    )["stateMachineAliasArn"]
    ctx.on_cleanup(
        _teardown(
            lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn),
            "ResourceNotFound",
        )
    )

    base_exec_arn = sfn.start_execution(stateMachineArn=sm_arn)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=base_exec_arn))
    version_exec_arn = sfn.start_execution(stateMachineArn=v1_arn)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=version_exec_arn))
    alias_exec_arn = sfn.start_execution(stateMachineArn=alias_arn)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=alias_exec_arn))

    for exec_arn in (base_exec_arn, version_exec_arn, alias_exec_arn):
        _wait_terminal(sfn, exec_arn)

    # Positive control: the unqualified listing covers every execution we started.
    all_arns = _poll_until(
        lambda: {e["executionArn"] for e in _list_all_executions(sfn, stateMachineArn=sm_arn)},
        lambda arns: {base_exec_arn, version_exec_arn, alias_exec_arn} <= arns,
        description="all three executions visible in the unqualified listing",
    )
    assert {base_exec_arn, version_exec_arn, alias_exec_arn} <= all_arns, (
        f"positive control: expected all three executions in the unqualified listing, got {all_arns}"
    )

    # Filtered by the version ARN: only the execution started through that exact ARN. ListExecutions
    # with a qualified ARN is eventually consistent right after the execution completes, so this is a
    # bounded poll, never a bare single read.
    version_items = _poll_until(
        lambda: {e["executionArn"]: e for e in _list_all_executions(sfn, stateMachineArn=v1_arn)},
        lambda items: version_exec_arn in items,
        description="the version-started execution visible when filtering by the version ARN",
    )
    assert base_exec_arn not in version_items, (
        f"unqualified-ARN execution {base_exec_arn} leaked into the version-filtered listing"
    )
    version_item = version_items[version_exec_arn]
    assert version_item.get("stateMachineVersionArn") == v1_arn, (
        f"expected stateMachineVersionArn == {v1_arn!r} on the version-started item, got {version_item!r}"
    )
    assert version_item.get("stateMachineAliasArn") is None, (
        f"expected no stateMachineAliasArn on the version-started item, got {version_item!r}"
    )

    # Filtered by the alias ARN, together with a status filter.
    alias_items = _poll_until(
        lambda: {
            e["executionArn"]: e
            for e in _list_all_executions(sfn, stateMachineArn=alias_arn, statusFilter="SUCCEEDED")
        },
        lambda items: alias_exec_arn in items,
        description="the alias-started execution visible when filtering by the alias ARN and status",
    )
    assert base_exec_arn not in alias_items and version_exec_arn not in alias_items, (
        "unrelated executions leaked into the alias-filtered, status-filtered listing"
    )
    alias_item = alias_items[alias_exec_arn]
    assert alias_item.get("stateMachineAliasArn") == alias_arn, (
        f"expected stateMachineAliasArn == {alias_arn!r} on the alias-started item, got {alias_item!r}"
    )
    assert alias_item.get("stateMachineVersionArn") == v1_arn, (
        f"expected stateMachineVersionArn == {v1_arn!r} on the alias-started item, got {alias_item!r}"
    )

    # A qualified ARN that was never created returns an empty list, not an error.
    never_published_version_arn = f"{sm_arn}:999"
    never_existed_alias_arn = f"{sm_arn}:{ctx.unique_name('sim2real-behav-no-such-alias-')}"
    for fake_arn in (never_published_version_arn, never_existed_alias_arn):
        empty = sfn.list_executions(stateMachineArn=fake_arn)["executions"]
        assert empty == [], (
            f"expected an empty list for the never-created qualified ARN {fake_arn}, got {empty}"
        )

    # Combining a qualified ARN with the PENDING_REDRIVE status filter is rejected.
    code, message = _error(
        lambda: sfn.list_executions(stateMachineArn=v1_arn, statusFilter="PENDING_REDRIVE")
    )
    assert code == "ValidationException", (
        f"expected ValidationException for stateMachineArn + PENDING_REDRIVE statusFilter, got {code}"
    )
    assert message == (
        "StatusFilter of PENDING_REDRIVE cannot be applied to ListExecutions call with StateMachine ARN"
    ), f"unexpected ValidationException message for PENDING_REDRIVE statusFilter: {message!r}"

    # The alias and version are deleted; their executions stay listed by the now-dead ARNs.
    sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)
    sfn.delete_state_machine_version(stateMachineVersionArn=v1_arn)

    version_items_after = _poll_until(
        lambda: {e["executionArn"] for e in _list_all_executions(sfn, stateMachineArn=v1_arn)},
        lambda arns: version_exec_arn in arns,
        description="the execution still listed by its version ARN after the version was deleted",
    )
    assert version_exec_arn in version_items_after
    alias_items_after = _poll_until(
        lambda: {e["executionArn"] for e in _list_all_executions(sfn, stateMachineArn=alias_arn)},
        lambda arns: alias_exec_arn in arns,
        description="the execution still listed by its alias ARN after the alias was deleted",
    )
    assert alias_exec_arn in alias_items_after


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
