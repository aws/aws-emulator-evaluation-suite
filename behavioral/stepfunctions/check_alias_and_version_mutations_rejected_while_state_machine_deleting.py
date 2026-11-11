"""alias-and-version-mutations-rejected-while-state-machine-deleting."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alias-and-version-mutations-rejected-while-state-machine-deleting"
GROUP = "data-plane"
SERVICES = ["stepfunctions"]

_WAIT_DEFINITION = json.dumps(
    {"Comment": "sim2real deleting-mutations", "StartAt": "W", "States": {"W": {"Type": "Wait", "Seconds": 600, "End": True}}}
)

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

DELETING_POLL_TIMEOUT_S = 60.0


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachineAlias, UpdateStateMachineAlias and PublishStateMachineVersion against a
    state machine mid-deletion are all rejected StateMachineDeleting, each with its own exact
    message, while the same three calls still succeed against an unaffected state machine.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    target_arn = _create_state_machine(ctx, sfn, role_arn, "target-")
    target_v1 = sfn.publish_state_machine_version(stateMachineArn=target_arn)["stateMachineVersionArn"]
    target_alias_arn = sfn.create_state_machine_alias(
        name=ctx.unique_name("sim2real-behav-alias-"),
        routingConfiguration=[{"stateMachineVersionArn": target_v1, "weight": 100}],
    )["stateMachineAliasArn"]

    control_arn = _create_state_machine(ctx, sfn, role_arn, "control-")
    control_v1 = sfn.publish_state_machine_version(stateMachineArn=control_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=control_v1), "ResourceNotFound"))
    control_alias_arn = sfn.create_state_machine_alias(
        name=ctx.unique_name("sim2real-behav-alias-"),
        routingConfiguration=[{"stateMachineVersionArn": control_v1, "weight": 100}],
    )["stateMachineAliasArn"]

    # A RUNNING execution keeps the target in DELETING long enough to probe it; deletion itself
    # converges asynchronously (its alias and version disappear with it), so the cleanup stops the
    # execution and then waits it out rather than asserting the state machine is gone immediately.
    target_exec_arn = sfn.start_execution(stateMachineArn=target_arn, input="{}")["executionArn"]
    sfn.delete_state_machine(stateMachineArn=target_arn)
    ctx.on_cleanup(lambda: _finish_deletion(sfn, target_arn, target_exec_arn))
    _poll_until(
        lambda: sfn.describe_state_machine(stateMachineArn=target_arn)["status"],
        lambda status: status == "DELETING",
        timeout_s=DELETING_POLL_TIMEOUT_S,
    )

    target_name = target_arn.rsplit(":", 1)[-1]
    err = _error(lambda: sfn.create_state_machine_alias(
        name=ctx.unique_name("sim2real-behav-alias-"),
        routingConfiguration=[{"stateMachineVersionArn": target_v1, "weight": 100}],
    ))
    expected = f"Failed to create alias because the State Machine {target_name} is in the DELETING state"
    assert err == {"Code": "StateMachineDeleting", "Message": expected}, (
        f"CreateStateMachineAlias on a deleting state machine: expected {expected!r}, got {err!r}"
    )

    err = _error(lambda: sfn.update_state_machine_alias(stateMachineAliasArn=target_alias_arn, description="x"))
    expected = f"State Machine is being deleted: '{target_arn}'"
    assert err == {"Code": "StateMachineDeleting", "Message": expected}, (
        f"UpdateStateMachineAlias on a deleting state machine: expected {expected!r}, got {err!r}"
    )

    err = _error(lambda: sfn.publish_state_machine_version(stateMachineArn=target_arn))
    assert err == {"Code": "StateMachineDeleting", "Message": ""}, (
        f"PublishStateMachineVersion on a deleting state machine: expected an empty message, got {err!r}"
    )

    # Independent read: no new alias or version attached to the deleting state machine.
    aliases = sfn.list_state_machine_aliases(stateMachineArn=target_arn)["stateMachineAliases"]
    assert [a["stateMachineAliasArn"] for a in aliases] == [target_alias_arn], (
        f"no alias beyond the pre-existing one may have attached while deleting; got {aliases!r}"
    )
    versions = sfn.list_state_machine_versions(stateMachineArn=target_arn)["stateMachineVersions"]
    assert [v["stateMachineVersionArn"] for v in versions] == [target_v1], (
        f"no version beyond the pre-existing one may have attached while deleting; got {versions!r}"
    )

    # Positive control: the same three calls against an unaffected state machine all succeed.
    second_alias_arn = sfn.create_state_machine_alias(
        name=ctx.unique_name("sim2real-behav-alias-"),
        routingConfiguration=[{"stateMachineVersionArn": control_v1, "weight": 100}],
    )["stateMachineAliasArn"]
    sfn.update_state_machine_alias(stateMachineAliasArn=control_alias_arn, description="control")
    # PublishStateMachineVersion is a no-op on an unchanged definition, so change it first.
    control_v2 = sfn.update_state_machine(
        stateMachineArn=control_arn, definition=_WAIT_DEFINITION.replace("600", "601"), publish=True
    )["stateMachineVersionArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=control_v2), "ResourceNotFound"))
    # A version delete is refused while an alias still references it; both control aliases
    # reference control_v1, so they are swept, last, right after the last version this run mints.
    ctx.on_cleanup(lambda: _delete_aliases_of(sfn, control_arn))
    assert control_v2 != control_v1, "the positive control publish must mint a new version"
    control_desc = sfn.describe_state_machine_alias(stateMachineAliasArn=control_alias_arn)
    assert control_desc["description"] == "control", (
        f"the positive control update must take effect, got description {control_desc.get('description')!r}"
    )
    second_desc = sfn.describe_state_machine_alias(stateMachineAliasArn=second_alias_arn)
    assert second_desc["routingConfiguration"] == [{"stateMachineVersionArn": control_v1, "weight": 100}], (
        f"the positive control create must take effect, got {second_desc['routingConfiguration']!r}"
    )


def _finish_deletion(sfn, sm_arn: str, exec_arn: str) -> None:
    """Stop the execution holding `sm_arn` in DELETING, then wait for the delete to converge."""
    try:
        sfn.stop_execution(executionArn=exec_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise
    deadline = time.monotonic() + 240.0
    while time.monotonic() < deadline:
        try:
            sfn.describe_state_machine(stateMachineArn=sm_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "StateMachineDoesNotExist":
                return
            raise
        time.sleep(5.0)
    raise AssertionError(f"state machine {sm_arn!r} still deleting after 240s")


def _delete_aliases_of(sfn, state_machine_arn: str) -> None:
    """Aliases pin versions, and a pinned version blocks deletion, so unwind alias before version."""
    aliases = sfn.list_state_machine_aliases(stateMachineArn=state_machine_arn)["stateMachineAliases"]
    for alias in aliases:
        sfn.delete_state_machine_alias(stateMachineAliasArn=alias["stateMachineAliasArn"])


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> dict:
    """The AWS error `fn` raises, as {"Code", "Message"}; raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"Code": err.get("Code"), "Message": err.get("Message")}
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role_arn


def _create_state_machine(ctx, sfn, role_arn: str, tag: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the fresh role's trust propagates."""
    name = ctx.unique_name(f"sim2real-behav-sfn-{tag}")
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(name=name, definition=_WAIT_DEFINITION, roleArn=role_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
