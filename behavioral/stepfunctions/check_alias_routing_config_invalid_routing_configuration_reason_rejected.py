"""alias-routing-config-invalid-routing-configuration-reason-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alias-routing-config-invalid-routing-configuration-reason-rejected"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]

_PASS_DEFINITION = json.dumps(
    {"Comment": "sim2real alias routing reason", "StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}}
)

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachineAlias and UpdateStateMachineAlias reject a repeated, unqualified or
    cross-machine version ARN with ValidationException reason INVALID_ROUTING_CONFIGURATION and
    the exact message, while a well-formed routingConfiguration still succeeds on both calls.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_a = _create_state_machine(ctx, sfn, role_arn, "a-")
    sm_b = _create_state_machine(ctx, sfn, role_arn, "b-")
    a_v1 = sfn.publish_state_machine_version(stateMachineArn=sm_a)["stateMachineVersionArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=a_v1), "ResourceNotFound"))
    b_v1 = sfn.publish_state_machine_version(stateMachineArn=sm_b)["stateMachineVersionArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=b_v1), "ResourceNotFound"))

    control_name = ctx.unique_name("sim2real-behav-alias-")
    control_arn = sfn.create_state_machine_alias(
        name=control_name, routingConfiguration=[{"stateMachineVersionArn": a_v1, "weight": 100}]
    )["stateMachineAliasArn"]
    # A version delete is refused while any alias still references it, and the final positive
    # control below re-points this alias at a later version, so its teardown is registered once,
    # last, after every version this run mints — LIFO then deletes the alias before any version.

    create_cases = [
        (
            [{"stateMachineVersionArn": a_v1, "weight": 50}, {"stateMachineVersionArn": a_v1, "weight": 50}],
            "distinct state machine version ARNs",
            f"Routing configuration must contain distinct state machine version ARNs. "
            f"Received: [{a_v1}, {a_v1}]",
        ),
        (
            [{"stateMachineVersionArn": sm_a, "weight": 100}],
            "unqualified ARN",
            f"Routing configuration must contain state machine version ARNs. Received: [{sm_a}]",
        ),
        (
            [{"stateMachineVersionArn": f"{sm_a}:{control_name}", "weight": 100}],
            "alias-qualified ARN",
            f"Routing configuration must contain state machine version ARNs. "
            f"Received: [{sm_a}:{control_name}]",
        ),
        (
            [{"stateMachineVersionArn": a_v1, "weight": 50}, {"stateMachineVersionArn": b_v1, "weight": 50}],
            "two different state machines",
            "Routing configuration must contain state machine version ARNs for the same "
            f"state machine. Received: [{a_v1}, {b_v1}]",
        ),
    ]
    for routing, label, expected_message in create_cases:
        err = _error(lambda r=routing: sfn.create_state_machine_alias(
            name=ctx.unique_name("sim2real-behav-alias-bad-"), routingConfiguration=r
        ))
        assert err["Code"] == "ValidationException", f"CreateStateMachineAlias {label}: expected ValidationException, got {err!r}"
        assert err["Reason"] == "INVALID_ROUTING_CONFIGURATION", (
            f"CreateStateMachineAlias {label}: expected reason INVALID_ROUTING_CONFIGURATION, got {err['Reason']!r}"
        )
        assert err["Message"] == expected_message, (
            f"CreateStateMachineAlias {label}: expected {expected_message!r}, got {err['Message']!r}"
        )

    aliases = sfn.list_state_machine_aliases(stateMachineArn=sm_a)["stateMachineAliases"]
    arns = [a["stateMachineAliasArn"] for a in aliases]
    assert arns == [control_arn], f"a rejected create must leak no alias; expected only {control_arn!r}, got {arns!r}"
    b_aliases = sfn.list_state_machine_aliases(stateMachineArn=sm_b)["stateMachineAliases"]
    assert b_aliases == [], f"no alias may have attached to the unrelated state machine; got {b_aliases!r}"

    err = _error(lambda: sfn.update_state_machine_alias(
        stateMachineAliasArn=control_arn,
        routingConfiguration=[{"stateMachineVersionArn": a_v1, "weight": 50}, {"stateMachineVersionArn": b_v1, "weight": 50}],
    ))
    assert err["Code"] == "ValidationException", f"UpdateStateMachineAlias two machines: expected ValidationException, got {err!r}"
    assert err["Reason"] == "INVALID_ROUTING_CONFIGURATION", (
        f"UpdateStateMachineAlias two machines: expected reason INVALID_ROUTING_CONFIGURATION, got {err['Reason']!r}"
    )
    expected_update_message = (
        f"Routing configuration must contain state machine version ARNs for the same state machine. "
        f"Received: [{a_v1}, {b_v1}]"
    )
    assert err["Message"] == expected_update_message, (
        f"UpdateStateMachineAlias two machines: expected {expected_update_message!r}, got {err['Message']!r}"
    )
    desc = sfn.describe_state_machine_alias(stateMachineAliasArn=control_arn)
    assert desc["routingConfiguration"] == [{"stateMachineVersionArn": a_v1, "weight": 100}], (
        f"a rejected update must leave the alias routing unchanged, got {desc['routingConfiguration']!r}"
    )

    # Positive control: a valid update on the same alias, via the same operation, still succeeds.
    a_v2 = sfn.update_state_machine(stateMachineArn=sm_a, definition=_PASS_DEFINITION, publish=True)["stateMachineVersionArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=a_v2), "ResourceNotFound"))
    ctx.on_cleanup(lambda: _delete_aliases_of(sfn, sm_a))
    sfn.update_state_machine_alias(
        stateMachineAliasArn=control_arn, routingConfiguration=[{"stateMachineVersionArn": a_v2, "weight": 100}]
    )
    desc = sfn.describe_state_machine_alias(stateMachineAliasArn=control_arn)
    assert desc["routingConfiguration"] == [{"stateMachineVersionArn": a_v2, "weight": 100}], (
        f"a valid UpdateStateMachineAlias must still take effect, got {desc['routingConfiguration']!r}"
    )


def _delete_aliases_of(sfn, state_machine_arn: str) -> None:
    """Aliases pin versions, and a pinned version blocks deletion, so unwind alias before version."""
    aliases = sfn.list_state_machine_aliases(stateMachineArn=state_machine_arn)["stateMachineAliases"]
    for alias in aliases:
        sfn.delete_state_machine_alias(stateMachineAliasArn=alias["stateMachineAliasArn"])


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
    """The AWS error `fn` raises, as {"Code", "Message", "Reason"}; raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"Code": err.get("Code"), "Message": err.get("Message"), "Reason": exc.response.get("reason")}
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
            resp = sfn.create_state_machine(name=name, definition=_PASS_DEFINITION, roleArn=role_arn)
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
