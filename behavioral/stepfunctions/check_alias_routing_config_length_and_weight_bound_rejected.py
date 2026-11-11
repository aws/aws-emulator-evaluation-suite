"""alias-routing-config-length-and-weight-bound-rejected."""
from __future__ import annotations

import json
import time

from botocore.client import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alias-routing-config-length-and-weight-bound-rejected"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]

_PASS_DEFINITION = json.dumps(
    {"Comment": "sim2real alias length/weight bound", "StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}}
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
    """CreateStateMachineAlias and UpdateStateMachineAlias reject a routingConfiguration of 0 or 3
    entries and a weight outside 0..100 with the exact ValidationException message, creating or
    changing nothing, while a 1-entry, in-range routingConfiguration still succeeds on both calls.
    """
    # The SDK refuses an empty list and a negative weight before the request is ever sent, so this
    # client is built with local parameter validation off to reach the service for every case.
    sfn = ctx.client("stepfunctions", config=Config(parameter_validation=False))
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, sfn, role_arn)
    v1 = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v1), "ResourceNotFound"))

    control_name = ctx.unique_name("sim2real-behav-alias-")
    control_arn = sfn.create_state_machine_alias(
        name=control_name, routingConfiguration=[{"stateMachineVersionArn": v1, "weight": 100}]
    )["stateMachineAliasArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=control_arn), "ResourceNotFound"))

    for label, routing in [
        ("empty list", []),
        ("3 entries", [{"stateMachineVersionArn": v1, "weight": 34}] * 2 + [{"stateMachineVersionArn": v1, "weight": 33}]),
        ("weight below 0", [{"stateMachineVersionArn": v1, "weight": -1}]),
        ("weight above 100", [{"stateMachineVersionArn": v1, "weight": 101}]),
    ]:
        err = _error(lambda r=routing: sfn.create_state_machine_alias(
            name=ctx.unique_name("sim2real-behav-alias-bad-"), routingConfiguration=r
        ))
        assert err["Code"] == "ValidationException", f"CreateStateMachineAlias {label}: expected ValidationException, got {err!r}"
        expected = _expected_length_or_weight_message(routing)
        assert err["Message"] == expected, f"CreateStateMachineAlias {label}: expected {expected!r}, got {err['Message']!r}"

    aliases = sfn.list_state_machine_aliases(stateMachineArn=sm_arn)["stateMachineAliases"]
    arns = [a["stateMachineAliasArn"] for a in aliases]
    assert arns == [control_arn], f"a rejected create must leak no alias; expected only {control_arn!r}, got {arns!r}"

    for label, routing in [
        ("weight below 0", [{"stateMachineVersionArn": v1, "weight": -1}]),
        ("3 entries", [{"stateMachineVersionArn": v1, "weight": 34}] * 2 + [{"stateMachineVersionArn": v1, "weight": 33}]),
    ]:
        err = _error(lambda r=routing: sfn.update_state_machine_alias(
            stateMachineAliasArn=control_arn, routingConfiguration=r
        ))
        assert err["Code"] == "ValidationException", f"UpdateStateMachineAlias {label}: expected ValidationException, got {err!r}"
        expected = _expected_length_or_weight_message(routing)
        assert err["Message"] == expected, f"UpdateStateMachineAlias {label}: expected {expected!r}, got {err['Message']!r}"
        desc = sfn.describe_state_machine_alias(stateMachineAliasArn=control_arn)
        assert desc["routingConfiguration"] == [{"stateMachineVersionArn": v1, "weight": 100}], (
            f"a rejected update must leave the alias routing unchanged, got {desc['routingConfiguration']!r}"
        )

    # Positive control: a valid update (still 1 entry, in-range weight) succeeds.
    sfn.update_state_machine_alias(
        stateMachineAliasArn=control_arn, routingConfiguration=[{"stateMachineVersionArn": v1, "weight": 100}]
    )
    desc = sfn.describe_state_machine_alias(stateMachineAliasArn=control_arn)
    assert desc["routingConfiguration"] == [{"stateMachineVersionArn": v1, "weight": 100}], (
        f"a valid UpdateStateMachineAlias must still take effect, got {desc['routingConfiguration']!r}"
    )


def _expected_length_or_weight_message(routing: list[dict]) -> str:
    """The exact Smithy range/length constraint message returned for `routing`."""
    if len(routing) == 0:
        return "1 validation error detected: Value '[]' at 'routingConfiguration' failed to satisfy constraint: " \
            "Member must have length greater than or equal to 1"
    if len(routing) == 3:
        items = ", ".join(
            f"RoutingConfigurationListItem(stateMachineVersionArn={r['stateMachineVersionArn']}, weight={r['weight']})"
            for r in routing
        )
        return f"1 validation error detected: Value '[{items}]' at 'routingConfiguration' failed to satisfy " \
            "constraint: Member must have length less than or equal to 2"
    weight = routing[0]["weight"]
    if weight < 0:
        return f"1 validation error detected: Value '{weight}' at 'routingConfiguration.1.member.weight' " \
            "failed to satisfy constraint: Member must have value greater than or equal to 0"
    return f"1 validation error detected: Value '{weight}' at 'routingConfiguration.1.member.weight' " \
        "failed to satisfy constraint: Member must have value less than or equal to 100"


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


def _create_state_machine(ctx, sfn, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the fresh role's trust propagates."""
    name = ctx.unique_name("sim2real-behav-sfn-")
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
