"""alias-repoint-to-foreign-state-machine-version-rejected."""
# Re-pointing a live alias at a version of a DIFFERENT state machine is refused with
# ResourceNotFound, not the ValidationException CreateStateMachineAlias returns for the same
# foreign version: Update resolves the version under the alias's own state machine, where it does
# not exist. The model declares both codes on both operations.
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alias-repoint-to-foreign-state-machine-version-rejected"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]

EXECUTION_TIMEOUT_S = 120.0
ROLE_PROPAGATION_TIMEOUT_S = 90.0
ALIAS_CONVERGE_TIMEOUT_S = 60.0


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """UpdateStateMachineAlias pointing an alias of state machine A at a version of B is refused
    ResourceNotFound and the alias still runs A v1; re-pointing it at A's version 2 succeeds and
    is what runs next.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    sm_a, a_v1 = _create_published_state_machine(ctx, sfn, role_arn, "a-", {"from": "A", "rev": 1})
    sm_b, b_v1 = _create_published_state_machine(ctx, sfn, role_arn, "b-", {"from": "B", "rev": 1})
    assert a_v1.startswith(sm_a + ":") and b_v1.startswith(sm_b + ":"), (
        f"publish=True must return versions qualified off their own state machines; got "
        f"{a_v1!r} for {sm_a!r} and {b_v1!r} for {sm_b!r}"
    )

    alias_arn = sfn.create_state_machine_alias(
        name="live",
        description="sim2real alias-repoint-to-foreign-state-machine-version-rejected",
        routingConfiguration=[{"stateMachineVersionArn": a_v1, "weight": 100}],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: _swallow(
        lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)))

    first = _execute(sfn, alias_arn)
    assert first["status"] == "SUCCEEDED" and json.loads(first["output"]) == {
        "from": "A", "rev": 1}, (
        f"baseline: the alias must run A v1; got status {first['status']!r} output "
        f"{first.get('output')!r}"
    )

    # A second version of A, so the positive control has somewhere legitimate to go.
    a_v2 = sfn.update_state_machine(
        stateMachineArn=sm_a, definition=_definition({"from": "A", "rev": 2}), publish=True,
    )["stateMachineVersionArn"]
    assert a_v2 != a_v1 and a_v2.startswith(sm_a + ":"), (
        f"UpdateStateMachine(publish=True) must mint a new version of A; v1 {a_v1!r}, v2 {a_v2!r}"
    )

    # --- The one broken thing: a version of B on A's alias ------------------------------------------
    err = _error(lambda: sfn.update_state_machine_alias(
        stateMachineAliasArn=alias_arn,
        routingConfiguration=[{"stateMachineVersionArn": b_v1, "weight": 100}],
    ))
    expected = {"Code": "ResourceNotFound", "Message": "Request references a resource that does not exist."}
    assert err == expected, (
        f"re-pointing A's alias at B's version must be rejected with {expected}; got {err!r}"
    )

    # Effect absent, read back AND executed.
    routing = _alias_routing(sfn, alias_arn)
    assert routing == [(a_v1, 100)], (
        f"the rejected update must leave the alias on A v1 ({a_v1!r}); routing is now {routing!r}"
    )
    after_reject = _execute(sfn, alias_arn)
    assert after_reject["status"] == "SUCCEEDED" and json.loads(after_reject["output"]) == {
        "from": "A", "rev": 1}, (
        f"after the rejection the alias must still run A v1; got status "
        f"{after_reject['status']!r} output {after_reject.get('output')!r}"
    )
    assert after_reject.get("stateMachineVersionArn") == a_v1, (
        f"the alias must still resolve to A v1 ({a_v1!r}); got "
        f"{after_reject.get('stateMachineVersionArn')!r}"
    )
    b_aliases = sfn.list_state_machine_aliases(stateMachineArn=sm_b)["stateMachineAliases"]
    assert b_aliases == [], f"no alias may have attached to B; got {b_aliases!r}"

    # --- Positive control: the same call with A's own version ----------------------------------
    sfn.update_state_machine_alias(
        stateMachineAliasArn=alias_arn,
        routingConfiguration=[{"stateMachineVersionArn": a_v2, "weight": 100}],
    )
    routing = _alias_routing(sfn, alias_arn)
    assert routing == [(a_v2, 100)], (
        f"re-pointing at A's own version 2 must succeed; routing is {routing!r}"
    )
    # UpdateStateMachineAlias is documented eventually consistent for StartExecution, so poll the
    # observable condition: executions may resolve to v1 for a few seconds, never to anything else,
    # and each one must run exactly the definition of the version it resolved to.
    expected = {a_v1: {"from": "A", "rev": 1}, a_v2: {"from": "A", "rev": 2}}
    repaired = _execute_until_version(sfn, alias_arn, a_v2, expected)
    assert repaired.get("stateMachineVersionArn") == a_v2, (
        f"within {ALIAS_CONVERGE_TIMEOUT_S}s the alias must resolve to A v2 ({a_v2!r}); last "
        f"execution resolved to {repaired.get('stateMachineVersionArn')!r}"
    )


class _CallSucceeded(Exception):
    """Raised by _error when the call it was handed did NOT fail."""


def _error(fn) -> dict:
    """The AWS error `fn` raised, as {"Code", "Message"}; raises _CallSucceeded on success, so an
    unexpected success can never be mistaken for an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"Code": err.get("Code"), "Message": err.get("Message")}
    raise _CallSucceeded(f"call unexpectedly succeeded: {str(result)[:400]}")


def _swallow(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _definition(result: dict) -> str:
    return json.dumps({
        "Comment": "sim2real alias re-point negative",
        "StartAt": "Emit",
        "States": {"Emit": {"Type": "Pass", "Result": result, "End": True}},
    })


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-sfn-alias-neg-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "states.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    # IAM exposes no condition to poll; the bounded AccessDenied retry in
    # _create_published_state_machine waits out the propagation.
    return arn


def _create_published_state_machine(ctx, sfn, role_arn: str, tag: str, result: dict):
    from botocore.exceptions import ClientError

    name = ctx.unique_name(f"sim2real-sfn-alias-neg-{tag}")
    deadline = time.monotonic() + ROLE_PROPAGATION_TIMEOUT_S
    while True:
        try:
            created = sfn.create_state_machine(
                name=name, definition=_definition(result), roleArn=role_arn, publish=True,
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            break
        except ClientError as exc:
            # CreateStateMachine validates that states.amazonaws.com can assume the role; a fresh
            # role is not assumable until IAM propagates.
            if exc.response["Error"]["Code"] != "AccessDeniedException" or \
                    time.monotonic() > deadline:
                raise
            time.sleep(3)
    sm_arn = created["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))
    return sm_arn, created["stateMachineVersionArn"]


def _alias_routing(sfn, alias_arn: str) -> list[tuple[str, int]]:
    desc = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    return [(r["stateMachineVersionArn"], r["weight"]) for r in desc["routingConfiguration"]]


def _execute(sfn, target_arn: str) -> dict:
    started = sfn.start_execution(stateMachineArn=target_arn, input="{}")
    deadline = time.monotonic() + EXECUTION_TIMEOUT_S
    while True:
        desc = sfn.describe_execution(executionArn=started["executionArn"])
        if desc["status"] != "RUNNING":
            return desc
        if time.monotonic() > deadline:
            raise AssertionError(
                f"execution {started['executionArn']!r} still RUNNING after "
                f"{EXECUTION_TIMEOUT_S}s"
            )
        time.sleep(1)


def _execute_until_version(sfn, alias_arn: str, want: str, expected: dict) -> dict:
    """Execute through the alias until one resolves to `want`, bounded. Every execution must
    SUCCEED with the output of the version it resolved to, and resolve to a version in
    `expected` -- the only latitude AWS documents is the previous routing, briefly."""
    deadline = time.monotonic() + ALIAS_CONVERGE_TIMEOUT_S
    while True:
        desc = _execute(sfn, alias_arn)
        got = desc.get("stateMachineVersionArn")
        assert got in expected, (
            f"an execution through the alias resolved to {got!r}, which is neither the new nor "
            f"the previous version {sorted(expected)!r}"
        )
        assert desc["status"] == "SUCCEEDED" and json.loads(desc["output"]) == expected[got], (
            f"an execution resolved to {got!r} must run that version's definition "
            f"({expected[got]!r}); got status {desc['status']!r} output {desc.get('output')!r}"
        )
        if got == want or time.monotonic() > deadline:
            return desc
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
