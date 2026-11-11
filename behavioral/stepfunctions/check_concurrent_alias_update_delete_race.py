"""concurrent-alias-update-delete-race."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-alias-update-delete-race"
GROUP = "concurrency"
SERVICES = ["stepfunctions"]

_ITERATIONS = 4


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachineAlias racing DeleteStateMachineAlias resolves consistently: a refused delete leaves
    the alias with the routing of whichever update landed, a refused update gets ResourceNotFound or
    ConflictException with AWS's message, and the alias then ends ResourceNotFound with the exact message."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    def0 = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})
    sm_name = ctx.unique_name("sim2real-behav-sm-alias-race-")
    sm_arn = _create_state_machine(sfn, sm_name, def0, role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    v1_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: _delete_version_quiet(sfn, v1_arn))
    def1 = json.dumps({"StartAt": "Pass2", "States": {"Pass2": {"Type": "Pass", "End": True}}})
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=def1)
    v2_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: _delete_version_quiet(sfn, v2_arn))

    saw_update_win = False
    saw_delete_win = False

    for i in range(_ITERATIONS):
        alias_name = ctx.unique_name(f"sim2real-behav-alias-race-{i}-")
        alias_arn = sfn.create_state_machine_alias(
            name=alias_name,
            routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}],
        )["stateMachineAliasArn"]

        barrier = threading.Barrier(2)

        def _update(barrier=barrier, alias_arn=alias_arn):
            barrier.wait(timeout=5)
            return sfn.update_state_machine_alias(
                stateMachineAliasArn=alias_arn,
                routingConfiguration=[{"stateMachineVersionArn": v2_arn, "weight": 100}],
            )

        def _delete(barrier=barrier, alias_arn=alias_arn):
            barrier.wait(timeout=5)
            return sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)

        with ThreadPoolExecutor(max_workers=2) as pool:
            fut_update = pool.submit(_update)
            fut_delete = pool.submit(_delete)
            update_result = _capture(fut_update)
            delete_result = _capture(fut_delete)

        if delete_result[0] != "ok":
            # The delete itself may lose to a genuinely in-flight update (ConflictException) --
            # anything else is a real fidelity bug.
            # message varies: the race decides which refusal path answers, so only the code is stable.
            assert delete_result[1] == "ConflictException", (
                f"iteration {i}: DeleteStateMachineAlias failed with an unexpected code: {delete_result[1]!r}"
            )
            if update_result[0] == "ok":
                saw_update_win = True
                expected_versions = {v2_arn}
            else:
                # Each racer can see the other in flight, so both can be refused; the alias then
                # keeps its original routing.
                assert update_result[1] == "ConflictException", (
                    f"iteration {i}: delete lost with ConflictException and update failed with {update_result[1]!r}"
                )
                expected_message = "Failed to update alias due to conflicting request. Please retry."
                assert update_result[2] == expected_message, (
                    f"iteration {i}: refused update carried {update_result[2]!r}, expected {expected_message!r}"
                )
                expected_versions = {v1_arn}
            # The alias must still exist, consistently reflecting whichever update landed.
            described = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
            versions = {r["stateMachineVersionArn"] for r in described["routingConfiguration"]}
            assert versions == expected_versions, (
                f"iteration {i}: alias survived the race with routing {versions!r}, expected {expected_versions!r}"
            )
            sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)
        elif update_result[0] == "ok":
            saw_update_win = True
        else:
            saw_delete_win = True
            # The delete may have already fully removed the alias (ResourceNotFound), or the
            # update request may have been in flight against the alias just as the delete
            # removed it, which the service surfaces as a ConflictException rather than a 404 --
            # either way it must never report success against a gone-or-going resource.
            if update_result[1] == "ResourceNotFound":
                expected_message = "Request references a resource that does not exist."
            elif update_result[1] == "ConflictException":
                expected_message = "Failed to update alias due to conflicting request. Please retry."
            else:
                raise AssertionError(
                    f"iteration {i}: the losing UpdateStateMachineAlias must fail with ResourceNotFound "
                    f"or ConflictException, got {update_result[1]!r}"
                )
            assert update_result[2] == expected_message, (
                f"iteration {i}: the losing UpdateStateMachineAlias ({update_result[1]}) carried message "
                f"{update_result[2]!r}, expected {expected_message!r}"
            )

        # Regardless of who won, the alias must eventually be gone -- never "half deleted".
        # A successful DeleteStateMachineAlias can leave the alias describable for a few seconds,
        # so poll to a bounded deadline rather than trust one immediate read.
        code, message = _wait_for_alias_gone(sfn, alias_arn)
        assert code == "ResourceNotFound", (
            f"iteration {i}: alias should be fully deleted after the race, describe gave {code!r}"
        )
        assert message == f"Resource not found: '{alias_arn}'", (
            f"iteration {i}: unexpected ResourceNotFound message {message!r}"
        )

    assert saw_update_win or saw_delete_win, "the race never resolved either way across iterations"


def _capture(future):
    from botocore.exceptions import ClientError

    try:
        return ("ok", future.result())
    except ClientError as exc:
        return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))


def _wait_for_alias_gone(sfn, alias_arn: str, timeout: float = 30.0, interval: float = 2.0) -> tuple[str, str]:
    """Poll DescribeStateMachineAlias until it is refused; return the refusal's (code, message).

    An alias still describable when the window closes raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout
    while True:
        try:
            sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
        except ClientError as exc:
            err = exc.response["Error"]
            return err["Code"], err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"alias {alias_arn} is still describable {timeout}s after the race")
        time.sleep(interval)


def _delete_version_quiet(sfn, version_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sfn.delete_state_machine_version(stateMachineVersionArn=version_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _create_state_machine(sfn, name: str, definition: str, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's PassRole grant propagates -- never an unconditional sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)[
                "stateMachineArn"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")


def _create_sfn_role(ctx, inline_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-sfn-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
