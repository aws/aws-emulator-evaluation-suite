"""error-conflict-create-state-machine-duplicate-name."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-conflict-create-state-machine-duplicate-name"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]

_TAGS = [{"key": "sim2real", "value": "audit-error-conflict-create-state-machine-duplicate-name"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine is idempotent for an identical request, but reusing an existing name with a
    different definition raises StateMachineAlreadyExists without altering the original; once the
    name-holder is deleted, the identical call succeeds.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    name = ctx.unique_name("sim2real-behav-sm-dup-")
    def_a = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})
    def_b = json.dumps({"StartAt": "Wait", "States": {"Wait": {"Type": "Wait", "Seconds": 1, "End": True}}})

    sm_arn = _create_state_machine_retrying(
        sfn, name=name, definition=def_a, role_arn=role_arn, retry_codes=("AccessDeniedException",),
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    # Idempotent replay with the identical definition must succeed and reuse the same ARN.
    replay = sfn.create_state_machine(name=name, definition=def_a, roleArn=role_arn, tags=_TAGS)
    assert replay["stateMachineArn"] == sm_arn, (
        f"idempotent replay of an identical CreateStateMachine must reuse {sm_arn!r}, "
        f"got {replay['stateMachineArn']!r}"
    )

    code, message = _refusal(lambda: sfn.create_state_machine(name=name, definition=def_b, roleArn=role_arn, tags=_TAGS))
    assert code == "StateMachineAlreadyExists", f"expected StateMachineAlreadyExists, got {code!r}"
    expected_message = f"State Machine Already Exists: '{sm_arn}'"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # The rejection must have had no effect: an independent read still shows the ORIGINAL
    # definition, not the one from the rejected call.
    described = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert json.loads(described["definition"]) == json.loads(def_a), (
        f"rejected CreateStateMachine must not alter the existing definition; "
        f"expected {def_a!r}, got {described['definition']!r}"
    )

    # Restore: once the name-holder is gone, the identical (name, def_b, roleArn) call that was
    # just rejected must succeed -- proving the conflict was scoped to the existing resource, not
    # a permanently invalid input.
    sfn.delete_state_machine(stateMachineArn=sm_arn)
    new_arn = _create_state_machine_retrying(
        sfn, name=name, definition=def_b, role_arn=role_arn,
        retry_codes=("StateMachineDeleting", "StateMachineAlreadyExists"), timeout_s=180.0,
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=new_arn))
    described2 = sfn.describe_state_machine(stateMachineArn=new_arn)
    assert json.loads(described2["definition"]) == json.loads(def_b), (
        f"post-restore CreateStateMachine must take the NEW definition; "
        f"expected {def_b!r}, got {described2['definition']!r}"
    )


def _refusal(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises, so a target
    that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


def _create_state_machine_retrying(sfn, *, name, definition, role_arn, retry_codes, timeout_s=120.0):
    """CreateStateMachine, retrying `retry_codes` while a transient, self-clearing condition
    resolves: a freshly created role's PassRole grant propagating (AccessDeniedException), or a
    just-deleted state machine's name not yet being freed (StateMachineDeleting while the delete
    is in flight, StateMachineAlreadyExists once the record still shows briefly afterward)."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn, tags=_TAGS)
            return resp["stateMachineArn"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in retry_codes:
                last_err = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"create_state_machine did not succeed within {timeout_s}s: {last_err}")


def _create_sfn_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "audit-error-conflict-create-state-machine-duplicate-name"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
