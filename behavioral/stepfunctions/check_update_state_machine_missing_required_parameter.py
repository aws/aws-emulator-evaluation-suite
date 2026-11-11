"""update-state-machine-missing-required-parameter."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-state-machine-missing-required-parameter"
GROUP = 'state_machine_lifecycle'
SERVICES = ['stepfunctions']

_MISSING_MESSAGE = "Either the definition, the role ARN, the LoggingConfiguration, or the TracingConfiguration must be specified"


_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and deletes.

    A Pass/Wait-only state machine makes no AWS call on the customer's behalf, so the role
    needs no permissions; a role the check did not create is account configuration.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine, retrying the AccessDeniedException a fresh role gives while IAM
    propagates; IAM exposes no condition to poll for that, so the bounded retry is the wait."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _error(fn):
    """The (code, message) fn raises; an unexpected success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code"):
            return err["Code"], err.get("Message")
        raise
    raise AssertionError("expected the call to raise a ClientError, it succeeded")


def _wait_for_result(sfn, arn, expected_result, *, deadline_s=30, interval_s=1):
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_state_machine(stateMachineArn=arn)
        if json.loads(last["definition"])["States"]["P"].get("Result") == expected_result:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"definition never converged to Result={expected_result!r}, last describe: {last}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachine with none of definition, roleArn, loggingConfiguration or tracingConfiguration
    fails with MissingRequiredParameter and the exact message, leaving the definition and revisionId a
    preceding valid update set."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass({"v": 1}), _create_sfn_role(ctx))

    sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(_asl_pass({"v": 2})))
    desc_after_positive = _wait_for_result(sfn, arn, {"v": 2})

    code, message = _error(lambda: sfn.update_state_machine(stateMachineArn=arn))
    assert code == "MissingRequiredParameter", f"expected MissingRequiredParameter, got {code}"
    assert message == _MISSING_MESSAGE, f"expected message {_MISSING_MESSAGE!r}, got {message!r}"

    desc_after_negative = sfn.describe_state_machine(stateMachineArn=arn)
    assert json.loads(desc_after_negative["definition"]) == json.loads(desc_after_positive["definition"]), (
        "UpdateStateMachine with none of definition/roleArn/loggingConfiguration/"
        f"tracingConfiguration must not change the definition: "
        f"before={desc_after_positive['definition']!r} after={desc_after_negative['definition']!r}"
    )
    assert desc_after_negative.get("revisionId") == desc_after_positive.get("revisionId"), (
        "UpdateStateMachine with none of definition/roleArn/loggingConfiguration/"
        f"tracingConfiguration must not advance revisionId: "
        f"before={desc_after_positive.get('revisionId')!r} after={desc_after_negative.get('revisionId')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
