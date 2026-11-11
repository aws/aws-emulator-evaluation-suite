"""create-state-machine-idempotent-same-params."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-idempotent-same-params"
GROUP = 'state_machine_lifecycle'
SERVICES = ['stepfunctions']


_ROLE_ARNS = {}


def _execution_role_arn(ctx):
    """Create one Step Functions execution role per check run and register its cleanup."""
    key = id(ctx)
    if key in _ROLE_ARNS:
        return _ROLE_ARNS[key]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: _ROLE_ARNS.pop(key, None))
    _ROLE_ARNS[key] = arn
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A repeated CreateStateMachine with identical name, definition, roleArn and type is
    idempotent, returning the existing stateMachineArn instead of StateMachineAlreadyExists.
    """
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-idem-")
    role_arn = _execution_role_arn(ctx)
    definition = json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}})
    tags = [{"key": "sim2real", "value": "1"}]

    resp1 = sfn.create_state_machine(
        name=name, definition=definition, roleArn=role_arn, type="STANDARD", tags=tags
    )
    arn1 = resp1["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn1))

    resp2 = sfn.create_state_machine(
        name=name, definition=definition, roleArn=role_arn, type="STANDARD", tags=tags
    )
    assert resp2["stateMachineArn"] == arn1, (
        "idempotent CreateStateMachine must return the same stateMachineArn"
    )

    described = sfn.describe_state_machine(stateMachineArn=arn1)
    assert described["name"] == name, (
        f"expected the single resolved state machine named {name!r}, "
        f"describe returned name={described['name']!r}"
    )
    assert json.loads(described["definition"]) == json.loads(definition), (
        "the idempotently-resolved state machine's definition must be the one it was created "
        "with, not silently rewritten by the repeat call"
    )
    assert described["status"] == "ACTIVE", (
        f"expected the idempotently-resolved state machine to be ACTIVE, got {described['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
