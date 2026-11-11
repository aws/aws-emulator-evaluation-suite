"""error-execution-does-not-exist."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-execution-does-not-exist"
GROUP = 'errors'
SERVICES = ['stepfunctions']

def _create_sfn_role(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
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
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=_create_sfn_role(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _refusal(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises, so a target
    that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeExecution on a non-existent execution -> ExecutionDoesNotExist.

    A positive control (describing a real, just-started execution) comes first, so the
    negative cannot pass merely because DescribeExecution is denied or broken outright.
    """
    sfn = ctx.client("stepfunctions")
    # Use a real SM ARN but a bogus execution name to stay in-account
    definition = {"StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}}
    sm_arn = _create_state_machine(ctx, definition)

    real_exec_arn = sfn.start_execution(stateMachineArn=sm_arn)["executionArn"]
    positive = sfn.describe_execution(executionArn=real_exec_arn)
    assert positive["executionArn"] == real_exec_arn, (
        f"positive control: expected describe_execution to return {real_exec_arn!r}, "
        f"got {positive.get('executionArn')!r}"
    )

    # Construct an execution ARN that doesn't exist (same account, same SM)
    fake_exec_arn = sm_arn.replace(":stateMachine:", ":execution:") + ":ghost-exec-xyz"
    code, message = _refusal(lambda: sfn.describe_execution(executionArn=fake_exec_arn))
    assert code == "ExecutionDoesNotExist", f"Expected ExecutionDoesNotExist, got {code!r}"
    expected_message = f"Execution Does Not Exist: '{fake_exec_arn}'"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
