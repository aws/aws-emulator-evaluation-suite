"""error-invalid-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-invalid-arn"
GROUP = 'errors'
SERVICES = ['stepfunctions']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStateMachine with a malformed ARN fails with InvalidArn and the exact message, while the
    same operation on a real state machine ARN returns it."""
    sfn = ctx.client("stepfunctions")
    definition = {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}
    sm_arn = _create_state_machine(ctx, definition)

    ok = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert ok["stateMachineArn"] == sm_arn, f"expected {sm_arn!r}, got {ok.get('stateMachineArn')!r}"

    code, message = _refusal(lambda: sfn.describe_state_machine(stateMachineArn="not-an-arn"))
    assert code == "InvalidArn", f"Expected InvalidArn, got {code!r}"
    expected_message = "Invalid Arn: 'Invalid ARN prefix: not-an-arn'"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


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
        tags=[{"key": "sim2real", "value": "1"}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
