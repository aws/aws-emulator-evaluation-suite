"""describe-map-run-invalid-arn."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-map-run-invalid-arn"
GROUP = 'map_state'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and owns, so the
    outcome never rests on an execution role the account happens to carry."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


_PASS = {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}}


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine, retrying only the AccessDeniedException a freshly created role
    returns until IAM propagates it."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _fake_map_run_arn(state_machine_arn):
    """A syntactically well-formed but nonexistent mapRunArn, derived from a real
    stateMachineArn (mapRunArn shape is arn:...:mapRun:<name>/<label>:<id>)."""
    base = state_machine_arn.replace(":stateMachine:", ":mapRun:")
    return f"{base}/fakeLabel:{uuid.uuid4()}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeMapRun with a string that is not an ARN fails with InvalidArn, while a well-formed but
    nonexistent mapRunArn fails with ResourceNotFound, each with the exact message."""
    sfn = ctx.client("stepfunctions")
    sm_arn = _create_state_machine(ctx, _PASS, _create_sfn_role(ctx))
    wellformed_missing = _fake_map_run_arn(sm_arn)

    control_code, control_message = _error(lambda: sfn.describe_map_run(mapRunArn=wellformed_missing))
    assert control_code == "ResourceNotFound", (
        f"expected ResourceNotFound for a well-formed but nonexistent mapRunArn, got {control_code}"
    )
    expected = f"Resource not found: '{wellformed_missing}'"
    assert control_message == expected, f"expected message {expected!r}, got {control_message!r}"

    code, message = _error(lambda: sfn.describe_map_run(mapRunArn="not-an-arn-at-all"))
    assert code == "InvalidArn", f"expected InvalidArn, got {code}"
    expected = "Invalid Arn: 'Invalid ARN prefix: not-an-arn-at-all'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
