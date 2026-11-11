"""stop-execution-on-express-unsupported."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-execution-on-express-unsupported"
GROUP = 'express_workflows'
SERVICES = ['stepfunctions']
#: Real AWS refuses an EXPRESS execution ARN by its resource type, not by the execution.
_EXPRESS_INVALID_ARN_MESSAGE = "Invalid Arn: 'Resource type not valid in this context: express'"


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and deletes.

    The state machines here call no AWS API on the customer's behalf, so the role carries no
    permissions. It is created rather than looked up because a role the check did not create
    is account configuration, not a service contract.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine on a fresh role, retrying the one error IAM propagation can produce.

    A freshly created role is not instantly assumable and IAM exposes no condition to poll
    for that, so the bounded AccessDeniedException retry is the wait.
    """
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
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
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopExecution is unsupported for EXPRESS workflow executions -> InvalidArn.

    Real AWS rejects the EXPRESS executionArn shape itself (InvalidArn) rather than
    accepting it and returning a semantic ValidationException.
    """
    sfn = ctx.client("stepfunctions")
    definition = {"StartAt": "Wait", "States": {"Wait": {"Type": "Wait", "Seconds": 60, "End": True}}}

    # Positive control: StopExecution genuinely works on this account/role, so a
    # rejection below is specific to EXPRESS and not just every StopExecution call failing.
    control_arn = _create_state_machine(ctx, definition, sm_type="STANDARD")
    control_exec = sfn.start_execution(stateMachineArn=control_arn, input="{}")["executionArn"]
    sfn.stop_execution(executionArn=control_exec)
    control_status = sfn.describe_execution(executionArn=control_exec)["status"]
    assert control_status == "ABORTED", (
        f"positive control: expected STANDARD execution ABORTED after StopExecution, got {control_status}"
    )

    arn = _create_state_machine(ctx, definition, sm_type="EXPRESS")
    started = sfn.start_execution(stateMachineArn=arn, input="{}")
    exec_arn = started["executionArn"]

    error = _client_error(lambda: sfn.stop_execution(executionArn=exec_arn))
    code = error.get("Code")
    message = error.get("Message")
    assert code == "InvalidArn", f"expected InvalidArn stopping an EXPRESS execution, got {code}: {message}"
    expected_stop = _EXPRESS_INVALID_ARN_MESSAGE
    assert message == expected_stop, f"expected InvalidArn message {expected_stop!r}, got {message!r}"

    # Independent read, at a different operation than the one that mutated: DescribeExecution
    # rejects the SAME EXPRESS execution ARN with the identical InvalidArn contract. That is the
    # strongest "effect absent" available here — Step Functions exposes no execution-scoped read
    # at all for an EXPRESS execution with no CloudWatch Logging configured (ListExecutions on an
    # EXPRESS state machine raises StateMachineTypeNotSupported), so nothing in the API surface
    # could report this execution as stopped.
    describe_error = _client_error(lambda: sfn.describe_execution(executionArn=exec_arn))
    assert describe_error.get("Code") == "InvalidArn", (
        f"expected DescribeExecution to also reject the EXPRESS execution ARN, got {describe_error!r}"
    )
    expected_describe = _EXPRESS_INVALID_ARN_MESSAGE
    assert describe_error.get("Message") == expected_describe, (
        f"expected DescribeExecution message {expected_describe!r}, got {describe_error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
