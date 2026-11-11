"""error-validation-exception-update-map-run."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "error-validation-exception-update-map-run"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateMapRun validates toleratedFailurePercentage against its documented [0,100] range:
    a valid 25.0 on a running Map Run takes effect, then 150 returns ValidationException and
    leaves the Map Run at the last accepted value."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(
        ctx,
        inline_statements=[
            {
                "Effect": "Allow",
                "Action": ["states:StartExecution", "states:DescribeExecution", "states:StopExecution"],
                "Resource": "*",
            }
        ],
    )

    sm_name = ctx.unique_name("sim2real-behav-sm-dmap-")
    definition = json.dumps(
        {
            "StartAt": "Map",
            "States": {
                "Map": {
                    "Type": "Map",
                    "ItemsPath": "$.items",
                    "MaxConcurrency": 1,
                    "ItemProcessor": {
                        "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                        "StartAt": "Wait",
                        "States": {"Wait": {"Type": "Wait", "Seconds": 20, "End": True}},
                    },
                    "End": True,
                }
            },
        }
    )
    sm_arn = _create_state_machine_with_retry(ctx, sfn, sm_name, definition, role_arn)

    exec_input = json.dumps({"items": [{"i": 1}, {"i": 2}, {"i": 3}]})
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=exec_input)["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(sfn, exec_arn))

    map_run_arn = _poll_for_map_run(ctx, exec_arn, timeout_s=45.0)
    assert map_run_arn, "no Map Run ever appeared for the Distributed Map execution"

    sfn.update_map_run(mapRunArn=map_run_arn, toleratedFailurePercentage=25.0)
    accepted = sfn.describe_map_run(mapRunArn=map_run_arn)["toleratedFailurePercentage"]
    assert accepted == 25.0, (
        f"valid UpdateMapRun(toleratedFailurePercentage=25.0) did not take effect, got {accepted!r}"
    )

    code, message = _error_code(
        lambda: sfn.update_map_run(mapRunArn=map_run_arn, toleratedFailurePercentage=150.0)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '150.0' at 'toleratedFailurePercentage' failed to "
        "satisfy constraint: Member must have value less than or equal to 100"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after = sfn.describe_map_run(mapRunArn=map_run_arn)["toleratedFailurePercentage"]
    assert after == accepted, (
        f"rejected UpdateMapRun call still mutated toleratedFailurePercentage: {accepted!r} -> {after!r}"
    )


# ===== helpers =====
def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _best_effort_stop(sfn, exec_arn):
    from botocore.exceptions import ClientError

    try:
        sfn.stop_execution(executionArn=exec_arn)
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _poll_for_map_run(ctx, exec_arn, timeout_s=45.0, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        runs = sfn.list_map_runs(executionArn=exec_arn).get("mapRuns", [])
        if runs:
            return runs[0]["mapRunArn"]
        time.sleep(interval_s)
    return None


def _create_sfn_role(ctx, inline_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
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


def _create_state_machine_with_retry(ctx, sfn, name, definition, role_arn, timeout_s=90.0):
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's PassRole grant propagates, instead of a fixed sleep before the first attempt."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                tags=[{"key": "sim2real-check", "value": CHECK}],
            )
            arn = resp["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
