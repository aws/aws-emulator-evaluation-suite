"""concurrent-start-execution-same-name-idempotent."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-start-execution-same-name-idempotent"
GROUP = "concurrency"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent STANDARD StartExecution calls reusing one name with different inputs leave exactly
    one execution: the loser gets ExecutionAlreadyExists with the exact message naming the winner."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    definition = json.dumps(
        {
            "StartAt": "Wait",
            "States": {
                "Wait": {"Type": "Wait", "Seconds": 5, "Next": "Pass"},
                "Pass": {"Type": "Pass", "End": True},
            },
        }
    )
    sm_name = ctx.unique_name("sim2real-behav-sm-race-")
    sm_arn = _create_state_machine(sfn, sm_name, definition, role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    exec_name = ctx.unique_name("sim2real-behav-exec-race-").replace("_", "-")

    def _start(payload_tag: str):
        return sfn.start_execution(
            stateMachineArn=sm_arn, name=exec_name, input=json.dumps({"race": payload_tag})
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        future_a = pool.submit(_start, "A")
        future_b = pool.submit(_start, "B")
        result_a = _capture(future_a)
        result_b = _capture(future_b)

    results = [result_a, result_b]
    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly one racer to succeed, got {successes!r} / {failures!r}"
    assert len(failures) == 1, f"expected exactly one racer to fail, got {successes!r} / {failures!r}"
    assert failures[0][1] == "ExecutionAlreadyExists", (
        f"the losing racer (different input, same name) must get ExecutionAlreadyExists, "
        f"got {failures[0][1]!r}"
    )

    exec_arn = successes[0][1]["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    expected = f"Execution Already Exists: '{exec_arn}'"
    assert failures[0][2] == expected, f"expected message {expected!r}, got {failures[0][2]!r}"

    executions = sfn.list_executions(stateMachineArn=sm_arn)["executions"]
    matching = [e for e in executions if e["name"] == exec_name]
    assert len(matching) == 1, f"expected exactly one execution named {exec_name!r}, found {matching!r}"
    assert matching[0]["executionArn"] == exec_arn, (
        f"expected the listed execution's arn to be the winning racer's arn "
        f"{exec_arn!r}, got {matching[0]['executionArn']!r}"
    )


# ===== helpers =====
def _capture(future):
    from botocore.exceptions import ClientError

    try:
        return ("ok", future.result())
    except ClientError as exc:
        return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))


def _stop_if_running(sfn, exec_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        status = sfn.describe_execution(executionArn=exec_arn)["status"]
        if status == "RUNNING":
            sfn.stop_execution(executionArn=exec_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


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


def _create_state_machine(sfn, name: str, definition: str, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created role's PassRole
    grant propagates."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
