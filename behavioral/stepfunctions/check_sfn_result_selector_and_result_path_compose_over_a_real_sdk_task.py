"""sfn-result-selector-and-result-path-compose-over-a-real-sdk-task."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-result-selector-and-result-path-compose-over-a-real-sdk-task"
GROUP = 'input_output_processing'
SERVICES = ['stepfunctions']


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """ResultSelector narrows a real SDK task's response and ResultPath grafts it beside the
    untouched execution input, with the discarded response field provably absent.
    """
    sfn = ctx.client("stepfunctions")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    role_name, role_arn = _create_sfn_role(
        ctx, [{"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}]
    )

    definition = {
        "Comment": "one aws-sdk task, narrowed by ResultSelector, grafted by ResultPath",
        "StartAt": "WhoAmI",
        "States": {
            "WhoAmI": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
                "Parameters": {},
                "ResultSelector": {"Account.$": "$.Account", "Arn.$": "$.Arn"},
                "ResultPath": "$.identity",
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    input_payload = {"orderId": "sim2real-order-4711", "attempt": 3}
    exe = _run_to_terminal(ctx, sm_arn, input_payload)
    assert exe["status"] == "SUCCEEDED", (
        f'execution was {exe["status"]!r}: {exe.get("error")!r} {exe.get("cause")!r}'
    )

    output = json.loads(exe["output"])
    assert {k: output.get(k) for k in input_payload} == input_payload, (
        f"the execution input was altered by the task: output was {output!r}, "
        f"input was {input_payload!r}"
    )
    assert set(output["identity"]) == {"Account", "Arn"}, (
        f'ResultSelector should have kept exactly Account+Arn; output.identity was '
        f'{output["identity"]!r}'
    )
    assert "UserId" not in output["identity"], (
        f'ResultSelector did not drop UserId: {output["identity"]!r}'
    )

    raw_task_result = _raw_task_succeeded_output(ctx, exe["executionArn"])
    assert "UserId" in raw_task_result, (
        f"the raw TaskSucceeded result was {raw_task_result!r}, so ResultSelector had "
        f"nothing to drop and the assertion above proves nothing"
    )

    assert output["identity"]["Account"] == account_id, (
        f'the state machine reported account {output["identity"]["Account"]!r}, '
        f"the account is {account_id!r}"
    )
    assert role_name in output["identity"]["Arn"], (
        f'the SDK call was not made under the state machine role {role_name!r}: '
        f'the identity Arn was {output["identity"]["Arn"]!r}'
    )


def _create_sfn_role(ctx, statements):
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_name = f"{role_name}-policy"

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll; the bounded retries in _create_state_machine
    # and _run_to_terminal absorb it.
    return role_name, role_arn


def _create_state_machine(ctx, definition, role_arn, *, sm_type="STANDARD", logging=None,
                          name_prefix="sim2real-behav-sm-"):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name(name_prefix)
    kwargs = {
        "name": name,
        "definition": json.dumps(definition),
        "roleArn": role_arn,
        "type": sm_type,
        "tags": [{"key": "sim2real", "value": CHECK}],
    }
    if logging is not None:
        kwargs["loggingConfiguration"] = logging
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(**kwargs)["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
)


def _run_to_terminal(ctx, sm_arn, input_payload, *, timeout_s=120.0, max_attempts=6):
    """Start an execution and poll to a terminal status, absorbing the IAM trust race only."""
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(max_attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn,
            name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(input_payload),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(5)
    return desc


def _wait_terminal(ctx, exec_arn, *, timeout_s=120.0, interval_s=1.5):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on an already-terminal execution, so ExecutionDoesNotExist is
        # the only expected failure here; anything else is a real teardown failure and must raise.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _full_history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return events


def _raw_task_succeeded_output(ctx, exec_arn):
    for event in _full_history(ctx, exec_arn):
        if event["type"] == "TaskSucceeded":
            return event["taskSucceededEventDetails"]["output"]
    raise AssertionError(
        f"no TaskSucceeded event in the history of {exec_arn}: "
        f"types were {[e['type'] for e in _full_history(ctx, exec_arn)]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
