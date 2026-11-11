"""error-execution-already-exists."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-execution-already-exists"
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
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _refusal(fn):
    """Call fn(); return the (code, HTTP status, message) it is refused with. A success raises, so
    a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")

@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartExecution with a duplicate name -> ExecutionAlreadyExists."""
    sfn = ctx.client("stepfunctions")
    definition = {
        "StartAt": "P",
        "States": {"P": {"Type": "Pass", "End": True}},
    }
    sm_arn = _create_state_machine(ctx, definition)
    exec_name = ("exec-" + uuid.uuid4().hex[:12])
    # First execution
    resp = sfn.start_execution(stateMachineArn=sm_arn, name=exec_name, input="{}")
    ctx.on_cleanup(lambda a=resp["executionArn"]: sfn.stop_execution(executionArn=a))
    # Positive control: the first execution really ran to SUCCEEDED.
    first = _wait_execution_complete(ctx, resp["executionArn"])
    assert first["status"] == "SUCCEEDED", (
        f"first execution: expected SUCCEEDED, got {first['status']}: {first.get('cause')}"
    )
    # Second execution with same name
    code, status, message = _refusal(
        lambda: sfn.start_execution(stateMachineArn=sm_arn, name=exec_name, input="{}")
    )
    assert (code, status) == ("ExecutionAlreadyExists", 400), (
        f"duplicate StartExecution: expected ExecutionAlreadyExists/400, got {code!r}/{status!r}"
    )
    expected_message = f"Execution Already Exists: '{resp['executionArn']}'"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Independent read: the rejected duplicate must not have created a second execution.
    listed = sfn.list_executions(stateMachineArn=sm_arn)
    matching = [e for e in listed["executions"] if e["name"] == exec_name]
    assert len(matching) == 1, (
        f"expected exactly one execution named {exec_name!r} after the rejected duplicate "
        f"start, found {matching!r}"
    )
    assert matching[0]["executionArn"] == resp["executionArn"], (
        f"the sole execution named {exec_name!r} must be the original "
        f"({resp['executionArn']!r}), got {matching[0]['executionArn']!r}"
    )

    # Restore: the identical start under a fresh name succeeds.
    fresh_name = "exec-" + uuid.uuid4().hex[:12]
    fresh = sfn.start_execution(stateMachineArn=sm_arn, name=fresh_name, input="{}")
    ctx.on_cleanup(lambda a=fresh["executionArn"]: sfn.stop_execution(executionArn=a))
    fresh_desc = _wait_execution_complete(ctx, fresh["executionArn"])
    assert fresh_desc["status"] == "SUCCEEDED", (
        f"fresh-name execution: expected SUCCEEDED, got {fresh_desc['status']}: "
        f"{fresh_desc.get('cause')}"
    )
    listed = sfn.list_executions(stateMachineArn=sm_arn)["executions"]
    names = sorted(e["name"] for e in listed)
    assert names == sorted([exec_name, fresh_name]), (
        f"ListExecutions: expected exactly the original and the fresh execution, got {names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
