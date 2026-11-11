"""express-sync-execution-id-carries-express-arn-form."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "express-sync-execution-id-carries-express-arn-form"
GROUP = 'context_object'
SERVICES = ['stepfunctions']


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """In a synchronous Express execution, $$.Execution.Id is the response's own
    executionArn, whose resource type is 'express', not the 'execution' form a STANDARD
    machine's $$.Execution.Id carries for the same Pass state and input.
    """
    role_arn = _create_sfn_role(ctx)
    definition = {
        "StartAt": "Ctx",
        "States": {
            "Ctx": {"Type": "Pass", "Parameters": {"execId.$": "$$.Execution.Id"}, "End": True},
        },
    }
    exec_name = ctx.unique_name("sim2real-behav-exprid-")
    input_data = {"marker": ctx.unique_name("m-")}

    standard_arn = _create_state_machine(ctx, definition, role_arn, "STANDARD")
    standard = _run_standard(ctx, standard_arn, exec_name, input_data)
    assert standard["status"] == "SUCCEEDED", (
        f"STANDARD control execution {standard['status']!r}: error={standard.get('error')!r}"
    )
    standard_id = json.loads(standard["output"])["execId"]
    assert standard_id == standard["executionArn"], (
        f"STANDARD $$.Execution.Id {standard_id!r} != DescribeExecution's executionArn "
        f"{standard['executionArn']!r}"
    )
    assert re.fullmatch(
        rf"arn:aws:states:{re.escape(ctx.region)}:{re.escape(ctx.account)}:execution:"
        rf"{re.escape(standard_arn.rsplit(':', 1)[-1])}:{re.escape(exec_name)}",
        standard_id,
    ), f"STANDARD $$.Execution.Id {standard_id!r} is not an 'execution:' ARN"

    express_arn = _create_state_machine(ctx, definition, role_arn, "EXPRESS")
    express = ctx.client("stepfunctions").start_sync_execution(
        stateMachineArn=express_arn, name=exec_name, input=json.dumps(input_data)
    )
    assert express["status"] == "SUCCEEDED", (
        f"EXPRESS execution {express['status']!r}: error={express.get('error')!r} "
        f"cause={express.get('cause')!r}"
    )
    express_id = json.loads(express["output"])["execId"]
    assert express_id == express["executionArn"], (
        f"EXPRESS $$.Execution.Id {express_id!r} != StartSyncExecution's own executionArn "
        f"{express['executionArn']!r}"
    )
    assert re.fullmatch(
        rf"arn:aws:states:{re.escape(ctx.region)}:{re.escape(ctx.account)}:express:"
        rf"{re.escape(express_arn.rsplit(':', 1)[-1])}:{re.escape(exec_name)}:"
        rf"[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}",
        express_id,
    ), f"EXPRESS $$.Execution.Id {express_id!r} is not an 'express:' ARN with a trailing UUID"


def _create_sfn_role(ctx):
    """A bare execution role: a single Pass state calls no AWS API on the customer's behalf."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-exprid-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn express-id execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn, sm_type):
    """Create a state machine of ``sm_type``, absorbing IAM trust propagation with a retry."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-exprid-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine kept refusing the freshly created role: {last!r}")


def _stop_if_running(sfn, exec_arn):
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _run_standard(ctx, sm_arn, exec_name, input_data, *, timeout_s=60.0):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=exec_name, input=json.dumps(input_data)
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return desc
        time.sleep(2)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
