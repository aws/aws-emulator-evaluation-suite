"""express-sync-execution."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "express-sync-execution"
GROUP = 'express_workflows'
SERVICES = ['stepfunctions']

def _role_arn(ctx):
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
        roleArn=_role_arn(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": "behav"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_sync_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    return sfn.start_sync_execution(**kwargs)

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSyncExecution on an EXPRESS state machine returns the finished result in its own response:
    status SUCCEEDED and output {"express": true}. EXPRESS executions have no other reader:
    DescribeExecution and GetExecutionHistory do not support them."""
    definition = {
        "StartAt": "P",
        "States": {"P": {"Type": "Pass", "Result": {"express": True}, "End": True}},
    }
    sm_arn = _create_state_machine(ctx, definition, sm_type="EXPRESS")
    resp = _start_sync_execution(ctx, sm_arn, input_data={})
    assert resp["status"] == "SUCCEEDED", (
        f'StartSyncExecution returned status {resp["status"]!r}, expected SUCCEEDED: '
        f'{resp.get("error")!r} {resp.get("cause")!r}'
    )
    output = json.loads(resp["output"])
    assert output == {"express": True}, (
        f"StartSyncExecution returned output {output!r}, expected {{'express': True}} — "
        "the Pass state's static Result"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
