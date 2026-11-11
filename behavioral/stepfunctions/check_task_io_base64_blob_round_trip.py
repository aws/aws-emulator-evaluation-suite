"""task-io-base64-blob-round-trip."""
from __future__ import annotations

import base64
import json
import os
import time

from behavioral_harness import tags

CHECK = "task-io-base64-blob-round-trip"
GROUP = "representation"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A base64-encoded binary blob passed as activity task input and echoed back
    unchanged via SendTaskSuccess output is preserved byte-for-byte in the final
    execution output returned by DescribeExecution."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_role_for_state_machine(ctx)

    activity_name = ctx.unique_name("sim2real-sfn-blobact-")
    activity_arn = sfn.create_activity(name=activity_name)["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))

    definition = json.dumps(
        {
            "StartAt": "DoTask",
            "States": {"DoTask": {"Type": "Task", "Resource": activity_arn, "End": True}},
        }
    )
    sm_name = ctx.unique_name("sim2real-sfn-blobsm-")
    sm_arn = sfn.create_state_machine(name=sm_name, definition=definition, roleArn=role_arn)[
        "stateMachineArn"
    ]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    blob_b64 = base64.b64encode(os.urandom(48)).decode("ascii")
    input_payload = {"blob": blob_b64}

    exec_name = ctx.unique_name("sim2real-sfn-blobexec-")
    execution_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=exec_name, input=json.dumps(input_payload)
    )["executionArn"]

    task_token, task_input = _poll_for_activity_task(ctx, sfn, activity_arn, timeout_s=60)
    delivered = json.loads(task_input)
    assert delivered == input_payload, (
        f"activity task input diverged from execution input: expected {input_payload!r}, "
        f"got {delivered!r}"
    )

    sfn.send_task_success(taskToken=task_token, output=json.dumps({"blob": blob_b64}))

    desc = _wait_execution_terminal(ctx, sfn, execution_arn, timeout_s=60)
    assert desc["status"] == "SUCCEEDED", (
        f"expected execution status SUCCEEDED, got {desc['status']!r}: {desc}"
    )
    final_output = json.loads(desc["output"])
    assert final_output["blob"] == blob_b64, (
        f"final execution output blob diverged from the value sent via SendTaskSuccess: "
        f"expected {blob_b64!r}, got {final_output['blob']!r}"
    )
    original_bytes = base64.b64decode(blob_b64)
    round_tripped_bytes = base64.b64decode(final_output["blob"])
    assert round_tripped_bytes == original_bytes, (
        f"decoded blob bytes diverged after the round trip: expected {original_bytes!r}, "
        f"got {round_tripped_bytes!r}"
    )


def _create_role_for_state_machine(ctx) -> str:
    iam = ctx.client("iam")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_name = ctx.unique_name("sim2real-sfn-blobrole-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _poll_for_activity_task(ctx, sfn, activity_arn, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.get_activity_task(activityArn=activity_arn, workerName="sim2real-worker")
        token = resp.get("taskToken")
        if token:
            return token, resp["input"]
    raise AssertionError(f"no activity task became available within {timeout_s}s")


def _wait_execution_terminal(ctx, sfn, execution_arn, timeout_s=60.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=execution_arn)
        if desc["status"] != "RUNNING":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"execution did not terminate in {timeout_s}s, last status: {desc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
