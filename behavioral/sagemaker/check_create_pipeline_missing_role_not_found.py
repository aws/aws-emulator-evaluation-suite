"""create-pipeline-missing-role-not-found."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-pipeline-missing-role-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:negative-delivery", "cap:c1", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A pipeline step fails naming the missing role when RoleArn names no real role and sends no
    SQS message; with a real role an otherwise identical pipeline delivers the callback."""
    sm = ctx.client("sagemaker")
    sqs = ctx.client("sqs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # CreatePipeline and StartPipelineExecution both accept this role; only the step resolves it.
    bogus_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-behav-no-such-role-')}"
    bad_queue_url = _create_queue(ctx, sqs, "sim2real-behav-pipe-cb-bad-")
    bad_pipeline_name = ctx.unique_name("sim2real-behav-pipe-bad-")
    sm.create_pipeline(
        PipelineName=bad_pipeline_name,
        ClientRequestToken=str(uuid.uuid4()),
        RoleArn=bogus_role_arn,
        PipelineDefinition=_callback_definition(bad_queue_url),
    )
    ctx.on_cleanup(
        lambda: sm.delete_pipeline(PipelineName=bad_pipeline_name, ClientRequestToken=str(uuid.uuid4()))
    )
    bad_exec_arn = sm.start_pipeline_execution(
        PipelineName=bad_pipeline_name, ClientRequestToken=str(uuid.uuid4())
    )["PipelineExecutionArn"]

    bad_status = _wait_terminal(sm, bad_exec_arn, timeout_s=90.0)
    assert bad_status["PipelineExecutionStatus"] == "Failed", (
        f"expected the pipeline execution to fail when RoleArn names no real role, got "
        f"{bad_status['PipelineExecutionStatus']!r}"
    )
    bad_step = _sole_step(sm, bad_exec_arn)
    assert bad_step["StepStatus"] == "Failed", (
        f"expected the callback step itself to fail, got {bad_step['StepStatus']!r}"
    )
    reason = bad_step.get("FailureReason", "")
    assert bogus_role_arn in reason and "does not exist" in reason, (
        f"expected the step failure to name the missing role {bogus_role_arn!r} as not "
        f"existing, got {reason!r}"
    )

    # Effect absent, on an independent side channel: the queue never received the callback
    # message the step would have sent had the role resolved.
    depth = sqs.get_queue_attributes(
        QueueUrl=bad_queue_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert depth == "0", (
        f"expected zero messages on {bad_queue_url} when the role does not exist, got {depth}"
    )

    # Positive control: an otherwise-identical pipeline with a real, permitted role delivers.
    role_arn = _create_sagemaker_role(ctx)
    good_queue_url = _create_queue(ctx, sqs, "sim2real-behav-pipe-cb-ok-")
    good_pipeline_name = ctx.unique_name("sim2real-behav-pipe-ok-")
    good_exec_arn = _start_execution_with_retry(
        ctx,
        sm,
        pipeline_name=good_pipeline_name,
        role_arn=role_arn,
        definition=_callback_definition(good_queue_url),
        queue_url=good_queue_url,
    )

    message = _wait_for_message(sqs, good_queue_url, timeout_s=60.0)
    assert message is not None, (
        f"expected the real role to let the callback step deliver a message to "
        f"{good_queue_url}, but none arrived"
    )

    # Terminal, independent read: the step is Executing (delivered, awaiting the callback
    # token), never Failed for a missing role.
    good_step = _sole_step(sm, good_exec_arn)
    assert good_step["StepStatus"] == "Executing", (
        f"expected the callback step to be Executing (delivered) with a real role, got "
        f"{good_step['StepStatus']!r}, reason={good_step.get('FailureReason')!r}"
    )
    assert good_step.get("Metadata", {}).get("Callback", {}).get("CallbackToken"), (
        f"expected a CallbackToken to have been issued once the message was delivered, got "
        f"{good_step.get('Metadata')!r}"
    )

    sm.stop_pipeline_execution(PipelineExecutionArn=good_exec_arn, ClientRequestToken=str(uuid.uuid4()))


def _callback_definition(queue_url: str) -> str:
    return json.dumps(
        {
            "Version": "2020-12-01",
            "Steps": [
                {
                    "Name": "Sim2RealCallbackStep",
                    "Type": "Callback",
                    "SqsQueueUrl": queue_url,
                    "Arguments": {},
                }
            ],
        }
    )


def _create_queue(ctx, sqs, prefix: str) -> str:
    queue_name = ctx.unique_name(prefix)
    queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    return queue_url


def _wait_terminal(sm, exec_arn: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = sm.describe_pipeline_execution(PipelineExecutionArn=exec_arn)
    while last["PipelineExecutionStatus"] == "Executing" and time.monotonic() < deadline:
        time.sleep(3.0)
        last = sm.describe_pipeline_execution(PipelineExecutionArn=exec_arn)
    if last["PipelineExecutionStatus"] == "Executing":
        raise AssertionError(f"pipeline execution {exec_arn} never reached a terminal state within {timeout_s}s")
    return last


def _sole_step(sm, exec_arn: str, *, wait_s: float = 0.0) -> dict:
    deadline = time.monotonic() + wait_s
    steps = sm.list_pipeline_execution_steps(PipelineExecutionArn=exec_arn)["PipelineExecutionSteps"]
    while not steps and time.monotonic() < deadline:
        time.sleep(2.0)
        steps = sm.list_pipeline_execution_steps(PipelineExecutionArn=exec_arn)["PipelineExecutionSteps"]
    assert len(steps) == 1, f"expected exactly one step for {exec_arn}, got {len(steps)}"
    return steps[0]


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-pipe-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSQSFullAccess"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSQSFullAccess"
        )
    )
    return resp["Role"]["Arn"]


def _start_execution_with_retry(ctx, sm, *, pipeline_name, role_arn, definition, queue_url, timeout_s=60.0):
    # IAM roles are eventually consistent; a role that was just created may not yet be
    # assumable by the pipeline's first execution attempt. Poll by starting fresh executions
    # against a single created pipeline until one gets past role resolution.
    sm.create_pipeline(
        PipelineName=pipeline_name,
        ClientRequestToken=str(uuid.uuid4()),
        RoleArn=role_arn,
        PipelineDefinition=definition,
    )
    ctx.on_cleanup(
        lambda: sm.delete_pipeline(PipelineName=pipeline_name, ClientRequestToken=str(uuid.uuid4()))
    )
    deadline = time.monotonic() + timeout_s
    last_step = None
    while time.monotonic() < deadline:
        exec_arn = sm.start_pipeline_execution(
            PipelineName=pipeline_name, ClientRequestToken=str(uuid.uuid4())
        )["PipelineExecutionArn"]
        deadline_step = time.monotonic() + 20.0
        last_step = _sole_step(sm, exec_arn, wait_s=20.0)
        while last_step["StepStatus"] == "Starting" and time.monotonic() < deadline_step:
            time.sleep(2.0)
            last_step = _sole_step(sm, exec_arn)
        if last_step["StepStatus"] == "Executing":
            return exec_arn
        try:
            sm.stop_pipeline_execution(PipelineExecutionArn=exec_arn, ClientRequestToken=str(uuid.uuid4()))
        except ClientError:
            pass  # already in a terminal state; nothing to stop
        time.sleep(3.0)
    raise AssertionError(
        f"pipeline execution for {pipeline_name} never got past role resolution within "
        f"{timeout_s}s: last step was {last_step}"
    )


def _wait_for_message(sqs, queue_url: str, *, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        messages = resp.get("Messages") or []
        if messages:
            return messages[0]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
