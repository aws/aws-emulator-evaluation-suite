"""deploy-job-queue-rejects-priority-above-maximum."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-job-queue-rejects-priority-above-maximum"
GROUP = "deploy"
SERVICES = ["batch", "cloudformation"]

_STACK_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})
_VALIDATION_FAILED = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
    "with resource and property details, resolve each error, then retry the operation."
)


def _await_stack(cfn, stack_id: str, timeout_s: float = 300.0, period_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _STACK_TERMINAL:
            return status
        time.sleep(period_s)
    raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")


def _poll_until(probe, ok, timeout_s: float = 180.0, period_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not ok(result):
        if time.monotonic() > deadline:
            raise AssertionError(f"condition not met within {timeout_s:.0f}s; last read {result!r}")
        time.sleep(period_s)
        result = probe()
    return result


def _stack_create_failure(cfn, stack_id: str) -> str:
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for e in page["StackEvents"]:
            if e["LogicalResourceId"] == stack_id.split("/")[-2] and e["ResourceStatus"] == "CREATE_FAILED":
                return e["ResourceStatusReason"]
    raise AssertionError(f"no stack-level CREATE_FAILED event for {stack_id}")


def _disable_and_delete(cfn, batch, stack_id: str, se_name: str, jq_name: str) -> None:
    """Disable the job queue and service environment (if Batch ever created them), then delete."""
    queues = batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"]
    if queues and queues[0]["state"] != "DISABLED":
        batch.update_job_queue(jobQueue=jq_name, state="DISABLED")
        _poll_until(lambda: batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"][0],
                    lambda q: q["state"] == "DISABLED")
    envs = batch.describe_service_environments(serviceEnvironments=[se_name])["serviceEnvironments"]
    if envs and envs[0]["state"] != "DISABLED":
        batch.update_service_environment(serviceEnvironment=se_name, state="DISABLED")
        _poll_until(
            lambda: batch.describe_service_environments(serviceEnvironments=[se_name])
            ["serviceEnvironments"][0],
            lambda s: s["state"] == "DISABLED",
        )
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status != "DELETE_COMPLETE":
        cfn.delete_stack(StackName=stack_id)
        status = _await_stack(cfn, stack_id)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}, expected DELETE_COMPLETE")


def _template(se_name: str, jq_name: str, sp_name: str, priority: int) -> str:
    return json.dumps({
        "Resources": {
            "SP": {
                "Type": "AWS::Batch::SchedulingPolicy",
                "Properties": {
                    "Name": sp_name,
                    "QuotaSharePolicy": {"IdleResourceAssignmentStrategy": "FIFO"},
                },
            },
            "SE": {
                "Type": "AWS::Batch::ServiceEnvironment",
                "Properties": {
                    "ServiceEnvironmentName": se_name,
                    "ServiceEnvironmentType": "SAGEMAKER_TRAINING",
                    "CapacityLimits": [{"MaxCapacity": 1, "CapacityUnit": "ml.m6i.large"}],
                },
            },
            "JQ": {
                "Type": "AWS::Batch::JobQueue",
                "Properties": {
                    "JobQueueName": jq_name,
                    "JobQueueType": "SAGEMAKER_TRAINING",
                    "Priority": priority,
                    "SchedulingPolicyArn": {"Ref": "SP"},
                    "ServiceEnvironmentOrder": [{"Order": 1, "ServiceEnvironment": {"Ref": "SE"}}],
                },
            },
        },
        "Outputs": {"SERef": {"Value": {"Ref": "SE"}}, "JQRef": {"Value": {"Ref": "JQ"}}},
    })


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A JobQueue's Priority above the schema's maximum of 1000 fails CloudFormation's own
    template validation before any resource is created, while the same template at Priority 1000
    deploys and reads back from Batch.
    """
    cfn = ctx.client("cloudformation")
    batch = ctx.client("batch")

    ok_se = ctx.unique_name("sim2real-batch-jqprio-ok-se-")
    ok_jq = ctx.unique_name("sim2real-batch-jqprio-ok-jq-")
    ok_sp = ctx.unique_name("sim2real-batch-jqprio-ok-sp-")
    ok_stack = ctx.unique_name("sim2real-batch-jqprio-ok-stack-")
    ok_stack_id = cfn.create_stack(
        StackName=ok_stack, TemplateBody=_template(ok_se, ok_jq, ok_sp, 1000)
    )["StackId"]
    ctx.on_cleanup(lambda: _disable_and_delete(cfn, batch, ok_stack_id, ok_se, ok_jq))
    status = _await_stack(cfn, ok_stack_id)
    assert status == "CREATE_COMPLETE", f"positive control stack ended {status!r}"
    se = _poll_until(lambda: batch.describe_service_environments(serviceEnvironments=[ok_se])
                      ["serviceEnvironments"][0], lambda s: s["status"] == "VALID")
    assert se["serviceEnvironmentArn"], f"service environment missing an ARN: {se!r}"
    jq = _poll_until(lambda: batch.describe_job_queues(jobQueues=[ok_jq])["jobQueues"][0],
                      lambda q: q["status"] == "VALID")
    assert (jq["jobQueueName"], jq["priority"]) == (ok_jq, 1000), (
        f"positive control job queue reads name {jq['jobQueueName']!r}, priority {jq['priority']!r}"
    )

    bad_se = ctx.unique_name("sim2real-batch-jqprio-bad-se-")
    bad_jq = ctx.unique_name("sim2real-batch-jqprio-bad-jq-")
    bad_sp = ctx.unique_name("sim2real-batch-jqprio-bad-sp-")
    bad_stack = ctx.unique_name("sim2real-batch-jqprio-bad-stack-")
    bad_stack_id = cfn.create_stack(
        StackName=bad_stack, TemplateBody=_template(bad_se, bad_jq, bad_sp, 1001)
    )["StackId"]
    ctx.on_cleanup(lambda: _disable_and_delete(cfn, batch, bad_stack_id, bad_se, bad_jq))
    status = _await_stack(cfn, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack with Priority 1001 ended {status!r}, expected ROLLBACK_COMPLETE"
    )
    reason = _stack_create_failure(cfn, bad_stack_id)
    assert reason == _VALIDATION_FAILED, reason

    gone = (batch.describe_service_environments(serviceEnvironments=[bad_se])["serviceEnvironments"],
            batch.describe_job_queues(jobQueues=[bad_jq])["jobQueues"])
    assert gone == ([], []), (
        f"the rejected create left Batch resources named {bad_se!r}/{bad_jq!r}: {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
