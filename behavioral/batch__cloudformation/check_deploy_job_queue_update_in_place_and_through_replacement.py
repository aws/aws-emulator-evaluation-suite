"""deploy-job-queue-update-in-place-and-through-replacement."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-job-queue-update-in-place-and-through-replacement"
GROUP = "deploy"
SERVICES = ["batch", "cloudformation"]

_STACK_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})


def _await_stack(cfn, stack_id: str, timeout_s: float = 600.0, period_s: float = 3.0) -> str:
    """Block on DescribeStacks(StackName=stack_id) until a terminal StackStatus; return it."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _STACK_TERMINAL:
            return status
        time.sleep(period_s)
    raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")


def _tear_down(cfn, stack_id: str) -> None:
    """Delete ``stack_id`` and wait it out; raise unless it ends DELETE_COMPLETE."""
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status != "DELETE_COMPLETE":
        cfn.delete_stack(StackName=stack_id)
        status = _await_stack(cfn, stack_id)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}, expected DELETE_COMPLETE")


def _stack_outputs(cfn, stack_id: str) -> dict:
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _ordered_events(cfn, stack_id: str) -> list:
    """(LogicalResourceId, ResourceStatus) of every non-"_IN_PROGRESS" event, oldest first."""
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    rows = [e for page in pages for e in page["StackEvents"]]
    rows.reverse()
    return [(e["LogicalResourceId"], e["ResourceStatus"]) for e in rows
            if not e["ResourceStatus"].endswith("_IN_PROGRESS")]


def _is_ordered_subsequence(needles: list, haystack: list) -> bool:
    """True if every item of ``needles`` occurs in ``haystack``, in that relative order."""
    it = iter(haystack)
    return all(any(item == needle for item in it) for needle in needles)


def _poll_until(probe, ok, timeout_s: float = 180.0, period_s: float = 3.0):
    """Call ``probe()`` until ``ok(result)`` holds; return that result or raise on timeout."""
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not ok(result):
        if time.monotonic() > deadline:
            raise AssertionError(f"condition not met within {timeout_s:.0f}s; last read {result!r}")
        time.sleep(period_s)
        result = probe()
    return result


def _template(ce_name: str, jq_name: str, priority: int, subnet_ids: list, sg_id: str) -> str:
    return json.dumps({
        "Resources": {
            "CE": {
                "Type": "AWS::Batch::ComputeEnvironment",
                "Properties": {
                    "ComputeEnvironmentName": ce_name,
                    "Type": "MANAGED",
                    "ComputeResources": {
                        "Type": "FARGATE",
                        "MaxvCpus": 2,
                        "Subnets": subnet_ids,
                        "SecurityGroupIds": [sg_id],
                    },
                },
            },
            "JQ": {
                "Type": "AWS::Batch::JobQueue",
                "Properties": {
                    "JobQueueName": jq_name,
                    "Priority": priority,
                    "ComputeEnvironmentOrder": [{"Order": 1, "ComputeEnvironment": {"Ref": "CE"}}],
                },
            },
        },
        "Outputs": {
            "CERef": {"Value": {"Ref": "CE"}},
            "JQRef": {"Value": {"Ref": "JQ"}},
            "JQArnAtt": {"Value": {"Fn::GetAtt": ["JQ", "JobQueueArn"]}},
        },
    })


def _job_queue(batch, arn: str) -> dict:
    found = batch.describe_job_queues(jobQueues=[arn])["jobQueues"]
    assert len(found) == 1, f"describe_job_queues({arn!r}) returned {found!r}"
    return found[0]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AWS::Batch::JobQueue's schema marks Priority mutable and JobQueueName createOnly: a
    Priority-only UpdateStack keeps the queue's ARN, while a JobQueueName change replaces it and
    the stack's cleanup phase removes the old ARN from Batch's own listing.
    """
    cfn = ctx.client("cloudformation")
    batch = ctx.client("batch")
    network = ctx.network()
    subnet_ids, sg_id = network.subnet_ids, network.security_group_id

    ce_name = ctx.unique_name("sim2real-batch-jqupd-ce-")
    jq_name_1 = ctx.unique_name("sim2real-batch-jqupd-a-")
    stack_name = ctx.unique_name("sim2real-batch-jqupd-stack-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(ce_name, jq_name_1, 1, subnet_ids, sg_id),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _tear_down(cfn, stack_id))
    status = _await_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack create ended {status!r}, expected CREATE_COMPLETE"

    out = _stack_outputs(cfn, stack_id)
    ce_arn, jq_arn_1 = out["CERef"], out["JQRef"]
    assert out["JQArnAtt"] == jq_arn_1, f"GetAtt JobQueueArn {out['JQArnAtt']!r} != Ref {jq_arn_1!r}"

    _poll_until(lambda: batch.describe_compute_environments(computeEnvironments=[ce_arn])
                ["computeEnvironments"][0],
                lambda ce: ce["status"] == "VALID")
    jq = _poll_until(lambda: _job_queue(batch, jq_arn_1), lambda q: q["status"] == "VALID")
    assert (jq["jobQueueName"], jq["priority"]) == (jq_name_1, 1), (
        f"job queue reads name {jq['jobQueueName']!r}, priority {jq['priority']!r}, expected "
        f"{jq_name_1!r} and 1"
    )

    # Priority is "No interruption" in the resource schema: updating it in place keeps the ARN.
    cfn.update_stack(
        StackName=stack_id, TemplateBody=_template(ce_name, jq_name_1, 5, subnet_ids, sg_id)
    )
    status = _await_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"priority update ended {status!r}, expected UPDATE_COMPLETE"
    out = _stack_outputs(cfn, stack_id)
    assert out["JQRef"] == jq_arn_1, (
        f"an in-place Priority update changed the job queue ARN to {out['JQRef']!r}, expected it "
        f"to stay {jq_arn_1!r}"
    )
    jq = _poll_until(lambda: _job_queue(batch, jq_arn_1), lambda q: q["priority"] == 5)
    assert jq["jobQueueName"] == jq_name_1, f"in-place update changed the name to {jq['jobQueueName']!r}"

    # JobQueueName is "Replacement": changing it swaps in a new job queue under a new ARN.
    jq_name_2 = ctx.unique_name("sim2real-batch-jqupd-b-")
    cfn.update_stack(
        StackName=stack_id, TemplateBody=_template(ce_name, jq_name_2, 5, subnet_ids, sg_id)
    )
    status = _await_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"name update ended {status!r}, expected UPDATE_COMPLETE"
    out = _stack_outputs(cfn, stack_id)
    jq_arn_2 = out["JQRef"]
    assert jq_arn_2 != jq_arn_1, (
        "a JobQueueName update must replace the job queue under a new ARN, not update it in place"
    )

    events = _ordered_events(cfn, stack_id)
    want = [("JQ", "CREATE_COMPLETE"), ("JQ", "DELETE_COMPLETE"), (stack_name, "UPDATE_COMPLETE")]
    assert _is_ordered_subsequence(want, events), (
        f"a replacement creates the new job queue and deletes the old one during the update's "
        f"cleanup phase: expected the ordered subsequence {want!r} in {events!r}"
    )

    jq = _poll_until(lambda: _job_queue(batch, jq_arn_2), lambda q: q["status"] == "VALID")
    assert (jq["jobQueueName"], jq["priority"]) == (jq_name_2, 5), (
        f"replacement job queue reads name {jq['jobQueueName']!r}, priority {jq['priority']!r}, "
        f"expected {jq_name_2!r} and 5"
    )
    gone = _poll_until(lambda: batch.describe_job_queues(jobQueues=[jq_arn_1])["jobQueues"],
                       lambda found: found == [])
    assert gone == [], f"Batch still lists the replaced job queue: {gone!r}"

    _tear_down(cfn, stack_id)
    after_jq = batch.describe_job_queues(jobQueues=[jq_arn_2])["jobQueues"]
    after_ce = batch.describe_compute_environments(computeEnvironments=[ce_arn])["computeEnvironments"]
    assert (after_jq, after_ce) == ([], []), (
        f"after the stack delete Batch lists job queue {after_jq!r} and compute environment "
        f"{after_ce!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
