"""list-jobs-by-consumable-resource-returns-associated-jobs."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-jobs-by-consumable-resource-returns-associated-jobs"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListJobsByConsumableResource returns jobs that reference a given consumable resource
    in their submission, and stops returning them once the job is cancelled/terminal-scoped
    out by a status filter."""
    batch = ctx.client("batch")

    consumable_name = ctx.unique_name("sim2real-consumable-")
    consumable_arn = batch.create_consumable_resource(
        consumableResourceName=consumable_name,
        resourceType="REPLENISHABLE",
        totalQuantity=5,
        tags={"sim2real": CHECK},
    )["consumableResourceArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: batch.delete_consumable_resource(consumableResource=consumable_arn)))

    job_def_name = ctx.unique_name("sim2real-jobdef-")
    job_def_arn = batch.register_job_definition(
        jobDefinitionName=job_def_name,
        type="container",
        containerProperties={
            "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
            "command": ["echo", "hello"],
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "512"},
            ],
        },
        consumableResourceProperties={
            "consumableResourceList": [{"consumableResource": consumable_arn, "quantity": 1}]
        },
        tags={"sim2real": CHECK},
    )["jobDefinitionArn"]
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=job_def_arn))

    queue_arn = _create_bare_job_queue(ctx)

    job_name = ctx.unique_name("sim2real-job-")
    job_id = batch.submit_job(jobName=job_name, jobQueue=queue_arn, jobDefinition=job_def_arn)["jobId"]

    def _cancel_job():
        _best_effort(lambda: batch.terminate_job(jobId=job_id, reason="test-cleanup"))

    ctx.on_cleanup(_cancel_job)

    # The job has no compute environment to run on, so it parks in a non-terminal state
    # (e.g. RUNNABLE) referencing the consumable resource it was submitted with.
    matches = _poll_until(
        lambda: [j for j in _list_all_jobs_by_consumable_resource(batch, consumable_arn) if j["jobArn"]],
        lambda ms: any(m["jobName"] == job_name for m in ms),
        timeout_s=90,
    )
    match = next(m for m in matches if m["jobName"] == job_name)
    assert match["jobQueueArn"] == queue_arn, f"expected jobQueueArn {queue_arn!r}, got {match['jobQueueArn']!r}"
    assert match["jobDefinitionArn"].startswith(job_def_arn.rsplit(":", 1)[0]), (
        f"expected jobDefinitionArn to start with {job_def_arn.rsplit(':', 1)[0]!r}, got {match['jobDefinitionArn']!r}"
    )
    assert match["jobStatus"] in ("SUBMITTED", "PENDING", "RUNNABLE"), (
        f"expected a non-terminal status, got {match['jobStatus']!r}"
    )

    # Filtering by JOB_NAME narrows to exactly this job.
    filtered = batch.list_jobs_by_consumable_resource(
        consumableResource=consumable_arn, filters=[{"name": "JOB_NAME", "values": [job_name]}]
    )["jobs"]
    assert len(filtered) == 1, f"expected exactly 1 job for JOB_NAME={job_name!r}, got {len(filtered)}"
    assert filtered[0]["jobArn"] == match["jobArn"], (
        f"JOB_NAME filter returned a different job than the unfiltered listing: "
        f"{filtered[0]['jobArn']!r} != {match['jobArn']!r}"
    )

    # Terminate the job and confirm it drops out of the non-terminal status filter view.
    batch.terminate_job(jobId=job_id, reason="test-terminate")
    _poll_until(
        lambda: batch.describe_jobs(jobs=[job_id])["jobs"][0]["status"],
        lambda s: s == "FAILED",
        timeout_s=90,
    )
    # Real AWS Batch's ListJobsByConsumableResource permits only a single value per
    # JOB_STATUS filter, so query each non-terminal status separately and union results.
    still_runnable = []
    for status in ("RUNNABLE", "SUBMITTED", "PENDING"):
        still_runnable.extend(
            batch.list_jobs_by_consumable_resource(
                consumableResource=consumable_arn,
                filters=[{"name": "JOB_STATUS", "values": [status]}],
            )["jobs"]
        )
    assert all(j["jobName"] != job_name for j in still_runnable), (
        f"{job_name!r} still appears in a non-terminal JOB_STATUS filter after being terminated: {still_runnable!r}"
    )
    # Once a job reaches a terminal state it releases its consumable resource
    # association entirely: real AWS Batch's ListJobsByConsumableResource stops
    # returning the job under *any* status filter (including FAILED), not just the
    # non-terminal ones checked above. This is a secondary index that can lag behind
    # the authoritative DescribeJobs status by a few seconds, so poll the unfiltered
    # listing until the job has fully dropped out before asserting it's also absent
    # from the FAILED-filtered view.
    _poll_until(
        lambda: [j for j in _list_all_jobs_by_consumable_resource(batch, consumable_arn) if j["jobName"] == job_name],
        lambda matches: matches == [],
        timeout_s=90,
    )
    still_failed = batch.list_jobs_by_consumable_resource(
        consumableResource=consumable_arn, filters=[{"name": "JOB_STATUS", "values": ["FAILED"]}]
    )["jobs"]
    assert all(j["jobName"] != job_name for j in still_failed), (
        f"{job_name!r} still appears under a JOB_STATUS=FAILED filter after fully dropping out of the "
        f"unfiltered listing: {still_failed!r}"
    )


def _best_effort(fn: Callable[[], Any]) -> None:
    """Cleanup only: run fn() and ignore a service refusal (the resource may already be gone)."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "NoSuchEntity"
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _list_all_jobs_by_consumable_resource(batch, consumable_resource: str):
    out = []
    token = None
    while True:
        kwargs = {"consumableResource": consumable_resource}
        if token:
            kwargs["nextToken"] = token
        resp = batch.list_jobs_by_consumable_resource(**kwargs)
        out.extend(resp.get("jobs", []))
        token = resp.get("nextToken")
        if not token:
            return out


def _create_batch_service_role(ctx) -> str:
    """Real AWS Batch's CreateComputeEnvironment rejects requests without a serviceRole
    (there is no automatic service-linked role fallback in this account), so create a
    minimal IAM role Batch can assume and pass its ARN explicitly."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-svcrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "batch.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        _best_effort(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _best_effort(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_compute_environment_retrying_role_propagation(batch, *, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    """A freshly created IAM service role may not yet be assumable by Batch. Retry
    CreateComputeEnvironment on the specific propagation error real AWS returns, bounded,
    instead of a flat sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return batch.create_compute_environment(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code != "ClientException" or "role" not in message.lower():
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"service role never propagated within {timeout_s}s: {last_err}")


#: The suite's cleanup budget; the retries of every teardown of one run share one deadline in it.
_CLEANUP_BUDGET_S = 900.0
_cleanup_deadlines: dict[int, tuple[object, float]] = {}


def _teardown_ce(ctx, batch, name):
    """Disable and delete the compute environment, then wait until DescribeComputeEnvironments no
    longer lists it: the service role torn down after it must outlive the asynchronous delete.
    ClientException refusals (a queue still detaching, the CE still updating) retry every 2 s."""
    held = _cleanup_deadlines.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _cleanup_deadlines[id(ctx)] = (ctx, time.monotonic() + _CLEANUP_BUDGET_S)
    deadline = held[1]
    steps = [
        lambda: batch.update_compute_environment(computeEnvironment=name, state="DISABLED"),
        lambda: batch.delete_compute_environment(computeEnvironment=name),
    ]
    while True:
        listed = [
            ce
            for ce in batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
            if ce.get("status") != "DELETED"
        ]
        if not listed:
            return
        if steps and listed[0].get("status") != "DELETING":
            try:
                steps[0]()
                steps.pop(0)
                continue
            except ClientError as exc:
                err = exc.response["Error"]
                if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                    return
                if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                    raise
        elif time.monotonic() >= deadline:
            raise TimeoutError(f"compute environment {name} still listed at the cleanup deadline")
        time.sleep(2)


def _create_bare_job_queue(ctx) -> str:
    """Real AWS Batch requires every job queue to have at least one entry in
    computeEnvironmentOrder. An UNMANAGED compute environment with no registered
    container instances satisfies that requirement (and makes the queue VALID) while
    never actually running any submitted job, so it stays parked in a non-terminal
    status for the check to observe."""
    batch = ctx.client("batch")
    service_role_arn = _create_batch_service_role(ctx)

    ce_name = ctx.unique_name("sim2real-ce-")
    ce_arn = _create_compute_environment_retrying_role_propagation(
        batch,
        computeEnvironmentName=ce_name,
        type="UNMANAGED",
        state="ENABLED",
        serviceRole=service_role_arn,
        tags={"sim2real": CHECK},
    )["computeEnvironmentArn"]

    ctx.on_cleanup(lambda: _teardown_ce(ctx, batch, ce_name))
    _poll_until(
        lambda: batch.describe_compute_environments(computeEnvironments=[ce_arn])["computeEnvironments"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=120,
    )

    name = ctx.unique_name("sim2real-jq-")
    arn = batch.create_job_queue(
        jobQueueName=name,
        priority=1,
        state="ENABLED",
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags={"sim2real": CHECK},
    )["jobQueueArn"]

    def _cleanup():
        _best_effort(lambda: batch.update_job_queue(jobQueue=arn, state="DISABLED"))
        _poll_until(
            lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"][0]["status"],
            lambda s: s in ("VALID", "INVALID"),
            timeout_s=120,
        )
        batch.delete_job_queue(jobQueue=arn)

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[arn])["jobQueues"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        timeout_s=120,
    )
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
