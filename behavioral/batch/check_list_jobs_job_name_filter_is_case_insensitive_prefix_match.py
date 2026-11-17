"""list-jobs-job-name-filter-is-case-insensitive-prefix-match."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-jobs-job-name-filter-is-case-insensitive-prefix-match"
GROUP = "job-listing"
SERVICES = ["batch", "ecs", "iam"]

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "batch.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_SERVICE_ROLE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); raise naming the last value seen at the deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last saw {last!r}")


def _delete_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SERVICE_ROLE_POLICY)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _service_role(ctx):
    """Create this run's own Batch service role for an UNMANAGED compute environment."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-batch-unmgd-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SERVICE_ROLE_POLICY)
    return arn


def _create_ce(ctx, bat, role_arn):
    bat_name = ctx.unique_name("sim2real-behav-ce-")
    last_exc = None
    for attempt in range(10):
        try:
            arn = bat.create_compute_environment(
                computeEnvironmentName=bat_name,
                type="UNMANAGED",
                state="ENABLED",
                serviceRole=role_arn,
                tags={"sim2real:managed": "true"},
            )["computeEnvironmentArn"]
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "").lower()
            if "cannot be assumed" not in msg and "not authorized" not in msg and "sts:assumerole" not in msg:
                raise
            last_exc = exc
            time.sleep(4)
    else:
        raise last_exc
    ctx.on_cleanup(lambda: _teardown_ce(bat, bat_name))
    ce = _poll_until(
        lambda: bat.describe_compute_environments(computeEnvironments=[bat_name])["computeEnvironments"][0],
        lambda c: c["status"] in ("VALID", "INVALID"),
        description=f"compute environment {bat_name} settles",
    )
    assert ce["status"] == "VALID", f"compute environment did not validate: {ce.get('statusReason')!r}"
    return bat_name, arn


def _teardown_ce(bat, name):
    if not bat.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]:
        return
    bat.update_compute_environment(computeEnvironment=name, state="DISABLED")
    _poll_until(
        lambda: bat.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        description=f"compute environment {name} disabled",
    )
    deadline = time.monotonic() + 300.0
    while True:
        try:
            bat.delete_compute_environment(computeEnvironment=name)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    _poll_until(
        lambda: bat.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"],
        lambda envs: not envs or envs[0]["status"] == "DELETED",
        timeout_s=300.0,
        interval_s=5.0,
        description=f"compute environment {name} deleted",
    )


def _create_queue(ctx, bat, ce_arn):
    jq_name = ctx.unique_name("sim2real-behav-jq-")
    jq_arn = bat.create_job_queue(
        jobQueueName=jq_name,
        state="ENABLED",
        priority=1,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags={"sim2real:managed": "true"},
    )["jobQueueArn"]
    ctx.on_cleanup(lambda: _teardown_queue(bat, jq_name))
    jq = _poll_until(
        lambda: bat.describe_job_queues(jobQueues=[jq_name])["jobQueues"][0],
        lambda q: q["status"] in ("VALID", "INVALID"),
        description=f"job queue {jq_name} settles",
    )
    assert jq["status"] == "VALID", f"job queue did not validate: {jq.get('statusReason')!r}"
    return jq_name


def _teardown_queue(bat, name):
    if not bat.describe_job_queues(jobQueues=[name])["jobQueues"]:
        return
    bat.update_job_queue(jobQueue=name, state="DISABLED")
    _poll_until(
        lambda: bat.describe_job_queues(jobQueues=[name])["jobQueues"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        description=f"job queue {name} disabled",
    )
    bat.delete_job_queue(jobQueue=name)
    _poll_until(
        lambda: bat.describe_job_queues(jobQueues=[name])["jobQueues"],
        lambda qs: not qs or qs[0]["status"] == "DELETED",
        timeout_s=300.0,
        interval_s=5.0,
        description=f"job queue {name} deleted",
    )


def _deregister_batch_jd(bat, ref):
    """Deregister one Batch job definition revision; an already-gone one is fine."""
    try:
        bat.deregister_job_definition(jobDefinition=ref)
    except ClientError as exc:
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise


def _sweep_ecs_task_defs(ctx, refs, *, budget_s=90.0, interval_s=5.0):
    """Remove the same-named ECS task definition registering a Batch job definition creates,
    which DeregisterJobDefinition never removes.

    Batch can create it asynchronously, well after DeregisterJobDefinition returns, so this
    runs LAST among this check's cleanups (registered first; LIFO) and polls a bounded window
    rather than firing once right after the create -- a ref that never appears was never
    pushed to ECS and is not a leak.
    """
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + budget_s
    remaining = set(refs)
    while remaining and time.monotonic() < deadline:
        for ref in list(remaining):
            try:
                ecs.deregister_task_definition(taskDefinition=ref)
            except ClientError as exc:
                message = exc.response["Error"].get("Message", "")
                if "does not exist" in message or "Unable to describe task definition" in message:
                    continue
                raise
            failures = ecs.delete_task_definitions(taskDefinitions=[ref]).get("failures") or []
            assert not failures, f"DeleteTaskDefinitions refused {ref}: {failures!r}"
            remaining.discard(ref)
        if remaining:
            time.sleep(interval_s)


def _register_jd(ctx, bat, jd_refs):
    jd_name = ctx.unique_name("sim2real-behav-jd-")
    resp = bat.register_job_definition(
        jobDefinitionName=jd_name,
        type="container",
        containerProperties={
            "image": "busybox:1.36",
            "command": ["echo", "hi"],
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "512"},
            ],
        },
    )
    ref = f"{jd_name}:{resp['revision']}"
    jd_refs.append(ref)
    ctx.on_cleanup(lambda: _deregister_batch_jd(bat, ref))
    return resp["jobDefinitionArn"]


def _submit(ctx, bat, jq_name, jd_arn, job_name):
    job_id = bat.submit_job(jobName=job_name, jobQueue=jq_name, jobDefinition=jd_arn)["jobId"]
    ctx.on_cleanup(lambda: _terminate(bat, job_id))
    return job_id


def _terminate(bat, job_id):
    job = bat.describe_jobs(jobs=[job_id])["jobs"]
    if job and job[0]["status"] not in ("SUCCEEDED", "FAILED"):
        bat.terminate_job(jobId=job_id, reason="behavioral check teardown")
        _poll_until(
            lambda: bat.describe_jobs(jobs=[job_id])["jobs"][0]["status"],
            lambda s: s in ("SUCCEEDED", "FAILED"),
            timeout_s=180.0,
            interval_s=3.0,
            description=f"job {job_id} reaches terminal",
        )


def _job_name_filter(bat, jq_name, value):
    return {
        j["jobId"]
        for j in bat.list_jobs(jobQueue=jq_name, filters=[{"name": "JOB_NAME", "values": [value]}])[
            "jobSummaryList"
        ]
    }


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListJobs' JOB_NAME filter matches case-insensitively, a trailing '*' matches by prefix, and
    a value naming no job returns an empty list rather than every job in the queue."""
    bat = ctx.client("batch")
    jd_refs: list[str] = []
    ctx.on_cleanup(lambda: _sweep_ecs_task_defs(ctx, jd_refs))
    role_arn = _service_role(ctx)
    ce_name, ce_arn = _create_ce(ctx, bat, role_arn)
    jq_name = _create_queue(ctx, bat, ce_arn)
    jd_arn = _register_jd(ctx, bat, jd_refs)

    name_mixed = ctx.unique_name("sim2real-behav-Finch-")
    name_lower = ctx.unique_name("sim2real-behav-finch-")
    name_other = ctx.unique_name("sim2real-behav-Heron-")

    id_mixed = _submit(ctx, bat, jq_name, jd_arn, name_mixed)
    id_lower = _submit(ctx, bat, jq_name, jd_arn, name_lower)
    id_other = _submit(ctx, bat, jq_name, jd_arn, name_other)

    prefix_value = "sim2real-behav-finch-*"
    matched = _poll_until(
        lambda: _job_name_filter(bat, jq_name, prefix_value),
        lambda ids: {id_mixed, id_lower, id_other} & ids == {id_mixed, id_lower},
        description="JOB_NAME prefix filter converges on both finch jobs",
    )
    assert matched == {id_mixed, id_lower}, (
        f"JOB_NAME={prefix_value!r} matched {matched!r}, expected exactly {{id_mixed, id_lower}}"
    )

    exact_value = name_mixed.upper()
    exact_matched = _poll_until(
        lambda: _job_name_filter(bat, jq_name, exact_value),
        lambda ids: ids == {id_mixed},
        description="JOB_NAME exact case-insensitive filter converges on the mixed-case job",
    )
    assert exact_matched == {id_mixed}, (
        f"JOB_NAME={exact_value!r} matched {exact_matched!r}, expected only the mixed-case job"
    )

    no_match = _job_name_filter(bat, jq_name, "sim2real-behav-nonexistent-prefix-*")
    assert no_match == set(), f"a prefix naming no job must match nothing, got {no_match!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
