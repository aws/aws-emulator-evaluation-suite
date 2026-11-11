"""fifo-scheduling-policy-preserves-submission-order-within-share."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "fifo-scheduling-policy-preserves-submission-order-within-share"
GROUP = "ordering"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Within a single shareIdentifier under a fair-share scheduling policy, jobs are
    returned by GetJobQueueSnapshot's frontOfQueue in the same order they were submitted
    (FIFO), independent of the fair-share weight machinery."""
    batch = ctx.client("batch")
    iam = ctx.client("iam")

    role_arn = _create_batch_unmanaged_service_role(ctx, iam)
    policy_arn = _create_fairshare_policy(ctx, batch, share_ids=["teamfifo"])
    ce_arn, ce_name = _create_unmanaged_compute_environment(ctx, batch, role_arn)
    jobdef_arn = _register_minimal_jobdef(ctx, batch)
    queue_arn, queue_name = _create_job_queue(ctx, batch, ce_arn, policy_arn)

    job_arns: list[str] = []
    for i in range(3):
        name = ctx.unique_name(f"sim2real-batch-fifo-j{i}-")
        resp = batch.submit_job(
            jobName=name,
            jobQueue=queue_arn,
            jobDefinition=jobdef_arn,
            shareIdentifier="teamfifo",
            schedulingPriorityOverride=1,
            tags=dict(_MANAGED_TAGS),
        )
        job_id = resp["jobId"]
        job_arns.append(resp["jobArn"])
        ctx.on_cleanup(lambda jid=job_id: _stop_job(batch, jid))
        # Space out submissions so real AWS orders them unambiguously by submission time.
        time.sleep(1.5)

    front = _poll_front_of_queue(batch, queue_arn, expected_arns=set(job_arns), timeout_s=90.0)
    positions = {arn: idx for idx, arn in enumerate(entry["jobArn"] for entry in front)}
    assert job_arns[0] in positions and job_arns[1] in positions and job_arns[2] in positions, (
        f"expected all 3 submitted jobs in frontOfQueue, got positions {positions}"
    )
    assert positions[job_arns[0]] < positions[job_arns[1]] < positions[job_arns[2]], (
        f"expected FIFO order within share, got positions {positions}"
    )


# ===== helpers =====

_MANAGED_TAGS = {
    "sim2real:managed": "true",
    "sim2real:prefix": "sim2real-batch-",
    "sim2real": "fifo-scheduling-policy-preserves-submission-order-within-share",
}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_batch_unmanaged_service_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-batch-svcrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "batch.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_tags_kv()
    )
    role_arn = resp["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole",
    )

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_fairshare_policy(ctx, batch, share_ids):
    name = ctx.unique_name("sim2real-batch-sp-")
    resp = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={
            "shareDecaySeconds": 0,
            "computeReservation": 0,
            "shareDistribution": [{"shareIdentifier": sid, "weightFactor": 1.0} for sid in share_ids],
        },
        tags=dict(_MANAGED_TAGS),
    )
    arn = resp["arn"]
    ctx.on_cleanup(lambda: _delete_scheduling_policy(batch, arn))
    return arn


def _retry_client_exception(call, timeout_s=120):
    """Retry a delete Batch refuses with ClientException while a dependency releases, every 2 s; then raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_scheduling_policy(batch, arn):
    _retry_client_exception(lambda: batch.delete_scheduling_policy(arn=arn), timeout_s=90)


def _create_unmanaged_compute_environment(ctx, batch, service_role_arn):
    ce_name = ctx.unique_name("sim2real-batch-ce-")
    deadline = time.monotonic() + 60
    ce_arn = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = batch.create_compute_environment(
                computeEnvironmentName=ce_name,
                type="UNMANAGED",
                state="ENABLED",
                serviceRole=service_role_arn,
                tags=dict(_MANAGED_TAGS),
            )
            ce_arn = resp["computeEnvironmentArn"]
            break
        except Exception as exc:  # IAM role propagation delay
            last_err = exc
            time.sleep(3)
    if ce_arn is None:
        raise AssertionError(f"could not create compute environment: {last_err}")
    ctx.on_cleanup(lambda: _delete_compute_environment(ctx, batch, ce_name))

    def _wait_valid():
        d = batch.describe_compute_environments(computeEnvironments=[ce_name])
        envs = d.get("computeEnvironments", [])
        return envs[0] if envs else None

    def _is_valid(env):
        return env is not None and env["status"] == "VALID"

    env = _poll_until(_wait_valid, _is_valid, timeout_s=90.0, interval_s=3.0)
    assert env["status"] == "VALID", env.get("statusReason")

    return ce_arn, ce_name


#: The suite's cleanup budget; the retries of every teardown of one run share one deadline in it.
_CLEANUP_BUDGET_S = 900.0
_cleanup_deadlines: dict[int, tuple[object, float]] = {}


def _delete_compute_environment(ctx, batch, ce_name):
    """Disable and delete the compute environment, then wait until DescribeComputeEnvironments no
    longer lists it: the service role torn down after it must outlive the asynchronous delete.
    ClientException refusals (a queue still detaching, the CE still updating) retry every 2 s."""
    held = _cleanup_deadlines.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _cleanup_deadlines[id(ctx)] = (ctx, time.monotonic() + _CLEANUP_BUDGET_S)
    deadline = held[1]
    steps = [
        lambda: batch.update_compute_environment(computeEnvironment=ce_name, state="DISABLED"),
        lambda: batch.delete_compute_environment(computeEnvironment=ce_name),
    ]
    while True:
        listed = [
            ce
            for ce in batch.describe_compute_environments(computeEnvironments=[ce_name])["computeEnvironments"]
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
            raise TimeoutError(f"compute environment {ce_name} still listed at the cleanup deadline")
        time.sleep(2)


def _register_minimal_jobdef(ctx, batch):
    name = ctx.unique_name("sim2real-batch-jobdef-")
    resp = batch.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "busybox:1.36",
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "128"},
            ],
            "command": ["true"],
        },
        tags=dict(_MANAGED_TAGS),
    )
    arn = resp["jobDefinitionArn"]
    ctx.on_cleanup(lambda: _deregister_safely(batch, arn))
    return arn


def _deregister_safely(batch, jobdef_arn):
    batch.deregister_job_definition(jobDefinition=jobdef_arn)


def _create_job_queue(ctx, batch, ce_arn, policy_arn):
    name = ctx.unique_name("sim2real-batch-jq-")
    resp = batch.create_job_queue(
        jobQueueName=name,
        state="ENABLED",
        priority=1,
        schedulingPolicyArn=policy_arn,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=dict(_MANAGED_TAGS),
    )
    arn = resp["jobQueueArn"]

    def _wait_valid():
        d = batch.describe_job_queues(jobQueues=[name])
        queues = d.get("jobQueues", [])
        return queues[0] if queues else None

    queue = _poll_until(_wait_valid, lambda q: q is not None and q["status"] == "VALID", timeout_s=60.0, interval_s=2.0)
    assert queue["status"] == "VALID", queue.get("statusReason")

    ctx.on_cleanup(lambda: _delete_job_queue(batch, arn, name))
    return arn, name


def _delete_job_queue(batch, jq_arn, jq_name):
    try:
        batch.update_job_queue(jobQueue=jq_arn, state="DISABLED")
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _retry_client_exception(lambda: batch.delete_job_queue(jobQueue=jq_arn), timeout_s=120)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        d = batch.describe_job_queues(jobQueues=[jq_name])
        queues = d.get("jobQueues", [])
        if not queues or queues[0]["status"] == "DELETED":
            return
        time.sleep(4)


def _stop_job(batch, job_id):
    jobs = batch.describe_jobs(jobs=[job_id]).get("jobs", [])
    status = jobs[0]["status"] if jobs else None
    if status in ("STARTING", "RUNNING"):
        batch.terminate_job(jobId=job_id, reason="sim2real-cleanup")
    else:
        batch.cancel_job(jobId=job_id, reason="sim2real-cleanup")
    deadline = time.monotonic() + 60
    terminal = {"SUCCEEDED", "FAILED"}
    while time.monotonic() < deadline:
        jobs = batch.describe_jobs(jobs=[job_id]).get("jobs", [])
        if not jobs or jobs[0]["status"] in terminal:
            return
        time.sleep(3)


def _poll_front_of_queue(batch, queue_arn, expected_arns, timeout_s=90.0):
    def _probe():
        resp = batch.get_job_queue_snapshot(jobQueue=queue_arn)
        return resp.get("frontOfQueue", {}).get("jobs", [])

    def _has_all(jobs):
        seen = {entry["jobArn"] for entry in jobs}
        return expected_arns.issubset(seen)

    return _poll_until(_probe, _has_all, timeout_s=timeout_s, interval_s=3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
