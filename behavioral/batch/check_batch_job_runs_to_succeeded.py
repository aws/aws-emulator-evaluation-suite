"""batch-job-runs-to-succeeded."""

from __future__ import annotations
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "batch-job-runs-to-succeeded"
GROUP = "data-plane"
SERVICES = ["batch"]


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
# A small public image an anonymous Fargate pull can fetch.
_IMAGE = "public.ecr.aws/docker/library/busybox:latest"
# Batch's own log group for container jobs (AWS-created on first use; never deleted here).
_JOB_LOG_GROUP = "/aws/batch/job"
# The harness's per-check budget for this suite: every wait ends only where the runner would
# stop the check anyway, so no wait is an assertion on elapsed time.
_SUITE_BUDGET_S = 1800
_VPC_CACHE: dict = {}
_UNMANAGED_ROLE_NAME = "sim2real-behav-batch-service-role"
_BATCH_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
_BATCH_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "batch.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_ECS_TASK_EXECUTION_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
)
_ECS_TASKS_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _poll_until(
    probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _retry_while_failing(fn, *, timeout_s=60, interval_s=5, description="operation"):
    """Retry fn() while it raises, bounded by a deadline; re-raise the last error past it.

    Absorbs IAM/STS role-propagation lag right after a role is created without an
    unconditional sleep: the wait ends the instant the dependent call starts succeeding.
    """
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"{description} still failing after {timeout_s}s: {last_exc}"
    ) from last_exc


def _describe_ce(bat, name):
    envs = bat.describe_compute_environments(computeEnvironments=[name]).get(
        "computeEnvironments", []
    )
    return envs[0] if envs else None


def _describe_jq(bat, name):
    qs = bat.describe_job_queues(jobQueues=[name]).get("jobQueues", [])
    return qs[0] if qs else None


def _describe_job(bat, job_id):
    js = bat.describe_jobs(jobs=[job_id]).get("jobs", [])
    return js[0] if js else None


# Prefix of every data-path failure message: running a Batch job needs a real container runtime,
# so a target without one fails these assertions rather than the control-plane ones.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _wait_ce_status(bat, name, statuses, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
    )


def _wait_jq_status(bat, name, statuses, timeout_s=120, interval_s=3):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} status in {sorted(statuses)}",
    )


def _wait_job_status(bat, job_id, statuses, timeout_s=180, interval_s=3, trace=None):
    """Poll a job to a terminal status set, recording the ordered distinct statuses seen.

    `trace` (when passed a list) lets the caller tell a job that genuinely transited
    RUNNABLE/STARTING/RUNNING from one that a target teleported straight to SUCCEEDED.
    """

    def probe():
        j = _describe_job(bat, job_id)
        if trace is not None and j is not None:
            st = j.get("status")
            if st and (not trace or trace[-1] != st):
                trace.append(st)
        return j

    return _poll_until(
        probe,
        lambda j: j is not None and j.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job {job_id} status in {sorted(statuses)}",
    )


def _delete_role(ctx, role_name, policy_arn):
    """Teardown: detach the managed policy then delete an IAM role; only NoSuchEntity is tolerated."""
    iam = ctx.client("iam")
    for step in (
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            step()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise


def _service_linked_role_arn(ctx):
    """The account's AWSServiceRoleForBatch SLR (valid for MANAGED CEs). Shared: never deleted."""
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName="AWSServiceRoleForBatch")["Role"]["Arn"]
    except Exception:
        pass
    try:
        resp = iam.create_service_linked_role(AWSServiceName="batch.amazonaws.com")
        return resp["Role"]["Arn"]
    except Exception as exc:
        raise AssertionError(
            f"cannot resolve the Batch service-linked role: {exc}"
        ) from exc


def _fargate_execution_role_arn(ctx):
    """Create this run's own ECS task execution role for Fargate Batch jobs; returns its ARN."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-batch-exec-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST_POLICY),
        Description="SimParity behavioral suite: Batch Fargate task execution role",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name, _ECS_TASK_EXECUTION_POLICY))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_ECS_TASK_EXECUTION_POLICY)
    return arn


def _default_vpc_networking(ctx):
    """Resolve (subnet_ids, security_group_id) from the run's shared network (MANAGED CEs).

    Cached per region for the life of this check so an explicit call and the CE creation
    observe identical values. Raises AssertionError when the account lacks a usable default
    VPC: an absent prerequisite is a failure here, never a skip.
    """
    if ctx.region in _VPC_CACHE:
        return _VPC_CACHE[ctx.region]
    ec2 = ctx.client("ec2")
    try:
        vpcs = ec2.describe_vpcs(
            Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]
        ).get("Vpcs", [])
    except Exception as exc:
        raise AssertionError(f"cannot describe VPCs in this account: {exc}") from exc
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region; cannot build a MANAGED Fargate CE"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    subnet_ids = [
        s["SubnetId"] for s in subnets if s.get("AvailableIpAddressCount", 0) > 0
    ]
    if not subnet_ids:
        raise AssertionError(f"shared network {vpc_id} has no usable subnets")
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError(f"shared network {vpc_id} has no default security group")
    _VPC_CACHE[ctx.region] = (subnet_ids[:3], sgs[0]["GroupId"])
    return _VPC_CACHE[ctx.region]


def _retry_refused(call, *, timeout_s=60):
    """Run a Batch teardown call, where "does not exist" means already gone.

    Batch answers ClientException while a dependency drains: retry that every 2 s, then raise.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return None
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _teardown_ce(ctx, bat, name):
    """Disable a compute environment, wait for it to settle, then delete it (best-effort)."""
    _retry_refused(
        lambda: bat.update_compute_environment(
            computeEnvironment=name, state="DISABLED"
        )
    )
    _wait_ce_status(bat, name, {"VALID", "INVALID"}, timeout_s=90, interval_s=3)
    _retry_refused(lambda: bat.delete_compute_environment(computeEnvironment=name))
    _wait_compute_environment_gone(bat, name)


def _teardown_jq(ctx, bat, name):
    """Disable a job queue, wait for it to settle, then delete it (best-effort)."""
    try:
        bat.update_job_queue(jobQueue=name, state="DISABLED")
        _wait_jq_status(bat, name, {"VALID", "INVALID"}, timeout_s=60)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _swallow(lambda: bat.delete_job_queue(jobQueue=name))


def _deregister_jd(bat, name, revision):
    _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}"))


def _create_fargate_ce(ctx, bat, name=None, max_vcpus=4, state="ENABLED"):
    """MANAGED / FARGATE compute environment backed by the account's default VPC."""
    subnets, sg = _default_vpc_networking(ctx)
    name = name or ctx.unique_name("sim2real-behav-ce-fg-")
    service_role_arn = _service_linked_role_arn(ctx)
    resp = _retry_while_failing(
        lambda: bat.create_compute_environment(
            computeEnvironmentName=name,
            type="MANAGED",
            state=state,
            serviceRole=service_role_arn,
            computeResources={
                "type": "FARGATE",
                "maxvCpus": max_vcpus,
                "subnets": subnets,
                "securityGroupIds": [sg],
            },
            tags=_MANAGED_TAGS,
        ),
        timeout_s=60,
        interval_s=5,
        description=(
            f"create compute environment {name} "
            "(waiting for the Batch service-linked role to propagate)"
        ),
    )
    ctx.on_cleanup(lambda: _teardown_ce(ctx, bat, name))
    return name, resp["computeEnvironmentArn"]


def _create_job_queue(
    ctx,
    bat,
    ce_arn,
    name=None,
    priority=10,
    state="ENABLED",
    scheduling_policy_arn=None,
):
    name = name or ctx.unique_name("sim2real-behav-jq-")
    kwargs = dict(
        jobQueueName=name,
        state=state,
        priority=priority,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
    )
    if scheduling_policy_arn:
        kwargs["schedulingPolicyArn"] = scheduling_policy_arn
    resp = bat.create_job_queue(**kwargs)
    ctx.on_cleanup(lambda: _teardown_jq(ctx, bat, name))
    return name, resp["jobQueueArn"]


def _register_fargate_job_definition(
    ctx, bat, name=None, command=None, assign_public_ip="ENABLED"
):
    """Register a FARGATE job definition running a trivial public busybox command."""
    name = name or ctx.unique_name("sim2real-behav-jd-fg-")
    resp = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": _IMAGE,
            "command": command or ["echo", "hello-sim2real"],
            "executionRoleArn": _fargate_execution_role_arn(ctx),
            "resourceRequirements": [
                {"type": "VCPU", "value": "0.25"},
                {"type": "MEMORY", "value": "512"},
            ],
            "networkConfiguration": {"assignPublicIp": assign_public_ip},
            "fargatePlatformConfiguration": {"platformVersion": "LATEST"},
        },
    )
    rev = resp["revision"]
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, rev))
    return name, resp["jobDefinitionArn"], rev


def _submit_job(ctx, bat, queue, job_definition, name=None, depends_on=None):
    name = name or ctx.unique_name("sim2real-behav-job-")
    kwargs = dict(jobName=name, jobQueue=queue, jobDefinition=job_definition)
    if depends_on:
        kwargs["dependsOn"] = depends_on
    resp = bat.submit_job(**kwargs)
    job_id = resp["jobId"]
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: bat.terminate_job(jobId=job_id, reason="behavioral-test-cleanup")
        )
    )
    return job_id, resp["jobArn"]


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data"
)
def run(ctx) -> None:
    """A Fargate job printing N*N for a per-run N ends SUCCEEDED, exit 0, with exactly N*N logged.

    Only an executed container can produce that log; each deleted resource is then proven gone.
    """
    bat = ctx.client("batch")
    logs = ctx.client("logs")

    ce_name, ce_arn = _create_fargate_ce(ctx, bat, max_vcpus=4)
    _wait_ce_status(bat, ce_name, {"VALID"}, timeout_s=_SUITE_BUDGET_S, interval_s=5)

    jq_name, _jq_arn = _create_job_queue(ctx, bat, ce_arn)
    _wait_jq_status(bat, jq_name, {"VALID"}, timeout_s=_SUITE_BUDGET_S, interval_s=3)

    # A per-run N: the expected output exists only once the container has computed it.
    n = int(ctx.unique_name("")[:6], 16) % 90000 + 10000
    jd_name, _jd_arn, revision = _register_fargate_job_definition(
        ctx, bat, command=["sh", "-c", f"echo $(({n}*{n}))"]
    )

    job_id, _job_arn = _submit_job(
        ctx, bat, queue=jq_name, job_definition=f"{jd_name}:{revision}"
    )

    job = _wait_job_status(
        bat, job_id, {"SUCCEEDED", "FAILED"}, timeout_s=_SUITE_BUDGET_S, interval_s=15
    )
    status = job.get("status")
    # A container runtime is the data plane here: the job body is a trivial command, so any terminal
    # state other than SUCCEEDED means nothing executed it.
    assert status == "SUCCEEDED", (
        f"{DATAPLANE_MARKER}: job {job_id} ended in {status!r} (expected SUCCEEDED); "
        f"reason={job.get('statusReason')!r}"
    )
    container = job.get("container") or {}
    assert container.get("exitCode") == 0, (
        f"{DATAPLANE_MARKER}: expected container.exitCode == 0 for job {job_id}, got "
        f"{container.get('exitCode')!r}; reason={container.get('reason')!r}"
    )
    stream = container.get("logStreamName")
    assert stream, f"{DATAPLANE_MARKER}: SUCCEEDED job {job_id} names no container logStreamName"
    ctx.on_cleanup(lambda: _delete_log_stream(logs, stream))
    # Log delivery trails the job's terminal state; poll until the line lands.
    messages = _poll_until(
        lambda: _log_messages(logs, stream),
        bool,
        timeout_s=_SUITE_BUDGET_S,
        interval_s=5,
        description=f"log events in {_JOB_LOG_GROUP}/{stream}",
    )
    assert [m.strip() for m in messages] == [str(n * n)], (
        f"{DATAPLANE_MARKER}: the container log for job {job_id} holds {messages!r}, expected "
        f"exactly [{str(n * n)!r}] (N={n})"
    )

    # Deregister the job definition: no ACTIVE revision remains, and SubmitJob refuses it.
    bat.deregister_job_definition(jobDefinition=f"{jd_name}:{revision}")
    active = [
        d
        for page in bat.get_paginator("describe_job_definitions").paginate(
            jobDefinitionName=jd_name, status="ACTIVE"
        )
        for d in page["jobDefinitions"]
    ]
    assert active == [], f"deregistered job definition {jd_name} still has ACTIVE revisions: {active!r}"
    try:
        bat.submit_job(
            jobName=ctx.unique_name("sim2real-behav-job-dead-"), jobQueue=jq_name,
            jobDefinition=f"{jd_name}:{revision}",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        http = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        message = exc.response.get("Error", {}).get("Message") or ""
    else:
        raise AssertionError(f"SubmitJob with the deregistered job definition {jd_name} was ACCEPTED")
    assert code == "ClientException", f"expected ClientException submitting a deregistered definition, got {code}"
    assert http == 400, f"expected HTTP 400 submitting a deregistered definition, got {http}"
    expected_message = f"JobDefinition {_jd_arn} is not in ACTIVE status."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Delete the queue, then the compute environment; each read by name ends empty or DELETED.
    bat.update_job_queue(jobQueue=jq_name, state="DISABLED")
    _wait_jq_status(bat, jq_name, {"VALID", "INVALID"}, timeout_s=_SUITE_BUDGET_S)
    bat.delete_job_queue(jobQueue=jq_name)
    gone_jq = _poll_until(
        lambda: _describe_jq(bat, jq_name),
        lambda q: q is None or q.get("status") == "DELETED",
        timeout_s=_SUITE_BUDGET_S, interval_s=5, description=f"job queue {jq_name} deleted",
    )
    assert gone_jq is None or gone_jq["status"] == "DELETED", f"job queue not deleted: {gone_jq!r}"
    _assert_gone_from_listing(
        [q for page in bat.get_paginator("describe_job_queues").paginate() for q in page["jobQueues"]],
        "jobQueueName", jq_name, "job queue",
    )
    _assert_dead_mutation_refused(
        lambda: bat.update_job_queue(jobQueue=jq_name, state="ENABLED"),
        f"UpdateJobQueue(state=ENABLED) on the deleted job queue {jq_name}",
    )
    bat.update_compute_environment(computeEnvironment=ce_name, state="DISABLED")
    _wait_ce_status(bat, ce_name, {"VALID", "INVALID"}, timeout_s=_SUITE_BUDGET_S, interval_s=5)
    bat.delete_compute_environment(computeEnvironment=ce_name)
    gone_ce = _poll_until(
        lambda: _describe_ce(bat, ce_name),
        lambda c: c is None or c.get("status") == "DELETED",
        timeout_s=_SUITE_BUDGET_S, interval_s=5, description=f"compute environment {ce_name} deleted",
    )
    assert gone_ce is None or gone_ce["status"] == "DELETED", f"compute environment not deleted: {gone_ce!r}"
    _assert_gone_from_listing(
        [
            c
            for page in bat.get_paginator("describe_compute_environments").paginate()
            for c in page["computeEnvironments"]
        ],
        "computeEnvironmentName", ce_name, "compute environment",
    )
    _assert_dead_mutation_refused(
        lambda: bat.update_compute_environment(computeEnvironment=ce_name, state="ENABLED"),
        f"UpdateComputeEnvironment(state=ENABLED) on the deleted compute environment {ce_name}",
    )


def _assert_gone_from_listing(items, name_key, name, kind):
    """The unfiltered listing no longer holds ``name``, or holds it only as DELETED."""
    live = [i for i in items if i.get(name_key) == name and i.get("status") != "DELETED"]
    assert live == [], f"deleted {kind} {name} still listed as live: {live!r}"


def _assert_dead_mutation_refused(call, what):
    """A mutation on a deleted Batch resource is refused ClientException/400 with a message."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code = err.get("Code")
        http = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        message = err.get("Message") or ""
    else:
        raise AssertionError(f"{what} was ACCEPTED")
    assert code == "ClientException", f"{what}: expected ClientException, got {code}"
    assert http == 400, f"{what}: expected HTTP 400, got {http}"
    assert message.strip(), f"{what}: expected a non-empty refusal message"


def _log_messages(logs, stream):
    """Every message in the job's log stream, oldest first; [] while it does not exist yet."""
    try:
        events = logs.get_log_events(
            logGroupName=_JOB_LOG_GROUP, logStreamName=stream, startFromHead=True
        )["events"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return []
        raise
    return [e["message"] for e in events]


def _delete_log_stream(logs, stream):
    """Teardown: delete this job's log stream, tolerating one already gone."""
    try:
        logs.delete_log_stream(logGroupName=_JOB_LOG_GROUP, logStreamName=stream)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _wait_compute_environment_gone(batch, name, timeout_s=300.0, interval_s=5.0):
    """Wait until a deleted compute environment is gone; the delete is asynchronous and needs the
    service role until it completes, so a later cleanup must not delete the role first."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        found = batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
        if not [ce for ce in found if ce.get("status") != "DELETED"]:
            return
        time.sleep(interval_s)
    raise AssertionError(f"compute environment {name} still present {timeout_s:.0f}s after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
