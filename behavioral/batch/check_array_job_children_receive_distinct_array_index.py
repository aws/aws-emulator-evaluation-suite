"""array-job-children-receive-distinct-array-index."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "array-job-children-receive-distinct-array-index"
GROUP = 'data-plane'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_FARGATE_EXEC_ROLE_NAME = "sim2real-behav-batch-exec-role"
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
_CE_VALID_S = 300      # a MANAGED/FARGATE CE provisions a backing ECS cluster
_JQ_VALID_S = 300      # queue VALID follows CE association
_TEARDOWN_S = 300      # DISABLED -> VALID -> deleted -> gone, per resource
_JOB_TERMINAL_S = 900  # Fargate cold start + public.ecr.aws image pull + run


def _swallow(fn):
    """Run fn(), treating only the resource's not-found answers as already gone."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("NoSuchEntity", "ResourceNotFoundException")
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_role(ctx, role_name, policy_arn):
    """Detach the managed policy then delete an IAM role (best-effort)."""
    iam = ctx.client("iam")
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _swallow(lambda: iam.delete_role(RoleName=role_name))


def _fargate_execution_role_arn(ctx):
    """Create or reuse the Fargate task execution role and return its ARN.

    Cleanup is registered only when this call created the role, so a shared role is never deleted.
    """
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName=_FARGATE_EXEC_ROLE_NAME)["Role"]["Arn"]
    except Exception:
        pass
    try:
        resp = iam.create_role(
            RoleName=_FARGATE_EXEC_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST_POLICY),
            Description="SimParity behavioral suite: Batch Fargate task execution role",
            Tags=_tags_kv(),
        )
        arn = resp["Role"]["Arn"]
    except Exception as exc:
        try:
            return iam.get_role(RoleName=_FARGATE_EXEC_ROLE_NAME)["Role"]["Arn"]
        except Exception:
            raise AssertionError(
                f"cannot create/resolve the Fargate task execution role: {exc}"
            ) from exc
    _swallow(lambda: iam.attach_role_policy(RoleName=_FARGATE_EXEC_ROLE_NAME, PolicyArn=_ECS_TASK_EXECUTION_POLICY))
    ctx.on_cleanup(lambda: _delete_role(ctx, _FARGATE_EXEC_ROLE_NAME, _ECS_TASK_EXECUTION_POLICY))
    return arn


def _deregister_jd(bat, name, revision):
    _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}"))


_VPC_CACHE: dict = {}


def _default_vpc_networking(ctx):
    """Resolve (subnet_ids, security_group_id) from the shared network, cached per region."""
    if ctx.region in _VPC_CACHE:
        return _VPC_CACHE[ctx.region]
    ec2 = ctx.client("ec2")
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    except Exception as exc:
        raise AssertionError(f"cannot describe VPCs in this account: {exc}") from exc
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region; cannot build a MANAGED Fargate CE")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    subnet_ids = [s["SubnetId"] for s in subnets if s.get("AvailableIpAddressCount", 0) > 0]
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
        raise AssertionError(f"cannot resolve the Batch service-linked role: {exc}") from exc


def _retry_while_propagating(fn, *, timeout_s, interval_s=5, description):
    """Retry fn() while it raises, bounded by timeout_s.

    A new IAM role can take a while to become usable by other services' control planes.
    """
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"{description} kept failing past {timeout_s}s: {last_exc}") from last_exc


def _describe_ce(bat, name):
    envs = bat.describe_compute_environments(computeEnvironments=[name]).get("computeEnvironments", [])
    return envs[0] if envs else None


def _describe_jq(bat, name):
    qs = bat.describe_job_queues(jobQueues=[name]).get("jobQueues", [])
    return qs[0] if qs else None


def _describe_job(bat, job_id):
    js = bat.describe_jobs(jobs=[job_id]).get("jobs", [])
    return js[0] if js else None


def _wait_ce_status(bat, name, statuses, timeout_s=_CE_VALID_S, interval_s=5):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
    )


def _wait_jq_status(bat, name, statuses, timeout_s=_JQ_VALID_S, interval_s=3):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} status in {sorted(statuses)}",
    )


def _wait_job_status(bat, job_id, statuses, timeout_s=_JOB_TERMINAL_S, interval_s=10):
    return _poll_until(
        lambda: _describe_job(bat, job_id),
        lambda j: j is not None and j.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job {job_id} status in {sorted(statuses)}",
    )


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


def _teardown_jobs(bat, job_ids):
    """Terminate every job and wait for each to be terminal.

    A queue cannot be deleted while it holds non-terminal jobs, so this runs before queue teardown.
    """
    for jid in list(job_ids):
        _swallow(lambda jid=jid: bat.terminate_job(jobId=jid, reason="behavioral-test-cleanup"))
    for jid in list(job_ids):
        _poll_until(
            lambda jid=jid: _describe_job(bat, jid),
            lambda j: j is None or j.get("status") in ("SUCCEEDED", "FAILED"),
            timeout_s=_TEARDOWN_S,
            interval_s=5,
            description=f"job {jid} terminal before queue teardown",
        )


def _teardown_jq(bat, name):
    """DISABLE -> poll VALID -> DeleteJobQueue -> poll gone.

    DeleteJobQueue on an ENABLED queue fails, and so does deleting a CE a queue still references.
    """
    _retry_refused(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _wait_jq_status(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S, interval_s=3)
    _retry_refused(lambda: bat.delete_job_queue(jobQueue=name))
    _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is None,
        timeout_s=_TEARDOWN_S,
        interval_s=5,
        description=f"job queue {name} gone",
    )


def _teardown_ce(bat, name):
    """DISABLE -> poll settled -> DeleteComputeEnvironment -> poll gone."""
    _retry_refused(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _wait_ce_status(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S, interval_s=5)
    _retry_refused(lambda: bat.delete_compute_environment(computeEnvironment=name))
    _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is None,
        timeout_s=_TEARDOWN_S,
        interval_s=5,
        description=f"compute environment {name} gone",
    )


def _delete_log_streams(ctx, stream_names):
    """Delete this check's /aws/batch/job log streams; the group itself is shared by all jobs."""
    if not stream_names:
        return
    logs = ctx.client("logs")
    for s in sorted(set(stream_names)):
        _swallow(lambda s=s: logs.delete_log_stream(logGroupName="/aws/batch/job", logStreamName=s))


def _collect_log_streams(job):
    """Every logStreamName a job's attempts reported (may be empty if it never started)."""
    out = []
    for att in job.get("attempts") or []:
        name = (att.get("container") or {}).get("logStreamName")
        if name:
            out.append(name)
    name = (job.get("container") or {}).get("logStreamName")
    if name:
        out.append(name)
    return out


def _fargate_stack(ctx, bat, max_vcpus=4):
    """MANAGED/FARGATE CE + ENABLED queue, both polled to VALID. Returns (jq_name, ce_arn).

    FARGATE has no minvCpus floor, so an idle CE costs nothing; cleanup runs queue then CE.
    """
    subnets, sg = _default_vpc_networking(ctx)
    ce_name = ctx.unique_name("sim2real-behav-ce-fg-")
    service_role_arn = _service_linked_role_arn(ctx)
    resp = _retry_while_propagating(
        lambda: bat.create_compute_environment(
            computeEnvironmentName=ce_name,
            type="MANAGED",
            state="ENABLED",
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
        description=f"CreateComputeEnvironment {ce_name} (freshly-created service-linked role)",
    )
    ctx.on_cleanup(lambda: _teardown_ce(bat, ce_name))
    ce_arn = resp["computeEnvironmentArn"]
    ce = _wait_ce_status(bat, ce_name, {"VALID", "INVALID"})
    assert ce["status"] == "VALID", f"CE not VALID: {ce.get('statusReason')!r}"

    jq_name = ctx.unique_name("sim2real-behav-jq-")
    bat.create_job_queue(
        jobQueueName=jq_name,
        state="ENABLED",
        priority=10,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _teardown_jq(bat, jq_name))
    jq = _wait_jq_status(bat, jq_name, {"VALID", "INVALID"})
    assert jq["status"] == "VALID", f"queue not VALID: {jq.get('statusReason')!r}"
    return jq_name, ce_arn


def _fargate_container_properties(ctx, command, vcpu="0.25", memory="512"):
    return {
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "command": command,
        "executionRoleArn": _fargate_execution_role_arn(ctx),
        "resourceRequirements": [
            {"type": "VCPU", "value": vcpu},
            {"type": "MEMORY", "value": memory},
        ],
        "networkConfiguration": {"assignPublicIp": "ENABLED"},
        "fargatePlatformConfiguration": {"platformVersion": "LATEST"},
    }


def _register_fargate_jd(ctx, bat, command, *, retry_strategy=None, timeout=None,
                         parameters=None, vcpu="0.25", memory="512"):
    """Register a FARGATE job definition. Returns (name, arn, revision)."""
    name = ctx.unique_name("sim2real-behav-jd-fg-")
    kwargs = dict(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties=_fargate_container_properties(ctx, command, vcpu=vcpu, memory=memory),
        tags=_MANAGED_TAGS,
    )
    if retry_strategy:
        kwargs["retryStrategy"] = retry_strategy
    if timeout:
        kwargs["timeout"] = timeout
    if parameters:
        kwargs["parameters"] = parameters
    resp = _retry_while_propagating(
        lambda: bat.register_job_definition(**kwargs),
        timeout_s=30,
        description=f"RegisterJobDefinition {name} (freshly-created execution role)",
    )
    rev = resp["revision"]
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, rev))
    return name, resp["jobDefinitionArn"], rev


def _tracked_submit(ctx, bat, queue, job_definition, **kwargs):
    """SubmitJob with a cleanup registered at submit time. Returns the jobId."""
    name = ctx.unique_name("sim2real-behav-job-")
    resp = bat.submit_job(jobName=name, jobQueue=queue, jobDefinition=job_definition, **kwargs)
    jid = resp["jobId"]
    ctx.on_cleanup(lambda: _teardown_jobs(bat, [jid]))
    return jid


def _log_stream_sink(ctx):
    """Register log-stream reaping up front; the run body appends the names it observes."""
    streams: list = []
    ctx.on_cleanup(lambda: _delete_log_streams(ctx, streams))
    return streams


_STATUS_RANK = {
    "SUBMITTED": 0,
    "PENDING": 1,
    "RUNNABLE": 2,
    "STARTING": 3,
    "RUNNING": 4,
    "SUCCEEDED": 5,
    "FAILED": 5,
}


def _trace_job_to_terminal(bat, job_id, *, timeout_s=_JOB_TERMINAL_S, interval_s=5):
    """Poll DescribeJobs recording the ordered distinct statuses; return (trace, final_job)."""
    trace: list = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        job = _describe_job(bat, job_id)
        if job is not None:
            st = job.get("status")
            if st and (not trace or trace[-1] != st):
                trace.append(st)
            if st in ("SUCCEEDED", "FAILED"):
                return trace, job
        time.sleep(interval_s)
    raise AssertionError(
        f"job {job_id} did not reach a terminal state within {timeout_s}s; trace={trace}"
    )


def _list_array_children(bat, parent_id, status):
    """Every child of `parent_id` in `status`, following nextToken to the end.

    jobStatus is a single value, not a list, so one call can only ever see one status.
    """
    out = []
    token = None
    while True:
        kwargs = {"arrayJobId": parent_id, "jobStatus": status}
        if token:
            kwargs["nextToken"] = token
        page = bat.list_jobs(**kwargs)
        out.extend(page.get("jobSummaryList") or [])
        token = page.get("nextToken")
        if not token:
            return out


def _assert_monotonic(trace):
    """The observed status sequence must never go backwards through the Batch state machine."""
    ranks = [_STATUS_RANK[s] for s in trace if s in _STATUS_RANK]
    unknown = [s for s in trace if s not in _STATUS_RANK]
    assert not unknown, f"unmodelled job status(es) {unknown} in trace {trace}"
    assert ranks == sorted(ranks), f"job status went backwards: {trace}"

@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A size-2 array job's children exit with their own AWS_BATCH_JOB_ARRAY_INDEX (0 SUCCEEDED,
    1 FAILED), the parent aggregates them in statusSummary and carries no runtime fields, and
    ListJobs without jobStatus lists only RUNNING children.
    """
    bat = ctx.client("batch")
    streams = _log_stream_sink(ctx)
    queue, _ce_arn = _fargate_stack(ctx, bat)
    jd_name, _jd_arn, rev = _register_fargate_jd(
        ctx, bat, ["/bin/sh", "-c", 'exit "$AWS_BATCH_JOB_ARRAY_INDEX"']
    )

    parent_id = _tracked_submit(ctx, bat, queue, f"{jd_name}:{rev}", arrayProperties={"size": 2})

    parent = _wait_job_status(bat, parent_id, {"SUCCEEDED", "FAILED"}, timeout_s=_JOB_TERMINAL_S + 300)
    assert parent["status"] == "FAILED", (
        f"an array parent with one failing child must end FAILED, got {parent['status']!r}"
    )
    ap = parent.get("arrayProperties") or {}
    assert ap.get("size") == 2, f"parent must report arrayProperties.size == 2, got {ap.get('size')!r}"
    summary = ap.get("statusSummary") or {}
    assert summary.get("SUCCEEDED") == 1, (
        f"statusSummary must count exactly 1 SUCCEEDED child, got {summary!r}"
    )
    assert summary.get("FAILED") == 1, (
        f"statusSummary must count exactly 1 FAILED child, got {summary!r}"
    )
    # The array parent does carry a `container` member echoing the job definition, but it runs
    # nothing, so it must have no runtime fields; the children are asserted to have them below.
    parent_container = parent.get("container") or {}
    runtime_only = {
        k: parent_container[k]
        for k in ("exitCode", "taskArn", "containerInstanceArn", "logStreamName", "reason")
        if k in parent_container
    }
    assert not runtime_only, (
        f"an array PARENT job runs no container of its own, so its container detail must carry no "
        f"execution result; got {runtime_only!r}"
    )

    # "If you don't specify a status, only RUNNING jobs are returned." Both children are
    # terminal by now, so the unfiltered listing must be empty.
    unfiltered = bat.list_jobs(arrayJobId=parent_id).get("jobSummaryList", [])
    assert unfiltered == [], (
        f"ListJobs with no jobStatus defaults to RUNNING only, and both children are "
        f"terminal, so the array must list as empty; got "
        f"{[(s.get('jobId'), s.get('status')) for s in unfiltered]}"
    )

    # One call per status because jobStatus takes a single value; this also checks that each
    # child is listed under its own status.
    children = []
    for status in ("SUCCEEDED", "FAILED"):
        listed = _list_array_children(bat, parent_id, status)
        assert len(listed) == 1, (
            f"exactly one child ends {status} (child 0 exits 0, child 1 exits 1), so "
            f"ListJobs(arrayJobId=..., jobStatus={status}) must return 1 summary, got "
            f"{[s.get('jobId') for s in listed]}"
        )
        assert listed[0].get("status") == status, (
            f"ListJobs filtered by {status} must only return jobs in that status, got "
            f"{listed[0].get('status')!r}"
        )
        children.extend(listed)
    assert len(children) == 2, f"ListJobs(arrayJobId=...) must return the 2 children, got {len(children)}"
    by_index = {}
    for summ in children:
        idx = (summ.get("arrayProperties") or {}).get("index")
        assert idx is not None, f"every array child must report arrayProperties.index: {summ!r}"
        by_index[idx] = summ["jobId"]
    assert sorted(by_index) == [0, 1], f"child indices must be exactly 0 and 1, got {sorted(by_index)}"
    for idx, child_id in by_index.items():
        assert child_id == f"{parent_id}:{idx}", (
            f"child jobId must be '<parent>:<index>', got {child_id!r} for index {idx}"
        )

    for idx, child_id in sorted(by_index.items()):
        child = _wait_job_status(bat, child_id, {"SUCCEEDED", "FAILED"})
        streams.extend(_collect_log_streams(child))
        expected_status = "SUCCEEDED" if idx == 0 else "FAILED"
        assert child["status"] == expected_status, (
            f"child {idx} exits {idx}, so it must be {expected_status}, got {child['status']!r}"
        )
        child_container = child.get("container") or {}
        got = child_container.get("exitCode")
        assert got == idx, (
            f"child {idx}'s container must exit with its own array index: expected exitCode "
            f"{idx}, got {got!r} (AWS_BATCH_JOB_ARRAY_INDEX did not reach the container)"
        )
        # The runtime field the parent must lack is present on a child that really ran.
        assert child_container.get("taskArn"), (
            f"child {idx} ran on Fargate, so its container detail must name the ECS task that ran "
            f"it; got {child_container.get('taskArn')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
