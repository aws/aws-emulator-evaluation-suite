"""batch-consumable-resource-quantity-caps-concurrent-running-jobs."""

from __future__ import annotations

import concurrent.futures
import json
import sys
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-consumable-resource-quantity-caps-concurrent-running-jobs"

GROUP = "concurrency"

SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A consumable resource with totalQuantity 1 admits at most one of two jobs to RUNNING at any
    observed instant, and both jobs still reach SUCCEEDED.
    """
    bat = ctx.client("batch")
    # Long enough that a serialised pair is clearly observable at a 3 s poll. The poll can miss a
    # brief overlap, which only makes the invariant conservative; job order and start time are not
    # asserted because neither is guaranteed under contention.
    hold_s = 45

    cr_name = ctx.unique_name(_PREFIX + "cr-")
    try:
        bat.create_consumable_resource(
            consumableResourceName=cr_name,
            resourceType="REPLENISHABLE",
            totalQuantity=1,
            tags=dict(_MANAGED_TAGS),
        )
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"CreateConsumableResource is unavailable in {ctx.region}: {exc}"
        ) from exc

    def _drop_cr():
        _retry_refused(lambda: bat.delete_consumable_resource(consumableResource=cr_name), timeout_s=64)
        if _safe(lambda: bat.describe_consumable_resource(consumableResource=cr_name)) is not None:
            raise RuntimeError(f"batch consumable resource {cr_name} still present after "
                               f"DeleteConsumableResource")

    ctx.on_cleanup(_drop_cr)

    log_sink = _batch_job_log_sink(ctx, bat)
    _n, exec_role = _iam_role(ctx, "exec", _EXEC_STATEMENTS)
    # maxvCpus 4 is deliberately enough for BOTH jobs at 0.25 vCPU each: if they still serialise,
    # the consumable resource is the only thing that can have caused it, not the vCPU ceiling.
    queue = _fargate_stack(ctx, bat, max_vcpus=4)
    job_def = _register_jd(
        ctx, bat, ["sh", "-c", f"sleep {hold_s}"], exec_role_arn=exec_role,
        consumable={
            "consumableResourceList": [
                {"consumableResource": cr_name, "quantity": 1}
            ]
        },
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(lambda: _submit(ctx, bat, queue, job_def)) for _ in range(2)]
        job_ids = [f.result() for f in futures]
    assert len(set(job_ids)) == 2, f"two submissions must mint two job ids: {job_ids!r}"
    log_sink.extend(job_ids)

    trace = []
    deadline = time.monotonic() + _JOB_TIMEOUT_S
    finals = {}
    while time.monotonic() < deadline:
        jobs = {j["jobId"]: j for j in bat.describe_jobs(jobs=job_ids)["jobs"]}
        pair = tuple(jobs[j].get("status") for j in job_ids)
        trace.append(pair)
        for jid, job in jobs.items():
            if job.get("status") in ("SUCCEEDED", "FAILED"):
                finals[jid] = job
        if len(finals) == 2:
            break
        time.sleep(3)
    assert len(finals) == 2, (
        f"both jobs must reach a terminal state within {_JOB_TIMEOUT_S}s; trace was {trace!r}"
    )

    concurrent_running = [sum(1 for s in pair if s == "RUNNING") for pair in trace]
    assert max(concurrent_running) <= 1, (
        f"a consumable resource of totalQuantity 1, each job requiring 1, can never admit 2 "
        f"RUNNING jobs at once; the observed trace was {trace!r}"
    )
    assert any(n == 1 for n in concurrent_running), (
        f"at least one observation must have shown a job RUNNING, else the invariant is vacuous "
        f"(both jobs could have been skipped entirely); trace was {trace!r}"
    )
    assert all(j["status"] == "SUCCEEDED" for j in finals.values()), (
        f"the cap serialises the jobs, it does not reject them, so both must eventually run: "
        f"{[(j['jobId'], j['status'], j.get('statusReason')) for j in finals.values()]!r}"
    )
    # Both jobs really ran, and one strictly after the other -- the ordering-free half of the
    # invariant, which the poll trace could in principle have missed.
    windows = sorted((j["startedAt"], j["stoppedAt"]) for j in finals.values())
    assert all(isinstance(v, int) for w in windows for v in w), (
        f"both jobs ran, so both must report startedAt and stoppedAt: {windows!r}"
    )
    assert windows[1][0] >= windows[0][1], (
        f"the single consumable unit must not be held by two containers at once, so the second "
        f"job cannot have started before the first stopped: {windows!r}"
    )

    described = bat.describe_consumable_resource(consumableResource=cr_name)
    assert described["totalQuantity"] == 1, (
        f"totalQuantity must be unchanged by the jobs that consumed it: {described!r}"
    )
    assert described["inUseQuantity"] == 0, (
        f"a REPLENISHABLE resource must be fully released once every consuming job is terminal, "
        f"got inUseQuantity={described['inUseQuantity']!r}"
    )


# ===== helpers =====

_PREFIX = "sim2real-behav-"
_MANAGED_TAGS = {
    # The managed tag and the sim2real- name prefix make leftovers discoverable for cleanup.
    "sim2real:managed": "true",
    "sim2real:prefix": _PREFIX.rstrip("-"),
    "sim2real": "batch-consumable-resource-cap",
}

# Bounded deadlines, each with its reason. Never a bare sleep standing in for a wait.
_CE_TIMEOUT_S = 600       # a MANAGED/FARGATE CE provisions its own backing ECS cluster
_JQ_TIMEOUT_S = 300       # queue VALID follows CE association
_TEARDOWN_TIMEOUT_S = 300       # DISABLED -> settled -> deleted -> gone, per resource
_JOB_TIMEOUT_S = 1200  # Fargate placement + public.ecr.aws image pull + run
_LOG_TIMEOUT_S = 420            # awslogs stream creation, then first event delivery

# A tiny image an anonymous Fargate pull can always fetch, pinned by tag so a check about job
# semantics is never also a check about registry credentials or about "latest" moving.
_BUSYBOX = "public.ecr.aws/docker/library/busybox:1.36"

_ECS_TASKS_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
# What a Fargate task execution role must be able to do: pull from ECR Public and open/write the
# awslogs stream. Nothing else.
_EXEC_STATEMENTS = [
    {
        "Effect": "Allow",
        "Action": [
            "ecr:GetAuthorizationToken",
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
        ],
        "Resource": "*",
    }
]


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("NoSuchEntity", "ResourceNotFoundException")
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _safe(fn):
    """Run fn() and return its result, or None if it raised (probe helper)."""
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result.

    Raises AssertionError on deadline miss: a condition that never arrives is a fidelity failure.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error_code(fn):
    """The AWS error code fn() raised; fails if fn() succeeds instead.

    Accepting input real AWS rejects must not read like an error-code naming difference.
    """
    try:
        resp = fn()
    except Exception as exc:  # noqa: BLE001 - the code is the subject
        code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code")
        if not code:
            raise AssertionError(
                f"expected a modelled AWS error with an Error.Code, got {exc!r}"
            ) from exc
        return code
    raise AssertionError(
        f"the call was expected to be REJECTED but SUCCEEDED, returning {resp!r}"
    )


def _paginate(client, op, key, **kwargs):
    """Every page of a List*/Describe*, flattened.

    The account may hold other resources that push the asserted one off page one.
    """
    out = []
    try:
        pages = client.get_paginator(op).paginate(**kwargs)
    except Exception:  # noqa: BLE001 - no paginator modelled for this op
        return getattr(client, op)(**kwargs).get(key, [])
    for page in pages:
        out.extend(page.get(key, []))
    return out


def _default_vpc(ctx, min_subnets=1):
    """(vpc_id, subnet_ids) from the run's shared network, one subnet per AZ.

    The subnets already route to an internet gateway, so no NAT gateway or EIP is created.
    """
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region; a FARGATE CE needs subnets")
    vpc_id = vpcs[0]["VpcId"]
    subnets = _paginate(
        ec2,
        "describe_subnets",
        "Subnets",
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ],
    )
    per_az = {}
    for sn in sorted(subnets, key=lambda s: s["SubnetId"]):
        if sn.get("AvailableIpAddressCount", 0) > 0:
            per_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    ids = [per_az[az] for az in sorted(per_az)]
    if len(ids) < min_subnets:
        raise AssertionError(f"shared network {vpc_id} has {len(ids)} usable subnets, need {min_subnets}")
    return vpc_id, ids


def _default_sg(ctx, vpc_id):
    """The default security group of vpc_id -- nothing created, nothing to leak."""
    sgs = ctx.client("ec2").describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError(f"VPC {vpc_id} has no default security group")
    return sgs[0]["GroupId"]


def _iam_role(ctx, kind, statements):
    """Create a role trusting ecs-tasks with ONE inline policy; returns (name, arn).

    IAM is eventually consistent: the policy is polled back. Trust propagation to ECS has no
    observable condition; the role is first used when a job starts, after the stack is provisioned.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name(_PREFIX + kind + "-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST),
        Path="/sim2real/",
        Description="SimParity behavioral: Batch Fargate " + kind,
        Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _drop():
        _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        _swallow(lambda: iam.delete_role(RoleName=name))
        if _safe(lambda: iam.get_role(RoleName=name)) is not None:
            raise RuntimeError(f"IAM role {name} still exists after DeleteRole")

    ctx.on_cleanup(_drop)
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    _poll_until(
        lambda: _safe(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
        lambda r: r is not None,
        timeout_s=60,
        interval_s=2,
        description=f"role {name} inline policy readable",
    )
    return name, arn


def _batch_slr(ctx):
    """AWSServiceRoleForBatch, the serviceRole a MANAGED compute environment needs.

    Account-level and shared by every Batch check, so it is created-or-reused and never deleted.
    """
    iam = ctx.client("iam")
    existing = _safe(lambda: iam.get_role(RoleName="AWSServiceRoleForBatch"))
    if existing:
        return existing["Role"]["Arn"]
    _safe(lambda: iam.create_service_linked_role(AWSServiceName="batch.amazonaws.com"))
    role = _poll_until(
        lambda: _safe(lambda: iam.get_role(RoleName="AWSServiceRoleForBatch")),
        lambda r: r is not None,
        timeout_s=120,
        interval_s=5,
        description="AWSServiceRoleForBatch readable",
    )
    # Trust propagation is absorbed where Batch first uses the role: _create_ce retries it.
    return role["Role"]["Arn"]


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


def _await_ce(bat, name, statuses, timeout_s=_CE_TIMEOUT_S, interval_s=5):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
    )


def _await_jq(bat, name, statuses, timeout_s=_JQ_TIMEOUT_S, interval_s=3):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} status in {sorted(statuses)}",
    )


def _await_job(bat, job_id, statuses, timeout_s=_JOB_TIMEOUT_S, interval_s=10):
    return _poll_until(
        lambda: _describe_job(bat, job_id),
        lambda j: j is not None and j.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"batch job {job_id} status in {sorted(statuses)}",
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
    """Terminate every job, then wait for each to be terminal.

    DeleteJobQueue fails while the queue holds a non-terminal job, so the wait is required.
    """
    _leaks: list = []
    for jid in list(job_ids):
        _swallow(lambda jid=jid: bat.terminate_job(jobId=jid, reason=_PREFIX + "cleanup"))
    for jid in list(job_ids):
        try:
            _poll_until(
                lambda jid=jid: _describe_job(bat, jid),
                lambda j: j is None or j.get("status") in ("SUCCEEDED", "FAILED"),
                timeout_s=_TEARDOWN_TIMEOUT_S,
                interval_s=5,
                description=f"job {jid} terminal before queue teardown",
            )
        except Exception as exc:  # noqa: BLE001
            teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            if (
                not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
            ):
                _leaks.append((f"batch job {jid} never reached a terminal state; the queue and compute "
                               f"environment behind it may not have been deletable", exc))
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


def _teardown_jq(bat, name):
    """DISABLE -> poll settled -> DeleteJobQueue (retried) -> poll gone.

    DeleteJobQueue raises ClientException while the queue drains and succeeds seconds later.
    """
    _retry_refused(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _swallow(lambda: _await_jq(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_TIMEOUT_S))
    _retry_refused(lambda: bat.delete_job_queue(jobQueue=name), timeout_s=64)
    try:
        _poll_until(
            lambda: _describe_jq(bat, name),
            lambda jq: jq is None,
            timeout_s=_TEARDOWN_TIMEOUT_S,
            interval_s=5,
            description=f"job queue {name} gone",
        )
    except Exception as exc:  # noqa: BLE001
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(
                f"batch job queue {name} still present after DeleteJobQueue"
            ) from exc


def _teardown_ce(bat, name):
    """DISABLE -> poll settled -> DeleteComputeEnvironment (retried) -> poll gone.

    A compute environment cannot be deleted while ENABLED, and the delete is asynchronous.
    """
    _retry_refused(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _swallow(lambda: _await_ce(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_TIMEOUT_S))
    _retry_refused(lambda: bat.delete_compute_environment(computeEnvironment=name), timeout_s=64)
    try:
        _poll_until(
            lambda: _describe_ce(bat, name),
            lambda ce: ce is None,
            timeout_s=_TEARDOWN_TIMEOUT_S,
            interval_s=5,
            description=f"compute environment {name} gone",
        )
    except Exception as exc:  # noqa: BLE001
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(f"batch compute environment {name} still present after "
                               f"DeleteComputeEnvironment") from exc


def _create_ce(ctx, bat, timeout_s=60.0, **kwargs):
    """CreateComputeEnvironment, retried while Batch refuses a freshly created service role."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        try:
            return bat.create_compute_environment(**kwargs)["computeEnvironmentArn"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "ClientException" or "role" not in err.get("Message", "").lower():
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _fargate_stack(ctx, bat, max_vcpus=4):
    """MANAGED/FARGATE compute environment + ENABLED queue, both polled VALID. Returns the queue.

    FARGATE has no minvCpus floor, so an idle CE bills nothing. Teardown runs queue-then-CE (LIFO).
    """
    vpc_id, subnets = _default_vpc(ctx, min_subnets=1)
    sg = _default_sg(ctx, vpc_id)
    ce_name = ctx.unique_name(_PREFIX + "ce-fg-")
    ce_arn = _create_ce(
        ctx,
        bat,
        computeEnvironmentName=ce_name,
        type="MANAGED",
        state="ENABLED",
        serviceRole=_batch_slr(ctx),
        computeResources={
            "type": "FARGATE",
            "maxvCpus": max_vcpus,
            "subnets": subnets[:3],
            "securityGroupIds": [sg],
        },
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _teardown_ce(bat, ce_name))
    ce = _await_ce(bat, ce_name, {"VALID", "INVALID"})
    assert ce["status"] == "VALID", (
        f"compute environment {ce_name} did not become VALID: status={ce.get('status')!r} "
        f"statusReason={ce.get('statusReason')!r}"
    )

    jq_name = ctx.unique_name(_PREFIX + "jq-")
    bat.create_job_queue(
        jobQueueName=jq_name,
        state="ENABLED",
        priority=10,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _teardown_jq(bat, jq_name))
    jq = _await_jq(bat, jq_name, {"VALID", "INVALID"})
    assert jq["status"] == "VALID", (
        f"job queue {jq_name} did not become VALID: status={jq.get('status')!r} "
        f"statusReason={jq.get('statusReason')!r}"
    )
    return jq_name


def _register_jd(ctx, bat, command, *, exec_role_arn, image=_BUSYBOX, log_group=None,
                 job_role_arn=None, vcpu="0.25", memory="512", retry_strategy=None,
                 timeout=None, environment=None, consumable=None):
    """Register a container/FARGATE job definition. Returns "<name>:<revision>"."""
    name = ctx.unique_name(_PREFIX + "jd-")
    container = {
        "image": image,
        "command": command,
        "executionRoleArn": exec_role_arn,
        "resourceRequirements": [
            {"type": "VCPU", "value": vcpu},
            {"type": "MEMORY", "value": memory},
        ],
        "networkConfiguration": {"assignPublicIp": "ENABLED"},
        "fargatePlatformConfiguration": {"platformVersion": "LATEST"},
    }
    if log_group is not None:
        container["logConfiguration"] = {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": log_group,
                "awslogs-region": ctx.region,
                "awslogs-stream-prefix": "batch",
            },
        }
    if job_role_arn is not None:
        container["jobRoleArn"] = job_role_arn
    if environment is not None:
        container["environment"] = environment
    kwargs = dict(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties=container,
        tags=dict(_MANAGED_TAGS),
    )
    if retry_strategy is not None:
        kwargs["retryStrategy"] = retry_strategy
    if timeout is not None:
        kwargs["timeout"] = timeout
    if consumable is not None:
        kwargs["consumableResourceProperties"] = consumable
    rev = bat.register_job_definition(**kwargs)["revision"]
    ref = f"{name}:{rev}"

    def _drop_jd():
        _swallow(lambda: bat.deregister_job_definition(jobDefinition=ref))
        # A FARGATE job definition registers a same-named ECS task definition that
        # DeregisterJobDefinition never removes; Batch exposes no lever for it, so take it
        # directly through ECS.
        ecs = ctx.client("ecs")
        try:
            ecs.deregister_task_definition(taskDefinition=ref)
        except ClientError as exc:
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise
            return
        failures = ecs.delete_task_definitions(taskDefinitions=[ref]).get("failures") or []
        if failures:
            raise RuntimeError(f"DeleteTaskDefinitions refused {ref}: {failures!r}")

    ctx.on_cleanup(_drop_jd)
    return ref


def _submit(ctx, bat, queue, job_def, **kwargs):
    """SubmitJob with teardown registered from THIS response's jobId, at submit time."""
    name = kwargs.pop("jobName", None) or ctx.unique_name(_PREFIX + "job-")
    jid = bat.submit_job(jobName=name, jobQueue=queue, jobDefinition=job_def, **kwargs)["jobId"]
    ctx.on_cleanup(lambda: _teardown_jobs(bat, [jid]))
    return jid


def _create_log_group(ctx):
    """A log group this check owns, so teardown is one call that takes the streams too.

    Not the shared /aws/batch/job group, which every Batch job in the account writes to.
    """
    logs = ctx.client("logs")
    name = ctx.unique_name(_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))

    def _drop():
        _swallow(lambda: logs.delete_log_group(logGroupName=name))
        left = _safe(lambda: logs.describe_log_groups(logGroupNamePrefix=name))
        if left and left.get("logGroups"):
            raise RuntimeError(f"log group {name} still present after DeleteLogGroup")

    ctx.on_cleanup(_drop)
    return name


def _log_messages(ctx, group, stream):
    """Every message in one stream, oldest first, paginated to the end.

    GetLogEvents repeats its token when exhausted, and an empty page can still have more after it.
    """
    logs = ctx.client("logs")
    out, token, seen = [], None, set()
    while True:
        kwargs = dict(logGroupName=group, logStreamName=stream, startFromHead=True)
        if token:
            kwargs["nextToken"] = token
        resp = _safe(lambda kw=dict(kwargs): logs.get_log_events(**kw))
        if resp is None:
            return out
        out.extend(e.get("message", "") for e in resp.get("events", []))
        token = resp.get("nextForwardToken")
        if not token or token in seen:
            return out
        seen.add(token)


def _await_log_line(ctx, group, stream, predicate, *, timeout_s=_LOG_TIMEOUT_S, description="log line"):
    """Wait for the awslogs stream to exist AND to carry a line satisfying predicate.

    The stream opens when the task initialises, before the container writes, so only events count.
    """
    logs = ctx.client("logs")
    _poll_until(
        lambda: [
            s["logStreamName"]
            for s in _paginate(
                logs, "describe_log_streams", "logStreams",
                logGroupName=group, logStreamNamePrefix=stream,
            )
        ],
        lambda names: stream in names,
        timeout_s=timeout_s,
        interval_s=5,
        description=f"awslogs stream {stream} exists in {group}",
    )
    return _poll_until(
        lambda: _log_messages(ctx, group, stream),
        lambda msgs: any(predicate(m) for m in msgs),
        timeout_s=timeout_s,
        interval_s=5,
        description=f"{description} in {group}/{stream}",
    )


_JOB_STATUSES = ("SUBMITTED", "PENDING", "RUNNABLE", "STARTING", "RUNNING", "SUCCEEDED", "FAILED")


def _array_children(bat, array_job_id):
    """Every child of an array job, keyed by jobId, across every status.

    ListJobs defaults jobStatus to RUNNING, so finished children are listed only per named status.
    """
    out = {}
    for status in _JOB_STATUSES:
        for js in _paginate(bat, "list_jobs", "jobSummaryList",
                            arrayJobId=array_job_id, jobStatus=status):
            out[js["jobId"]] = js
    return out


def _await_stream_settled(ctx, group, stream, *, timeout_s=_LOG_TIMEOUT_S, stable_reads=3,
                          interval_s=10):
    """Poll a stream until its message list is unchanged across `stable_reads` consecutive reads.

    Logs has no ingestion-complete signal, so stability stands in for one; never settling raises.
    """
    last, stable = None, 0
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = _log_messages(ctx, group, stream)
        if last is not None and msgs == last:
            stable += 1
            if stable >= stable_reads:
                return msgs
        else:
            stable = 0
        last = msgs
        time.sleep(interval_s)
    raise AssertionError(
        f"log stream {group}/{stream} never settled within {timeout_s}s; last read was {last!r}"
    )


def _job_streams(job):
    """Every logStreamName a job's attempts reported, in attempt order, deduped."""
    out = []
    for att in job.get("attempts") or []:
        nm = (att.get("container") or {}).get("logStreamName")
        if nm and nm not in out:
            out.append(nm)
    nm = (job.get("container") or {}).get("logStreamName")
    if nm and nm not in out:
        out.append(nm)
    return out


def _reap_job_log_streams(ctx, bat, job_ids):
    """Delete the /aws/batch/job log streams these jobs' attempts created.

    The group is AWS-managed and shared account-wide, so only these jobs' streams are deleted.
    Names are resolved at teardown: a stream exists only once its attempt has been placed.
    """
    logs = ctx.client("logs")
    for jid in list(job_ids):
        job = _safe(lambda jid=jid: _describe_job(bat, jid)) or {}
        for st in _job_streams(job):
            _swallow(lambda st=st: logs.delete_log_stream(
                logGroupName="/aws/batch/job", logStreamName=st))


def _batch_job_log_sink(ctx, bat):
    """Register /aws/batch/job stream reaping up front; append every submitted jobId to the list.

    Registered before the first submit so LIFO order runs it last, after every job is terminal.
    """
    ids = []
    ctx.on_cleanup(lambda: _reap_job_log_streams(ctx, bat, ids))
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
