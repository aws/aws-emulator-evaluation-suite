"""batch-array-n-to-n-dependency-gates-only-matching-child-index."""

from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-array-n-to-n-dependency-gates-only-matching-child-index"

GROUP = "state-machine"

SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """With an N_TO_N array dependency, the dependent child at index i depends on parent child i and
    runs only if it succeeded; the child paired with the failed parent is never dispatched.

    Reference: https://docs.aws.amazon.com/batch/latest/userguide/array_jobs.html
    """
    bat = ctx.client("batch")
    size = 2

    log_sink = _batch_job_log_sink(ctx, bat)
    _n, exec_role = _iam_role(ctx, "exec", _EXEC_STATEMENTS)
    # 4 container executions at 0.25 vCPU, and the two waves do not overlap.
    queue = _fargate_stack(ctx, bat, max_vcpus=4)
    # The child's exit code IS its index, so index 0 exits 0 (success) and index 1 exits 1
    # (failure) from one job definition and one submission. Each parent child first sleeps
    # _PARENT_HOLD_S once it runs, so the check itself holds the window in which both parents
    # are non-terminal and the dependents must be PENDING.
    parent_def = _register_jd(
        ctx, bat, ["sh", "-c", f"sleep {_PARENT_HOLD_S}; exit $AWS_BATCH_JOB_ARRAY_INDEX"],
        exec_role_arn=exec_role,
    )
    dep_def = _register_jd(ctx, bat, ["sh", "-c", "exit 0"], exec_role_arn=exec_role)

    parent_id = _submit(ctx, bat, queue, parent_def, arrayProperties={"size": size})
    dep_id = _submit(
        ctx, bat, queue, dep_def,
        arrayProperties={"size": size},
        dependsOn=[{"jobId": parent_id, "type": "N_TO_N"}],
    )
    log_sink.extend([parent_id, dep_id])

    # --- Both dependent children must be HELD while their parents are still non-terminal.
    log_sink.extend(_array_children(bat, parent_id))
    dep_ids = sorted(_poll_until(
        lambda: _array_children(bat, dep_id),
        lambda cs: len(cs) == size,
        timeout_s=_JQ_TIMEOUT_S,
        interval_s=3,
        description=f"the dependent array enumerates its {size} children",
    ))
    log_sink.extend(dep_ids)
    held = bat.describe_jobs(jobs=dep_ids)["jobs"]
    # The held window is evidence only if the parents were still non-terminal AFTER the
    # dependents were read; the parents' own sleep is what keeps that true.
    parents_now = bat.describe_jobs(jobs=sorted(_array_children(bat, parent_id)))["jobs"]
    assert parents_now and all(
        j["status"] not in ("SUCCEEDED", "FAILED") for j in parents_now
    ), (
        f"the parents must still be non-terminal when the dependents are observed held, got "
        f"{[(j['jobId'], j['status']) for j in parents_now]!r}"
    )
    dep_on = {}
    for job in held:
        assert job["status"] == "PENDING", (
            f"a dependent array child whose N_TO_N parent has not finished must be held in "
            f"PENDING, got {job['status']!r} for {job['jobId']}"
        )
        # AWS resolves N_TO_N into "<parent>:<own index>" per child and drops the type key.
        deps = [d.get("jobId") for d in job.get("dependsOn") or []]
        assert len(deps) == 1 and deps[0].startswith(parent_id + ":"), (
            f"N_TO_N must be RESOLVED into a dependency on one specific parent CHILD, whose id is "
            f"'<arrayJobId>:<index>', not left as an array-wide dependency; child {job['jobId']} "
            f"reports {job.get('dependsOn')!r}"
        )
        dep_on[job["jobId"]] = deps[0]
    # The pairing is the whole claim: between them the dependent children must depend on the
    # parent children one-to-one -- never both on the same one, never on the array parent itself.
    assert sorted(dep_on.values()) == [f"{parent_id}:{i}" for i in range(size)], (
        f"the {size} dependent children must be paired one-to-one with the {size} parent "
        f"children: {dep_on!r}"
    )

    # --- The parents settle: index 0 SUCCEEDED, index 1 FAILED, by their own exit codes.
    parent = _poll_until(
        lambda: _describe_job(bat, parent_id),
        lambda j: j is not None
        and sum((j.get("arrayProperties") or {}).get("statusSummary", {}).get(s, 0)
                for s in ("SUCCEEDED", "FAILED")) == size,
        timeout_s=_JOB_TIMEOUT_S,
        interval_s=10,
        description=f"both parent array children terminal",
    )
    summary = parent["arrayProperties"]["statusSummary"]
    assert summary.get("SUCCEEDED") == 1 and summary.get("FAILED") == 1, (
        f"`exit $AWS_BATCH_JOB_ARRAY_INDEX` over size {size} must give exactly one SUCCEEDED and "
        f"one FAILED parent child, got statusSummary={summary!r}"
    )
    parent_ids = sorted(_array_children(bat, parent_id))
    parents = bat.describe_jobs(jobs=parent_ids)["jobs"]
    parent_exit_by_index = {
        j["arrayProperties"]["index"]: (j.get("container") or {}).get("exitCode") for j in parents
    }
    assert parent_exit_by_index == {0: 0, 1: 1}, (
        f"each parent child must exit with its own index: {parent_exit_by_index!r}"
    )

    # --- Poll both dependent children to terminal, recording the ORDERED trace of each. The trace
    #     is what proves the blocked one was never dispatched; a terminal status alone cannot.
    traces = {jid: [] for jid in dep_ids}
    finals = {}
    deadline = time.monotonic() + _JOB_TIMEOUT_S
    while time.monotonic() < deadline and len(finals) < size:
        for job in bat.describe_jobs(jobs=dep_ids)["jobs"]:
            jid, st = job["jobId"], job.get("status")
            if st and (not traces[jid] or traces[jid][-1] != st):
                traces[jid].append(st)
            if st in ("SUCCEEDED", "FAILED"):
                finals[jid] = job
        if len(finals) < size:
            time.sleep(5)
    assert len(finals) == size, (
        f"both dependent children must reach a terminal state within {_JOB_TIMEOUT_S}s; traces "
        f"were {traces!r}"
    )
    by_index = {j["arrayProperties"]["index"]: j for j in finals.values()}
    trace_by_index = {j["arrayProperties"]["index"]: traces[j["jobId"]] for j in finals.values()}
    assert sorted(by_index) == list(range(size)), f"dependent indices were {sorted(by_index)!r}"

    # --- Index 0: released by its own successful parent, and it really ran.
    ok = by_index[0]
    assert ok["status"] == "SUCCEEDED", (
        f"the dependent child whose same-index parent SUCCEEDED must be released and run to "
        f"SUCCEEDED, got {ok['status']!r} statusReason={ok.get('statusReason')!r}"
    )
    assert (ok.get("container") or {}).get("exitCode") == 0, (
        f"the released child really ran, so it must report exitCode 0, got "
        f"{(ok.get('container') or {}).get('exitCode')!r}"
    )
    # RUNNING can last less than one poll interval, so the run is proven by the job record:
    # startedAt marks its STARTING -> RUNNING transition and attempts lists the execution.
    assert ok.get("startedAt"), (
        f"the released child ran, so it must carry startedAt, trace was {trace_by_index[0]!r}"
    )
    assert ok.get("attempts"), (
        f"the released child ran, so it must record an attempt, got {ok.get('attempts')!r}"
    )
    assert dep_on[ok["jobId"]] == f"{parent_id}:0", (
        f"the released child must be the one paired with parent child 0, got "
        f"{dep_on[ok['jobId']]!r}"
    )

    # --- Index 1: its same-index parent failed, so it must never have been dispatched at all.
    blocked = by_index[1]
    assert blocked["status"] == "FAILED", (
        f"the dependent child whose same-index parent FAILED must not run, got "
        f"{blocked['status']!r}"
    )
    assert "RUNNING" not in trace_by_index[1] and "STARTING" not in trace_by_index[1], (
        f"dependent index 1 must never have been dispatched; its observed trace was "
        f"{trace_by_index[1]!r}"
    )
    assert not (blocked.get("attempts") or []), (
        f"a never-dispatched child must record no attempts, got {blocked.get('attempts')!r}"
    )
    assert "startedAt" not in blocked, (
        f"a never-dispatched child must have no startedAt: {blocked.get('startedAt')!r}"
    )
    assert (blocked.get("container") or {}).get("exitCode") is None, (
        f"a child that ran no container must report no exitCode, got "
        f"{(blocked.get('container') or {}).get('exitCode')!r}"
    )
    assert dep_on[blocked["jobId"]] == f"{parent_id}:1", (
        f"the blocked child must be the one paired with parent child 1 -- the index whose parent "
        f"failed -- got {dep_on[blocked['jobId']]!r}"
    )
    assert blocked.get("statusReason"), (
        f"a dependency-failed child must explain itself in statusReason: {blocked!r}"
    )


_PREFIX = "sim2real-behav-"
_MANAGED_TAGS = {
    "sim2real:managed": "true",
    "sim2real:prefix": _PREFIX.rstrip("-"),
    "sim2real": "batch-array-n-to-n-dependency",
}

# Bounded deadlines, each with its reason.
_CE_TIMEOUT_S = 600       # a MANAGED/FARGATE CE provisions its own backing ECS cluster
_JQ_TIMEOUT_S = 300       # queue VALID follows CE association
_TEARDOWN_TIMEOUT_S = 300       # DISABLED -> settled -> deleted -> gone, per resource
_JOB_TIMEOUT_S = 1200  # Fargate placement + public.ecr.aws image pull + run
_LOG_TIMEOUT_S = 420            # awslogs stream creation, then first event delivery
_PARENT_HOLD_S = 60             # each parent child runs this long before it exits
_SLR_ACCEPT_S = 120             # a just-created service-linked role becomes usable as serviceRole

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

    Raises AssertionError on deadline miss: a condition that never arrives is a failure.
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
    """The AWS error code fn() raised.

    Raises when fn() SUCCEEDS, so an unexpected acceptance never reads as a code mismatch.
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

    Other resources in the account can push the one this check asserts on off page one.
    """
    out = []
    try:
        pages = client.get_paginator(op).paginate(**kwargs)
    except Exception:  # noqa: BLE001 - no paginator modelled for this op
        return getattr(client, op)(**kwargs).get(key, [])
    for page in pages:
        out.extend(page.get(key, []))
    return out


def _create_network(ctx) -> tuple[str, str]:
    """(subnet_id, security_group_id) in an internet-routable VPC this check creates and tears down.

    The check owns its networking: a VPC, one public subnet, an internet gateway with a default
    route (so a Fargate task can pull a public image), and the VPC's own default security group.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.182.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-batch-vpc-")}])
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.182.1.0/24", AvailabilityZone=az)["Subnet"][
        "SubnetId"
    ]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _delete_with_retry(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
    )
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"][0][
        "RouteTableId"
    ]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return subnet_id, sg_id


def _delete_with_retry(fn, timeout_s: float = 600.0) -> None:
    """Retry a network delete while Fargate/Batch ENIs drain (DependencyViolation)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code.endswith(".NotFound") or code in ("Gateway.NotAttached",):
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(15)


def _iam_role(ctx, kind, statements):
    """Create a role trusting ecs-tasks with ONE inline policy; returns (name, arn).

    Fresh per check so another teardown cannot delete it mid-pull. IAM is eventually
    consistent, so the inline policy is polled back before use.
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
    """AWSServiceRoleForBatch -- the serviceRole a MANAGED compute environment needs.

    Account-level and shared by every Batch check, so it is created-or-reused and NEVER deleted
    (deleting it would break a sibling check mid-run, and it is free to keep).
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
    return role["Role"]["Arn"]


def _retry_client_exception(fn, *, timeout_s):
    """fn(), retried while Batch answers ClientException (a just-created serviceRole it cannot
    yet use); any other error, or the deadline, raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


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


def _teardown_jobs(bat, job_ids):
    """Terminate every job, then WAIT for each to be terminal.

    The wait is the load-bearing half: DeleteJobQueue is a 400 while the queue holds a
    non-terminal job, and DeleteComputeEnvironment is a 400 while a queue still references it,
    so skipping it leaks the queue AND the compute environment while the check passes.
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

    DeleteJobQueue raises ClientException for a queue that is still draining and accepts the
    same call seconds later, so it is retried.
    """
    _swallow(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _swallow(lambda: _await_jq(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_TIMEOUT_S))
    for attempt in range(8):
        try:
            bat.delete_job_queue(jobQueue=name)
            break
        except ClientError:  # still draining; retry
            if attempt == 7:
                raise
            time.sleep(8)
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

    A compute environment cannot be deleted while it is ENABLED and the delete is asynchronous,
    so both the state change and the delete are polled.
    """
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _swallow(lambda: _await_ce(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_TIMEOUT_S))
    for attempt in range(8):
        try:
            bat.delete_compute_environment(computeEnvironment=name)
            break
        except ClientError:  # still referenced by a draining queue; retry
            if attempt == 7:
                raise
            time.sleep(8)
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


def _fargate_stack(ctx, bat, max_vcpus=4):
    """MANAGED/FARGATE compute environment + ENABLED queue, both polled VALID. Returns the queue.

    FARGATE has no minvCpus floor, so an idle CE bills nothing even if teardown is interrupted.
    Teardowns are registered CE-then-queue, so LIFO order runs queue-then-CE.
    """
    subnet_id, sg = _create_network(ctx)
    ce_name = ctx.unique_name(_PREFIX + "ce-fg-")
    service_role = _batch_slr(ctx)
    ce_arn = _retry_client_exception(
        lambda: bat.create_compute_environment(
            computeEnvironmentName=ce_name,
            type="MANAGED",
            state="ENABLED",
            serviceRole=service_role,
            computeResources={
                "type": "FARGATE",
                "maxvCpus": max_vcpus,
                "subnets": [subnet_id],
                "securityGroupIds": [sg],
            },
            tags=dict(_MANAGED_TAGS),
        ),
        timeout_s=_SLR_ACCEPT_S,
    )["computeEnvironmentArn"]
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
    ctx.on_cleanup(lambda: _swallow(lambda: bat.deregister_job_definition(jobDefinition=ref)))
    return ref


def _submit(ctx, bat, queue, job_def, **kwargs):
    """SubmitJob with teardown registered from THIS response's jobId, at submit time."""
    name = kwargs.pop("jobName", None) or ctx.unique_name(_PREFIX + "job-")
    jid = bat.submit_job(jobName=name, jobQueue=queue, jobDefinition=job_def, **kwargs)["jobId"]
    ctx.on_cleanup(lambda: _teardown_jobs(bat, [jid]))
    return jid


def _create_log_group(ctx):
    """A log group this check owns outright, so teardown is one call that takes the streams too.

    Not the shared AWS-managed /aws/batch/job group, which must not be deleted or mixed into.
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

    GetLogEvents returns a token that repeats when exhausted, so the loop breaks on a repeat
    rather than on an empty page: a stream can hand back an empty page and still have more.
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

    Two waits, not one: the awslogs driver opens the stream when the ECS task is INITIALISED,
    measurably before the container writes anything, so the stream existing is no evidence that
    output was delivered -- only its events are.
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
    """Every child of an array job, keyed by jobId, across EVERY status.

    ListJobs defaults jobStatus to RUNNING, so without naming each status it returns [] once the
    children stop running.
    """
    out = {}
    for status in _JOB_STATUSES:
        for js in _paginate(bat, "list_jobs", "jobSummaryList",
                            arrayJobId=array_job_id, jobStatus=status):
            out[js["jobId"]] = js
    return out


def _await_stream_settled(ctx, group, stream, *, timeout_s=_LOG_TIMEOUT_S, stable_reads=3,
                          interval_s=10):
    """Poll a stream until its message list is UNCHANGED across `stable_reads` consecutive reads.

    Logs offers no "ingestion complete" signal, so stability across N reads stands in for one.
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

    The group is shared and AWS-managed, so only these jobs' streams go; names resolve at teardown.
    """
    logs = ctx.client("logs")
    for jid in list(job_ids):
        job = _safe(lambda jid=jid: _describe_job(bat, jid)) or {}
        for st in _job_streams(job):
            _swallow(lambda st=st: logs.delete_log_stream(
                logGroupName="/aws/batch/job", logStreamName=st))


def _batch_job_log_sink(ctx, bat):
    """Register /aws/batch/job stream reaping up front; append every submitted jobId to the list.

    Registered before the first submit so LIFO order runs it after every job is terminal.
    """
    ids = []
    ctx.on_cleanup(lambda: _reap_job_log_streams(ctx, bat, ids))
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
