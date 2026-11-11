"""batch-propagate-tags-copies-definition-and-job-tags-to-ecs-task-job-tag-wins."""

from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-propagate-tags-copies-definition-and-job-tags-to-ecs-task-job-tag-wins"
GROUP = "data-plane"
SERVICES = ["batch", "ecs"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_FARGATE_EXEC_ROLE_PREFIX = "sim2real-behav-batch-exec-"
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
_TEARDOWN_S = 300      # DISABLED -> settle -> deleted -> gone, per resource
_JOB_TERMINAL_S = 900  # Fargate cold start + public.ecr.aws image pull + run, ONE attempt


def _swallow(fn):
    """Run a teardown step; only a resource that is already gone is ignored, every other failure raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("InvalidNetworkInterfaceID.NotFound", "NoSuchEntity")
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition",
                ctx=None):
    """Poll probe() until predicate(result); RAISE on deadline miss, never return the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_role(ctx, role_name, policy_arn):
    iam = ctx.client("iam")
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _swallow(lambda: iam.delete_role(RoleName=role_name))


def _fargate_execution_role_arn(ctx):
    """Create this run's own ECS task execution role for Fargate Batch jobs; returns its ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name(_FARGATE_EXEC_ROLE_PREFIX)
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST_POLICY),
        Description="SimParity behavioral suite: Batch Fargate task execution role",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name, _ECS_TASK_EXECUTION_POLICY))
    iam.attach_role_policy(RoleName=name, PolicyArn=_ECS_TASK_EXECUTION_POLICY)
    _wait_role_assumable(ctx, name)
    return arn


def _wait_role_assumable(ctx, role_name):
    """Bounded wait for a new role to be readable via GetRole.

    IAM is eventually consistent, and Batch/ECS reject a role they cannot yet resolve.
    """
    iam = ctx.client("iam")
    _poll_until(
        lambda: iam.get_role(RoleName=role_name).get("Role"),
        lambda r: bool(r and r.get("Arn")),
        timeout_s=_budget_s(ctx, 60),
        ctx=ctx,
        interval_s=1,
        description=f"IAM role {role_name} readable after create",
    )


def _service_linked_role_arn(ctx):
    """The account's AWSServiceRoleForBatch SLR (required by a MANAGED CE). Shared: never deleted."""
    iam = ctx.client("iam")
    try:
        return iam.get_role(RoleName="AWSServiceRoleForBatch")["Role"]["Arn"]
    except Exception:  # noqa: BLE001 - absent SLR is the create branch
        pass
    try:
        resp = iam.create_service_linked_role(AWSServiceName="batch.amazonaws.com")
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"cannot resolve the Batch service-linked role: {exc}") from exc
    _wait_role_assumable(ctx, "AWSServiceRoleForBatch")
    return resp["Role"]["Arn"]


def _networking(ctx):
    """(subnet_ids, security_group_id) for a Fargate CE, from a VPC this check creates."""
    ec2 = ctx.client("ec2")
    vpc_id = _create_vpc(ctx, ec2)
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get(
        "Subnets", []
    )
    subnet_ids = [s["SubnetId"] for s in subnets if s.get("AvailableIpAddressCount", 0) > 0]
    assert subnet_ids, f"VPC {vpc_id} has no subnet with free addresses; cannot place a Fargate task"
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    ).get("SecurityGroups", [])
    assert sgs, f"VPC {vpc_id} has no default security group; cannot place a Fargate task"
    return subnet_ids[:3], sgs[0]["GroupId"]


def _create_vpc(ctx, ec2):
    """Create a minimal internet-routable VPC + one public subnet. Returns the VPC id."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.181.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _swallow(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
        timeout_s=_budget_s(ctx, 600),
        ctx=ctx,
        interval_s=1,
        description=f"VPC {vpc_id} available",
    )
    az = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.181.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _swallow(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_kv()}]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _swallow(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
        )
    )
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    return vpc_id


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


def _wait_ce(bat, name, statuses, timeout_s=_CE_VALID_S, interval_s=1, ctx=None):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
        ctx=ctx,
    )


def _wait_jq(bat, name, statuses, timeout_s=_JQ_VALID_S, interval_s=1, ctx=None):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} status in {sorted(statuses)}",
        ctx=ctx,
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_job_terminal(bat, job_id, timeout_s, ctx=None):
    """Wait for the job to reach SUCCEEDED or FAILED."""
    return _poll_until(
        lambda: _describe_job(bat, job_id),
        lambda j: j is not None and j.get("status") in ("SUCCEEDED", "FAILED"),
        timeout_s=timeout_s,
        interval_s=1,
        description=f"job {job_id} reached SUCCEEDED or FAILED",
        ctx=ctx,
    )


def _teardown_jobs(bat, job_ids):
    """Terminate every non-terminal job, then wait for each to be terminal.

    A queue holding non-terminal jobs cannot be deleted, so this must run before queue teardown.
    """
    for jid in list(job_ids):
        _swallow(lambda jid=jid: bat.terminate_job(jobId=jid, reason="behavioral-test-cleanup"))
    for jid in list(job_ids):
        _swallow(
            lambda jid=jid: _poll_until(
                lambda: _describe_job(bat, jid),
                lambda j: j is None or j.get("status") in ("SUCCEEDED", "FAILED"),
                timeout_s=_TEARDOWN_S,
                interval_s=5,
                description=f"job {jid} terminal before queue teardown",
            )
        )


def _teardown_jq(bat, name):
    """DISABLE -> poll settled -> DeleteJobQueue -> poll gone."""
    _swallow(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _swallow(lambda: _wait_jq(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S))
    last = None
    for _ in range(15):
        try:
            bat.delete_job_queue(jobQueue=name)
            break
        except Exception as exc:  # noqa: BLE001 - a queue still draining rejects the delete
            if isinstance(exc, ClientError) and "does not exist" in exc.response["Error"].get("Message", ""):
                break
            last = exc
            time.sleep(2)
    else:
        raise RuntimeError(f"job queue {name} was not deleted: {last!r}")
    _swallow(
        lambda: _poll_until(
            lambda: _describe_jq(bat, name),
            lambda jq: jq is None,
            timeout_s=_TEARDOWN_S,
            interval_s=5,
            description=f"job queue {name} gone",
        )
    )


def _teardown_ce(bat, name):
    """DISABLE -> poll settled -> DeleteComputeEnvironment -> poll gone."""
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _swallow(lambda: _wait_ce(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S))
    last = None
    for _ in range(15):
        try:
            bat.delete_compute_environment(computeEnvironment=name)
            break
        except Exception as exc:  # noqa: BLE001 - a still-referenced CE rejects the delete
            if isinstance(exc, ClientError) and "does not exist" in exc.response["Error"].get("Message", ""):
                break
            last = exc
            time.sleep(2)
    else:
        raise RuntimeError(f"compute environment {name} was not deleted: {last!r}")
    _swallow(
        lambda: _poll_until(
            lambda: _describe_ce(bat, name),
            lambda ce: ce is None,
            timeout_s=_TEARDOWN_S,
            interval_s=5,
            description=f"compute environment {name} gone",
        )
    )


def _fargate_stack(ctx, bat, max_vcpus=4):
    """MANAGED/FARGATE CE + ENABLED queue, both polled to VALID. Returns the queue name.

    Fargate has no minvCpus floor, so an idle CE bills nothing even if teardown is cut short.
    """
    subnets, sg = _networking(ctx)
    ce_name = ctx.unique_name("sim2real-behav-ce-fg-")
    resp = bat.create_compute_environment(
        computeEnvironmentName=ce_name,
        type="MANAGED",
        state="ENABLED",
        serviceRole=_service_linked_role_arn(ctx),
        computeResources={
            "type": "FARGATE",
            "maxvCpus": max_vcpus,
            "subnets": subnets,
            "securityGroupIds": [sg],
        },
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _teardown_ce(bat, ce_name))
    ce_arn = resp["computeEnvironmentArn"]
    ce = _wait_ce(bat, ce_name, {"VALID", "INVALID"}, timeout_s=_budget_s(ctx, _CE_VALID_S),
                  ctx=ctx)
    assert ce["status"] == "VALID", (
        f"compute environment {ce_name} must reach VALID, got {ce['status']!r}: "
        f"{ce.get('statusReason')!r}"
    )

    jq_name = ctx.unique_name("sim2real-behav-jq-")
    bat.create_job_queue(
        jobQueueName=jq_name,
        state="ENABLED",
        priority=10,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _teardown_jq(bat, jq_name))
    jq = _wait_jq(bat, jq_name, {"VALID", "INVALID"}, timeout_s=_budget_s(ctx, _JQ_VALID_S),
                  ctx=ctx)
    assert jq["status"] == "VALID", (
        f"job queue {jq_name} must reach VALID, got {jq['status']!r}: {jq.get('statusReason')!r}"
    )
    return jq_name


def _submit(ctx, bat, queue, job_def, **kwargs):
    """SubmitJob with teardown registered at submit time. Returns the jobId."""
    resp = bat.submit_job(
        jobName=ctx.unique_name("sim2real-behav-job-"),
        jobQueue=queue,
        jobDefinition=job_def,
        **kwargs,
    )
    jid = resp["jobId"]
    ctx.on_cleanup(lambda: _teardown_jobs(bat, [jid]))
    return jid


_JD_ONLY_KEY = "sim2realTagFromDefinition"
_JOB_ONLY_KEY = "sim2realTagFromJob"
_SHARED_KEY = "sim2realTagShared"
_PROBE_KEYS = (_JD_ONLY_KEY, _JOB_ONLY_KEY, _SHARED_KEY)
_ECS_TAGS_S = 300  # a just-created task may not expose tags on the first read


def _register_jd(ctx, bat, *, propagate, jd_tags, exec_role_arn):
    """A FARGATE job definition, optionally propagating tags. Returns "name:revision"."""
    name = ctx.unique_name("sim2real-behav-jd-fg-")
    kwargs = dict(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            # Headroom around CE settling and Fargate ENI attach, which alone can eat a short sleep.
            "command": ["/bin/sh", "-c", "sleep 150"],
            "executionRoleArn": exec_role_arn,
            "resourceRequirements": [
                {"type": "VCPU", "value": "0.25"},
                {"type": "MEMORY", "value": "512"},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
            "fargatePlatformConfiguration": {"platformVersion": "LATEST"},
        },
        tags={**_MANAGED_TAGS, **jd_tags},
    )
    if propagate:
        kwargs["propagateTags"] = True
    resp = bat.register_job_definition(**kwargs)
    rev = resp["revision"]
    ctx.on_cleanup(
        lambda: _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{rev}"))
    )
    return f"{name}:{rev}"


def _submit_tagged(ctx, bat, queue, job_def, job_tags):
    resp = bat.submit_job(
        jobName=ctx.unique_name("sim2real-behav-job-"),
        jobQueue=queue,
        jobDefinition=job_def,
        tags=job_tags,
    )
    jid = resp["jobId"]
    ctx.on_cleanup(lambda: _teardown_jobs(bat, [jid]))
    return jid


def _await_task_arn(ctx, bat, job_id):
    """Wait until the job's first attempt names an ECS task ARN, then return it."""
    job = _poll_until(
        lambda: _describe_job(bat, job_id),
        lambda j: bool(
            j
            and (j.get("attempts") or [])
            and ((j["attempts"][0].get("container") or {}).get("taskArn"))
        ),
        timeout_s=_budget_s(ctx, _JOB_TERMINAL_S),
        ctx=ctx,
        interval_s=1,
        description=(
            f"job {job_id} is placed and its attempt reports the ECS task ARN it runs as"
        ),
    )
    return job["attempts"][0]["container"]["taskArn"]


def _task_tags(ctx, cluster_arn, task_arn):
    """ecs:DescribeTasks(include=["TAGS"]) on a task ARN, as {key: value}. One read, no retry.

    ListTagsForResource rejects a STOPPED task; DescribeTasks serves running and stopped tasks.
    """
    resp = ctx.client("ecs").describe_tasks(cluster=cluster_arn, tasks=[task_arn], include=["TAGS"])
    assert not resp.get("failures"), (
        f"DescribeTasks must resolve task {task_arn!r} in cluster {cluster_arn!r} to read its "
        f"tags; got failures {resp.get('failures')!r}"
    )
    tasks = resp["tasks"]
    assert len(tasks) == 1, f"expected exactly one task for {task_arn!r}, got {len(tasks)}"
    return {t["key"]: t["value"] for t in tasks[0].get("tags", [])}


def _task_tags_until(ctx, cluster_arn, task_arn, want_keys):
    """Poll DescribeTasks(include=["TAGS"]) until every key in `want_keys` is present; raise on
    the deadline. A just-created task may not expose its tags on the first read.
    """
    want = set(want_keys)

    def _read():
        return _task_tags(ctx, cluster_arn, task_arn)

    return _poll_until(
        _read,
        lambda got: want <= set(got),
        timeout_s=_budget_s(ctx, _ECS_TAGS_S),
        ctx=ctx,
        interval_s=1,
        description=(
            f"ECS task {task_arn} exposes the propagated tag keys {sorted(want)} through "
            f"DescribeTasks(include=TAGS)"
        ),
    )


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """propagateTags copies the job definition's and the job's tags onto the ECS task, the job's
    value winning a shared key, and the tags survive the task stopping; an otherwise identical
    definition without the flag propagates none of them."""
    bat = ctx.client("batch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; refusing to run against an unidentified target"

    run_id = uuid.uuid4().hex[:12]
    from_definition = f"from-definition-{run_id}"
    from_job = f"from-job-{run_id}"
    jd_tags = {_JD_ONLY_KEY: from_definition, _SHARED_KEY: from_definition}
    job_tags = {_JOB_ONLY_KEY: from_job, _SHARED_KEY: from_job}
    assert from_definition != from_job, "the two tag values must differ for precedence to be visible"

    # Created before the compute environment, so IAM has the CE's provisioning time to make the
    # role assumable by ECS before any task references it.
    exec_role_arn = _fargate_execution_role_arn(ctx)
    queue = _fargate_stack(ctx, bat)
    # maxvCpus=4 against 0.25 vCPU per task, so both legs are placed at once and the twin is a
    # control group observed in the same instant rather than after the fact.
    ce_name = _describe_jq(bat, queue)["computeEnvironmentOrder"][0]["computeEnvironment"]
    cluster_arn = _describe_ce(bat, ce_name)["ecsClusterArn"]
    assert cluster_arn.startswith("arn:aws:ecs:"), (
        f"the compute environment must report the ECS cluster it is backed by, got "
        f"ecsClusterArn={cluster_arn!r}"
    )

    propagating_jd = _register_jd(
        ctx, bat, propagate=True, jd_tags=jd_tags, exec_role_arn=exec_role_arn
    )
    twin_jd = _register_jd(ctx, bat, propagate=False, jd_tags=jd_tags, exec_role_arn=exec_role_arn)

    # The flag must round-trip, read back through DescribeJobDefinitions rather than trusted from
    # the register response — otherwise "the twin has no flag" is unverified.
    prop_name, prop_rev = propagating_jd.rsplit(":", 1)
    twin_name, twin_rev = twin_jd.rsplit(":", 1)
    prop_detail = bat.describe_job_definitions(jobDefinitions=[propagating_jd])["jobDefinitions"][0]
    twin_detail = bat.describe_job_definitions(jobDefinitions=[twin_jd])["jobDefinitions"][0]
    assert prop_detail["propagateTags"] is True, (
        f"job definition {prop_name}:{prop_rev} was registered with propagateTags=True but "
        f"DescribeJobDefinitions reports {prop_detail.get('propagateTags')!r}"
    )
    assert not twin_detail.get("propagateTags"), (
        f"the twin job definition {twin_name}:{twin_rev} must report no propagateTags, so the "
        f"only difference between the legs is that flag; got {twin_detail.get('propagateTags')!r}"
    )

    propagating_job = _submit_tagged(ctx, bat, queue, propagating_jd, job_tags)
    twin_job = _submit_tagged(ctx, bat, queue, twin_jd, job_tags)

    propagating_task = _await_task_arn(ctx, bat, propagating_job)
    twin_task = _await_task_arn(ctx, bat, twin_job)
    assert propagating_task != twin_task, (
        f"the two legs must run as different ECS tasks; both report {propagating_task!r}"
    )

    # --- both tasks really are ECS tasks in the compute environment's own cluster --------------
    described = ctx.client("ecs").describe_tasks(
        cluster=cluster_arn, tasks=[propagating_task, twin_task], include=["TAGS"]
    )
    assert not described.get("failures"), (
        f"ECS must resolve both task ARNs inside cluster {cluster_arn!r}; DescribeTasks reported "
        f"failures {described.get('failures')!r}"
    )
    assert len(described["tasks"]) == 2, (
        f"ECS must return both tasks, got {len(described['tasks'])}: "
        f"{[t.get('taskArn') for t in described['tasks']]}"
    )
    for task in described["tasks"]:
        assert task["clusterArn"] == cluster_arn, (
            f"task {task.get('taskArn')!r} must belong to the compute environment's cluster "
            f"{cluster_arn!r}, got {task.get('clusterArn')!r}"
        )

    # --- leg 1: the propagating job's task carries all three keys, with the JOB winning --------
    # Runs first: once propagated tags are readable here, the twin's single unretried read below
    # is a real absence rather than an unsettled one.
    prop_tags = _task_tags_until(ctx, cluster_arn, propagating_task, _PROBE_KEYS)
    assert prop_tags.get(_JD_ONLY_KEY) == from_definition, (
        f"a job-definition-only tag must reach the ECS task with the DEFINITION's value; expected "
        f"{_JD_ONLY_KEY}={from_definition!r}, task {propagating_task} carries "
        f"{prop_tags.get(_JD_ONLY_KEY)!r} (all propagated keys: {sorted(prop_tags)})"
    )
    assert prop_tags.get(_JOB_ONLY_KEY) == from_job, (
        f"a job-only tag must reach the ECS task with the JOB's value; expected "
        f"{_JOB_ONLY_KEY}={from_job!r}, task {propagating_task} carries "
        f"{prop_tags.get(_JOB_ONLY_KEY)!r} (all propagated keys: {sorted(prop_tags)})"
    )
    assert prop_tags.get(_SHARED_KEY) == from_job, (
        f"THE PRECEDENCE RULE: for a key set on BOTH the job definition and the job, the JOB's "
        f"value wins; expected {_SHARED_KEY}={from_job!r}, task {propagating_task} carries "
        f"{prop_tags.get(_SHARED_KEY)!r} (definition set it to {from_definition!r}, so this value "
        f"tells you which side the target merged from)"
    )

    # --- leg 2: the twin, in the same cluster and the same instant, carries NONE of them -------
    twin_tags = _task_tags(ctx, cluster_arn, twin_task)
    leaked = {k: twin_tags[k] for k in _PROBE_KEYS if k in twin_tags}
    assert not leaked, (
        f"the twin job definition sets no propagateTags, so its ECS task {twin_task} must carry "
        f"NONE of {list(_PROBE_KEYS)}; it carries {leaked} (a target that tags every task "
        f"unconditionally fails exactly here, and would otherwise have passed leg 1)"
    )

    # --- both jobs must also actually complete, so the propagation was not read off a task that
    # --- never really ran -----------------------------------------------------------------------
    for label, jid in (("propagating", propagating_job), ("twin", twin_job)):
        final = _wait_job_terminal(bat, jid, timeout_s=_budget_s(ctx, _JOB_TERMINAL_S),
                                   ctx=ctx)
        assert final["status"] == "SUCCEEDED", (
            f"the {label} leg's job must SUCCEED, got {final['status']!r} "
            f"(statusReason={final.get('statusReason')!r})"
        )
        assert (final["attempts"][0].get("container") or {}).get("exitCode") == 0, (
            f"the {label} leg's container must exit 0, got "
            f"{final['attempts'][0].get('container')!r}"
        )

    # Tags are propagated at task creation and must survive the stop; DescribeTasks+TAGS still
    # serves a stopped task within ECS's one-hour retention window.
    after_stop = _task_tags(ctx, cluster_arn, propagating_task)
    assert after_stop.get(_SHARED_KEY) == from_job, (
        f"the propagated tags must survive the task stopping; {_SHARED_KEY} was {from_job!r} while "
        f"running and is {after_stop.get(_SHARED_KEY)!r} now"
    )


# AWS-managed ENIs of resources deleted asynchronously linger in the VPC, so network deletes wait
# (bounded) for them and retry DependencyViolation before raising with the ENIs still attached.
_NET_TEARDOWN_S = 210.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
