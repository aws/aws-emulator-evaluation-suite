"""compute-environment-disabled-withholds-placement-until-reenabled."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "compute-environment-disabled-withholds-placement-until-reenabled"
GROUP = "job-lifecycle"
SERVICES = ["batch"]


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
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
# Bounded deadlines, each with its reason. Never a bare sleep standing in for a wait.
_CE_VALID_S = 300      # a MANAGED/FARGATE CE provisions a backing ECS cluster
_JQ_VALID_S = 300      # queue VALID follows CE association
_TEARDOWN_S = 300      # DISABLED -> settle -> deleted -> gone, per resource
_JOB_TERMINAL_S = 900  # Fargate cold start + public.ecr.aws image pull + run, ONE attempt
# ECS reports a just-created execution role as unassumable until IAM propagates its trust policy;
# a control job that FAILS for that reason within this window of the first control submission is
# resubmitted, never graded.
_ROLE_PROPAGATION_S = 300


def _swallow(fn):
    """Run fn(); ignore only not-found answers (ENI/IAM NotFound, Batch 'does not exist') and
    raise every other error."""
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


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result); RAISE on deadline miss, never return the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_role(ctx, role_name, policy_arn):
    iam = ctx.client("iam")
    _swallow(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _swallow(lambda: iam.delete_role(RoleName=role_name))


def _fargate_execution_role_arn(ctx):
    """Create this run's ECS task execution role for Fargate Batch jobs; returns its ARN.

    The role is named per run and deleted by this check's cleanup, so no pre-existing or
    shared role is ever adopted.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-exec-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST_POLICY),
        Description="Batch Fargate task execution role",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name, _ECS_TASK_EXECUTION_POLICY))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_ECS_TASK_EXECUTION_POLICY)
    _wait_role_assumable(ctx, role_name)
    return arn


def _wait_role_assumable(ctx, role_name):
    """Bounded wait for a freshly-minted role to be readable by IAM's own read path.

    Reason: IAM create is eventually consistent and Batch/ECS reject a role it cannot yet
    resolve. Polling GetRole is the only condition observable from here, so the wait is
    bounded and raises rather than sleeping blind.
    """
    iam = ctx.client("iam")
    _poll_until(
        lambda: iam.get_role(RoleName=role_name).get("Role"),
        lambda r: bool(r and r.get("Arn")),
        timeout_s=60,
        interval_s=3,
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
    """(subnet_ids, security_group_id) for a Fargate CE, from a VPC this check creates.

    The check never depends on an ambient default VPC: it creates an internet-routable VPC
    with one public subnet and uses that VPC's own default security group.
    """
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
    ec2.get_waiter("vpc_available").wait(
        VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
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


def _wait_ce(bat, name, statuses, timeout_s=_CE_VALID_S, interval_s=5):
    return _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is not None and ce.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"compute environment {name} status in {sorted(statuses)}",
    )


def _wait_jq(bat, name, statuses, timeout_s=_JQ_VALID_S, interval_s=3):
    return _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is not None and jq.get("status") in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"job queue {name} status in {sorted(statuses)}",
    )


def _wait_job_terminal(bat, job_id, timeout_s):
    """Wait for SUCCEEDED or FAILED. The terminal set excludes every transient state."""
    return _poll_until(
        lambda: _describe_job(bat, job_id),
        lambda j: j is not None and j.get("status") in ("SUCCEEDED", "FAILED"),
        timeout_s=timeout_s,
        interval_s=10,
        description=f"job {job_id} reached SUCCEEDED or FAILED",
    )


def _teardown_jobs(bat, job_ids):
    """Terminate every non-terminal job, then wait for each to be terminal.

    A queue cannot be deleted while it holds non-terminal jobs and a CE cannot be deleted
    while a queue references it, so this MUST complete before the queue teardown runs.
    Registered before the queue so ctx's reverse order runs it first.
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


# The batch suite's cleanup budget (900 s), one deadline shared by every Batch delete of a run.
_TEARDOWN_RETRY_S = 900.0


def _delete_retrying(call, teardown_deadline):
    """Run a Batch delete; retry its ClientException refusals every 2 s to the shared deadline.

    A queue still draining or a compute environment still referenced refuses the delete with
    ClientException; an already-deleted resource returns; every other error raises.
    """
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    while True:
        try:
            call()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            if err["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _teardown_jq(bat, name, teardown_deadline):
    """DISABLE -> poll settled -> DeleteJobQueue -> poll gone."""
    _swallow(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _swallow(lambda: _wait_jq(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S))
    _delete_retrying(lambda: bat.delete_job_queue(jobQueue=name), teardown_deadline)
    _swallow(
        lambda: _poll_until(
            lambda: _describe_jq(bat, name),
            lambda jq: jq is None,
            timeout_s=_TEARDOWN_S,
            interval_s=5,
            description=f"job queue {name} gone",
        )
    )


def _teardown_ce(bat, name, teardown_deadline):
    """DISABLE -> poll settled -> DeleteComputeEnvironment -> poll gone."""
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _swallow(lambda: _wait_ce(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_S))
    _delete_retrying(lambda: bat.delete_compute_environment(computeEnvironment=name), teardown_deadline)
    _swallow(
        lambda: _poll_until(
            lambda: _describe_ce(bat, name),
            lambda ce: ce is None,
            timeout_s=_TEARDOWN_S,
            interval_s=5,
            description=f"compute environment {name} gone",
        )
    )


_MIN_HOLD_S = 240  # floor on the absence window
_MAX_HOLD_S = 600  # ceiling, so a pathologically slow control cannot blow the whole budget


def _fargate_ce(ctx, bat, teardown_deadline, *, state, network):
    """A MANAGED/FARGATE CE ending in the requested state, polled to VALID. Returns (name, arn).

    AWS refuses CreateComputeEnvironment(state="DISABLED") with "Compute Environment must be
    created in ENABLED state.", so a DISABLED CE is created ENABLED, then updated and re-polled
    to VALID (a DISABLED CE still reports status VALID).
    """
    subnets, sg = network
    ce_name = ctx.unique_name("sim2real-behav-ce-fg-")
    resp = bat.create_compute_environment(
        computeEnvironmentName=ce_name,
        type="MANAGED",
        state="ENABLED",
        serviceRole=_service_linked_role_arn(ctx),
        computeResources={
            "type": "FARGATE",
            "maxvCpus": 4,
            "subnets": subnets,
            "securityGroupIds": [sg],
        },
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _teardown_ce(bat, ce_name, teardown_deadline))
    ce = _wait_ce(bat, ce_name, {"VALID", "INVALID"})
    assert ce["status"] == "VALID", (
        f"compute environment {ce_name} must reach VALID after creation, got {ce['status']!r}: "
        f"{ce.get('statusReason')!r}"
    )
    if state == "DISABLED":
        bat.update_compute_environment(computeEnvironment=ce_name, state="DISABLED")
        ce = _poll_until(
            lambda: _describe_ce(bat, ce_name),
            lambda c: c is not None and c.get("state") == "DISABLED" and c.get("status") == "VALID",
            timeout_s=_CE_VALID_S,
            interval_s=5,
            description=f"compute environment {ce_name} settles DISABLED/VALID after the update",
        )
    assert ce["state"] == state, (
        f"compute environment {ce_name} must end in the requested state; expected {state!r}, "
        f"got {ce['state']!r}"
    )
    assert ce["status"] == "VALID", (
        f"compute environment {ce_name} must report status VALID in state {state!r} (state and "
        f"status are independent fields), got {ce['status']!r}: {ce.get('statusReason')!r}"
    )
    return ce_name, resp["computeEnvironmentArn"]


def _queue(ctx, bat, ce_arn, teardown_deadline):
    jq_name = ctx.unique_name("sim2real-behav-jq-")
    bat.create_job_queue(
        jobQueueName=jq_name,
        state="ENABLED",
        priority=10,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}],
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _teardown_jq(bat, jq_name, teardown_deadline))
    jq = _wait_jq(bat, jq_name, {"VALID", "INVALID"})
    assert jq["status"] == "VALID", (
        f"job queue {jq_name} must reach VALID, got {jq['status']!r}: {jq.get('statusReason')!r}"
    )
    return jq_name


def _register_jd(ctx, bat, exec_role_arn):
    name = ctx.unique_name("sim2real-behav-jd-fg-")
    resp = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        platformCapabilities=["FARGATE"],
        containerProperties={
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "command": ["/bin/sh", "-c", "exit 0"],
            "executionRoleArn": exec_role_arn,
            "resourceRequirements": [
                {"type": "VCPU", "value": "0.25"},
                {"type": "MEMORY", "value": "512"},
            ],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
            "fargatePlatformConfiguration": {"platformVersion": "LATEST"},
        },
        tags=dict(_MANAGED_TAGS),
    )
    rev = resp["revision"]
    ctx.on_cleanup(
        lambda: _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{rev}"))
    )
    return f"{name}:{rev}"


def _submit(ctx, bat, queue, job_def):
    resp = bat.submit_job(
        jobName=ctx.unique_name("sim2real-behav-job-"), jobQueue=queue, jobDefinition=job_def
    )
    jid = resp["jobId"]
    ctx.on_cleanup(lambda: _teardown_jobs(bat, [jid]))
    return jid


def _placed_control(ctx, bat, queue, job_def, exec_role_arn):
    """Submit the control job and wait until ECS really places it. Returns (job_id, job, t0).

    A control that FAILS because ECS cannot yet assume the just-created execution role (the
    statusReason names that role) is IAM propagation, not placement behaviour: a fresh control is
    submitted, bounded by _ROLE_PROPAGATION_S from the first submission. Any other FAILED raises.
    """
    retry_deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        t0 = time.monotonic()
        job_id = _submit(ctx, bat, queue, job_def)
        job = _poll_until(
            lambda: _describe_job(bat, job_id),
            lambda j: j is not None
            and j.get("status") in ("STARTING", "RUNNING", "SUCCEEDED", "FAILED"),
            timeout_s=_MAX_HOLD_S,
            interval_s=5,
            description=(
                "the ENABLED control compute environment places its job (if this fails the wiring "
                "is broken and the withheld leg proves nothing)"
            ),
        )
        if job["status"] != "FAILED":
            return job_id, job, t0
        reason = job.get("statusReason") or ""
        if exec_role_arn in reason and time.monotonic() < retry_deadline:
            time.sleep(2)
            continue
        raise AssertionError(
            f"the control job {job_id} on the ENABLED compute environment FAILED before placement: "
            f"{reason!r}"
        )


def _assert_withheld(bat, job_id, *, note):
    """The withheld job must be RUNNABLE with no attempt and no startedAt. Returns the job doc.

    Three observables, not one status word, so a target that reports a plausible status while
    the job has in fact run cannot pass.
    """
    job = _describe_job(bat, job_id)
    assert job is not None, f"{note}: DescribeJobs lost the withheld job {job_id}"
    assert job["status"] == "RUNNABLE", (
        f"{note}: a job whose only compute environment is DISABLED must be withheld in RUNNABLE, "
        f"got {job['status']!r} (statusReason={job.get('statusReason')!r})"
    )
    assert not job.get("attempts"), (
        f"{note}: a withheld job must record no attempts, got {job.get('attempts')!r}"
    )
    assert "startedAt" not in job, (
        f"{note}: a withheld job must have no startedAt, got {job.get('startedAt')!r}"
    )
    return job


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DISABLED compute environment withholds a job on its ENABLED queue while an ENABLED twin
    runs the same job, and re-enabling the compute environment releases the already-submitted job
    to SUCCEEDED without resubmission."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    bat = ctx.client("batch")

    # The execution role is created first so IAM has propagated it to ECS by the time a job is
    # placed: the compute environments and queues below are each polled VALID in between.
    exec_role_arn = _fargate_execution_role_arn(ctx)
    network = _networking(ctx)
    _live_ce, live_ce_arn = _fargate_ce(ctx, bat, teardown_deadline, state="ENABLED", network=network)
    withheld_ce, withheld_ce_arn = _fargate_ce(ctx, bat, teardown_deadline, state="DISABLED", network=network)
    live_queue = _queue(ctx, bat, live_ce_arn, teardown_deadline)
    withheld_queue = _queue(ctx, bat, withheld_ce_arn, teardown_deadline)
    job_def = _register_jd(ctx, bat, exec_role_arn)

    # The withheld job and the control run on identical wiring, so the control's measured
    # placement latency L is a fair calibration for the withheld job's absence window.
    withheld_job = _submit(ctx, bat, withheld_queue, job_def)

    # --- positive control: the ENABLED twin places the job, and L is measured, not assumed -----
    control_job, control, t0 = _placed_control(ctx, bat, live_queue, job_def, exec_role_arn)
    latency_s = time.monotonic() - t0
    # On AWS, at STARTING, `attempts` is still [] and `startedAt` is absent --
    # neither is populated until later (RUNNING/terminal). `container.taskArn`, naming the real
    # ECS task, is what appears at STARTING, so that is the real placement observable here.
    assert (control.get("container") or {}).get("taskArn"), (
        f"the control job {control_job} reported {control['status']!r} but named no ECS task, "
        f"so it was not really placed: {control!r}"
    )

    # --- the withheld job must be absent for a window calibrated on that very latency ---------
    hold_s = min(max(3 * latency_s, _MIN_HOLD_S), _MAX_HOLD_S)
    deadline = time.monotonic() + hold_s
    checks = 0
    while time.monotonic() < deadline:
        _assert_withheld(
            bat,
            withheld_job,
            note=(
                f"during the {hold_s:.0f}s absence window (3x the control's measured "
                f"{latency_s:.0f}s placement latency)"
            ),
        )
        checks += 1
        time.sleep(2)
    assert checks >= 3, (
        f"the absence window must be sampled at least 3 times to be evidence, sampled {checks} "
        f"times over {hold_s:.0f}s"
    )

    # The CE's own state is the second observable that the withholding was caused by DISABLED
    # and not by the job being unplaceable for some other reason.
    ce_now = _describe_ce(bat, withheld_ce)
    assert ce_now["state"] == "DISABLED", (
        f"the withholding compute environment must still be DISABLED at the end of the window, "
        f"got {ce_now['state']!r}"
    )

    control_final = _wait_job_terminal(bat, control_job, timeout_s=_JOB_TERMINAL_S)
    assert control_final["status"] == "SUCCEEDED", (
        f"the control job must SUCCEED on the ENABLED compute environment, got "
        f"{control_final['status']!r} (statusReason={control_final.get('statusReason')!r})"
    )

    # --- repair exactly the one broken thing, and DEMAND the withheld job now runs -------------
    bat.update_compute_environment(computeEnvironment=withheld_ce, state="ENABLED")
    reenabled = _poll_until(
        lambda: _describe_ce(bat, withheld_ce),
        lambda ce: ce is not None and ce.get("state") == "ENABLED" and ce.get("status") == "VALID",
        timeout_s=_CE_VALID_S,
        interval_s=5,
        description=f"compute environment {withheld_ce} settles ENABLED/VALID after the update",
    )
    assert reenabled["state"] == "ENABLED", (
        f"UpdateComputeEnvironment must move the state to ENABLED, got {reenabled['state']!r}"
    )

    released = _wait_job_terminal(bat, withheld_job, timeout_s=_JOB_TERMINAL_S)
    assert released["status"] == "SUCCEEDED", (
        f"the previously withheld job must be placed and SUCCEED once its compute environment is "
        f"re-ENABLED, with no re-submission; got {released['status']!r} "
        f"(statusReason={released.get('statusReason')!r})"
    )
    attempts = released["attempts"]
    assert len(attempts) == 1, (
        f"the released job must record exactly 1 attempt (it was never placed while withheld), "
        f"got {len(attempts)}: {attempts!r}"
    )
    assert (attempts[0].get("container") or {}).get("taskArn"), (
        f"the released job's attempt must name the real ECS task it ran as, got "
        f"{attempts[0].get('container')!r}"
    )
    assert isinstance(released.get("startedAt"), int), (
        f"the released job must record a startedAt once placed, got {released.get('startedAt')!r}"
    )
    # The release must be genuinely LATER than the control's completion: the whole point is that
    # this job sat out the window the control spent running.
    assert released["startedAt"] >= control_final["stoppedAt"], (
        f"the withheld job must have started only AFTER the window in which the control ran and "
        f"finished; released.startedAt={released['startedAt']} but "
        f"control.stoppedAt={control_final['stoppedAt']}"
    )


# EC2 network teardown: AWS-managed ENIs (here the Fargate tasks') leave asynchronously, so a
# network delete waits for them, retries DependencyViolation within one window shared by all of
# the check's network deletes, and raises naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
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
