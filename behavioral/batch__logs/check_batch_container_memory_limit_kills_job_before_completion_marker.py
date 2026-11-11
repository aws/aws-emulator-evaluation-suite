"""batch-container-memory-limit-kills-job-before-completion-marker."""

from __future__ import annotations

import json
import sys
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-container-memory-limit-kills-job-before-completion-marker"

GROUP = "container-batch-job"

SERVICES = ["batch", "logs"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A container allocating past its declared MEMORY is killed before its completion marker, while
    the same container allocating well inside the limit completes; only the allocation size
    differs, so the limit is enforced by the runtime, not echoed by the API."""
    bat = ctx.client("batch")
    memory_mib = 512
    over_bytes = 1073741824   # 1 GiB target, doubling, so the peak is ~2x that: far past 512 MiB
    under_bytes = 67108864    # 64 MiB target, peak ~128 MiB: comfortably inside 512 MiB

    log_group = _create_log_group(ctx)
    _n, exec_role = _iam_role(ctx, "exec", _EXEC_STATEMENTS)
    queue = _fargate_stack(ctx, bat, max_vcpus=4)

    def _alloc(target):
        # `&&`-chained: ALLOC_DONE is written only if awk RETURNED. With `;` the shell prints it
        # even after awk is SIGKILLed, and the absence assertion becomes unfalsifiable.
        awk = ('awk \'BEGIN{s="x"; while(length(s)<%d) s=s s; print "LEN=" length(s)}\'' % target)
        return ["sh", "-c", f"echo ALLOC_START; {awk} && echo ALLOC_DONE"]

    job_def = _register_jd(
        ctx, bat, _alloc(over_bytes),
        exec_role_arn=exec_role, log_group=log_group, memory=str(memory_mib),
    )
    control_id = _submit(
        ctx, bat, queue, job_def, containerOverrides={"command": _alloc(under_bytes)}
    )
    victim_id = _submit(ctx, bat, queue, job_def)

    # --- The control is the barrier: it proves the allocation command, the image and the log read
    #     all work, and that 512 MiB is enough for the under-limit target.
    control = _await_job(bat, control_id, {"SUCCEEDED", "FAILED"})
    assert control["status"] == "SUCCEEDED", (
        f"a container allocating {under_bytes} bytes inside a {memory_mib} MiB limit must SUCCEED, "
        f"got {control.get('status')!r} statusReason={control.get('statusReason')!r} "
        f"containerReason={(control.get('container') or {}).get('reason')!r}"
    )
    control_stream = (control.get("container") or {}).get("logStreamName")
    control_msgs = _await_log_line(
        ctx, log_group, control_stream, lambda m: "ALLOC_DONE" in m,
        description="the control container's ALLOC_DONE marker",
    )
    assert any("ALLOC_START" in m for m in control_msgs), (
        f"the control must write ALLOC_START before ALLOC_DONE: {control_msgs!r}"
    )
    assert (control.get("container") or {}).get("exitCode") == 0, (
        f"the under-limit control must exit 0, got "
        f"{(control.get('container') or {}).get('exitCode')!r}"
    )

    # --- Break exactly one thing: the allocation target.
    victim = _await_job(bat, victim_id, {"SUCCEEDED", "FAILED"})
    assert victim["status"] == "FAILED", (
        f"a container allocating {over_bytes} bytes under a {memory_mib} MiB MEMORY declaration "
        f"must be killed, so the job must be FAILED; got {victim.get('status')!r} "
        f"statusReason={victim.get('statusReason')!r} "
        f"containerReason={(victim.get('container') or {}).get('reason')!r}"
    )
    victim_stream = (victim.get("container") or {}).get("logStreamName")
    assert victim_stream and victim_stream != control_stream, (
        f"the killed job must report its own stream, got {victim_stream!r}"
    )
    victim_msgs = _await_log_line(
        ctx, log_group, victim_stream, lambda m: "ALLOC_START" in m,
        description="the victim container's ALLOC_START marker",
    )
    assert not any("ALLOC_DONE" in m for m in victim_msgs), (
        f"the allocation cannot complete under the declared limit, so ALLOC_DONE must never be "
        f"written: {victim_msgs!r}"
    )
    assert not any("LEN=" in m for m in victim_msgs), (
        f"an allocation that was killed cannot have printed its own length: {victim_msgs!r}"
    )
    final = _await_stream_settled(ctx, log_group, victim_stream)
    assert any("ALLOC_START" in m for m in final), (
        f"the victim's ALLOC_START must still be readable on the settled re-read: {final!r}"
    )
    assert not any("ALLOC_DONE" in m for m in final), (
        f"ALLOC_DONE must still be absent once the stream settled: {final!r}"
    )
    # The kill is a real signal, not a clean exit: the runtime SIGKILLs the offending process, so
    # the container's exit code must be the shell's report of that, never 0.
    victim_exit = (victim.get("container") or {}).get("exitCode")
    assert victim_exit != 0, (
        f"a container killed for exceeding its memory limit must not report a successful exit, "
        f"got exitCode={victim_exit!r}"
    )


# ===== helpers =====

_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = {
    # Tags that mark every resource this check creates as its own.
    "sim2real:managed": "true",
    "sim2real:prefix": _PREFIX.rstrip("-"),
    "sim2real": "batch-container-memory-limit-kills-job-before-completion-marker",
}

# Bounded deadlines, each with its reason. Never a bare sleep standing in for a wait.
_CE_TIMEOUT_S = 600       # a MANAGED/FARGATE CE provisions its own backing ECS cluster
_JQ_TIMEOUT_S = 300       # queue VALID follows CE association
_NET_TEARDOWN_S = 300  # Fargate task ENIs release minutes after the job is terminal
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
    """Run a teardown step fn(); return when the resource is already gone, raise anything else."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("InvalidNetworkInterfaceID.NotFound", "NoSuchEntity", "ResourceNotFoundException")
            and not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _delete_while_in_use(fn, timeout_s=60.0):
    """Run a Batch delete, retrying every 2 s while Batch refuses it for a dependency still
    draining (ClientException); not-found returns, anything else or the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _swallow(fn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe(fn):
    """Run fn() and return its result, or None if it raised (probe helper)."""
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result.

    Raises AssertionError on deadline miss -- deliberately, not AssertionError: a condition that
    never arrives is the fidelity failure this suite exists to catch.
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

    Raises when fn() SUCCEEDS instead of returning a falsy sentinel: an emulator that accepts
    input real AWS rejects is the strongest signal available here, and returning "" would
    downgrade it into an error-code mismatch that reads like a naming difference.
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

    An account can hold enough other resources to push the one this check asserts membership in
    off page one.
    """
    out = []
    try:
        pages = client.get_paginator(op).paginate(**kwargs)
    except Exception:  # noqa: BLE001 - no paginator modelled for this op
        return getattr(client, op)(**kwargs).get(key, [])
    for page in pages:
        out.extend(page.get(key, []))
    return out


def _create_network(ctx):
    """(subnet_ids, security_group_id) from a VPC this check creates; no account default is read.

    Public subnets in up to two available zones, routed through an internet gateway, so a task
    with assignPublicIp=ENABLED can pull from public.ecr.aws and write awslogs without a NAT
    gateway. The security group is the created VPC's own default group. Teardown is registered
    first, so ctx's LIFO order runs it after the compute environment that holds the subnets.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.182.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    net = {"vpc": vpc_id, "subnets": [], "igw": None}
    ctx.on_cleanup(lambda: _teardown_network(ctx, net))
    _poll_until(
        lambda: (_safe(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])) or {}).get("Vpcs", [{}])[0].get("State"),
        lambda s: s == "available",
        timeout_s=120, interval_s=2,
        description=f"vpc {vpc_id} available",
    )
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_kv()}]
    )["InternetGateway"]["InternetGatewayId"]
    net["igw"] = igw_id
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    main_rt = _poll_until(
        lambda: [
            rt["RouteTableId"]
            for rt in ec2.describe_route_tables(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "association.main", "Values": ["true"]},
                ]
            )["RouteTables"]
        ],
        bool,
        timeout_s=120, interval_s=2,
        description=f"main route table of {vpc_id}",
    )[0]
    ec2.create_route(RouteTableId=main_rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )[:2]
    assert zones, "the region reports no available availability zone"
    for i, az in enumerate(zones):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            AvailabilityZone=az,
            CidrBlock=f"10.182.{i + 1}.0/24",
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
        )["Subnet"]["SubnetId"]
        net["subnets"].append(subnet_id)
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    ).get("SecurityGroups", [])
    assert sgs, f"VPC {vpc_id} has no default security group"
    return list(net["subnets"]), sgs[0]["GroupId"]


def _net_retry(fn, label, *, budget_s=_NET_TEARDOWN_S, interval_s=10):
    """Repeat an EC2 delete through DependencyViolation within a bounded window; then raise."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return True
        except Exception as exc:  # noqa: BLE001 - still referenced while ENIs release
            if time.monotonic() >= deadline:
                raise RuntimeError(f"could not delete {label}: {exc}") from exc
            time.sleep(interval_s)


def _teardown_network(ctx, net):
    """Delete the VPC estate after ECS has released the Fargate task ENIs.

    ECS deletes a task's ENI minutes after the job is terminal, and DeleteSubnet raises
    DependencyViolation until it has, so each delete is retried inside one bounded window.
    """
    ec2 = ctx.client("ec2")
    vpc_id = net.get("vpc")
    if not vpc_id:
        return
    _swallow(lambda: _poll_until(
        lambda: ec2.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["NetworkInterfaces"],
        lambda found: not found,
        timeout_s=_NET_TEARDOWN_S, interval_s=10,
        description=f"ECS to release every ENI in {vpc_id}",
    ))
    for subnet_id in list(net["subnets"]):
        if _net_retry(lambda s=subnet_id: ec2.delete_subnet(SubnetId=s), f"subnet {subnet_id}"):
            net["subnets"].remove(subnet_id)
    if net.get("igw"):
        _net_retry(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=net["igw"], VpcId=vpc_id),
            f"internet gateway {net['igw']} detach",
        )
        if _net_retry(lambda: ec2.delete_internet_gateway(InternetGatewayId=net["igw"]),
                      f"internet gateway {net['igw']}"):
            net["igw"] = None
    if _net_retry(lambda: ec2.delete_vpc(VpcId=vpc_id), f"vpc {vpc_id}"):
        net["vpc"] = None


def _iam_role(ctx, kind, statements):
    """Create a role trusting ecs-tasks with ONE inline policy; returns (name, arn).

    Fresh per check rather than a shared account-level role: a shared role lets one check's
    teardown delete the role another check's job is still pulling under, which surfaces as
    CannotPullContainerError and reads exactly like a fidelity failure.

    IAM is eventually consistent, so the inline policy is polled back, and the role is created
    before the compute environment: CE provisioning gives the trust policy time to reach ECS
    before any task references the role.
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

    DeleteJobQueue raises ClientException for a queue that is still draining and accepts the same
    call seconds later, so the delete retries to a deadline.
    """
    _swallow(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _swallow(lambda: _await_jq(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_TIMEOUT_S))
    _delete_while_in_use(lambda: bat.delete_job_queue(jobQueue=name))
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
    so both the state change and the delete are polled; the delete retries like the queue's.
    """
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _swallow(lambda: _await_ce(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_TIMEOUT_S))
    _delete_while_in_use(lambda: bat.delete_compute_environment(computeEnvironment=name))
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

    FARGATE, never EC2: a MANAGED/EC2 CE with minvCpus > 0 keeps instances alive and is the
    classic Batch cost leak. FARGATE has no minvCpus floor, so an idle CE bills nothing even if
    teardown is interrupted; maxvCpus only caps concurrency.
    Teardowns are registered CE-then-queue, so ctx's LIFO order runs queue-then-CE.
    """
    subnets, sg = _create_network(ctx)
    ce_name = ctx.unique_name(_PREFIX + "ce-fg-")
    service_role = _batch_slr(ctx)
    # Bounded retry at first use: a just-created service-linked role can be rejected as not yet
    # assumable, and that 400 is the only signal IAM propagation gives.
    for attempt in range(8):
        try:
            ce_arn = bat.create_compute_environment(
                computeEnvironmentName=ce_name,
                type="MANAGED",
                state="ENABLED",
                serviceRole=service_role,
                computeResources={
                    "type": "FARGATE",
                    "maxvCpus": max_vcpus,
                    "subnets": subnets[:3],
                    "securityGroupIds": [sg],
                },
                tags=dict(_MANAGED_TAGS),
            )["computeEnvironmentArn"]
            break
        except Exception as exc:  # noqa: BLE001 - only an IAM-propagation 400 is retryable
            msg = str(exc).lower()
            if not ("cannot be assumed" in msg or "sts:assumerole" in msg) or attempt == 7:
                raise
            time.sleep(5)
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

    Deliberately NOT the AWS-managed /aws/batch/job group every Batch job in the account shares:
    deleting that would be a cross-tenant hazard, and reading it would mix in a sibling check's
    output.
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

    ListJobs defaults jobStatus to RUNNING, so enumerating an array's children without naming each
    status returns [] the moment they stop running -- which is precisely when their results are
    read. Measured on real AWS: a size-3 array whose statusSummary already showed 3 SUCCEEDED
    enumerated 0 children.
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

    A convergence gate, not a sleep. Asserting that a line is absent needs CloudWatch ingestion to
    have caught up, and Logs offers no "complete" signal to poll -- so stability across N reads
    spanning N*interval_s is the observable condition that stands in for one, and a stream that
    never settles raises instead of quietly reading a partial view.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
