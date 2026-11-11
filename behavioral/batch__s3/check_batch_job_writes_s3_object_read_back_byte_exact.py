"""batch-job-writes-s3-object-read-back-byte-exact."""

from __future__ import annotations

import hashlib
import json
import sys
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-job-writes-s3-object-read-back-byte-exact"

GROUP = "container-batch-job"

SERVICES = ["batch", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Batch job using its jobRoleArn copies an S3 object, and the copy is byte-identical.

    The container's credentials must allow GetObject on the source and PutObject on the destination;
    bytes, length and single-part MD5 are asserted, and nothing else is written to the bucket.
    """
    bat = ctx.client("batch")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    payload = ("sim2real-batch-s3 " + ctx.unique_name("payload-") + "\n" + ("x" * 512)).encode()
    src_key = "src/" + ctx.unique_name("obj-")
    dst_key = "dst/" + ctx.unique_name("obj-")
    s3.put_object(Bucket=bucket, Key=src_key, Body=payload)

    # Scoped to exactly the two prefixes the copy needs, and nothing else in the bucket.
    _n, job_role = _iam_role(ctx, "jobrole", [
        {"Effect": "Allow", "Action": ["s3:GetObject"],
         "Resource": f"arn:aws:s3:::{bucket}/src/*"},
        {"Effect": "Allow", "Action": ["s3:PutObject"],
         "Resource": f"arn:aws:s3:::{bucket}/dst/*"},
    ])
    _e, exec_role = _iam_role(ctx, "exec", _EXEC_STATEMENTS)
    queue = _fargate_stack(ctx, bat, max_vcpus=4)
    job_def = _register_jd(
        ctx, bat,
        ["s3", "cp", f"s3://{bucket}/{src_key}", f"s3://{bucket}/{dst_key}",
         "--region", ctx.region],
        exec_role_arn=exec_role, job_role_arn=job_role, image=_AWSCLI_IMAGE,
        memory="1024", environment=[{"name": "AWS_DEFAULT_REGION", "value": ctx.region}],
        # IAM is eventually consistent and offers no condition reporting that a role has become
        # assumable, so a first attempt can lose to propagation. Two attempts, retried only on a
        # non-zero container exit -- the retry is the correctness mechanism, not a sleep.
        retry_strategy={"attempts": 2,
                        "evaluateOnExit": [{"onExitCode": "1", "action": "RETRY"},
                                           {"onReason": "*", "action": "EXIT"}]},
    )
    job_id = _submit(ctx, bat, queue, job_def)

    job = _await_job(bat, job_id, {"SUCCEEDED", "FAILED"})
    assert job["status"] == "SUCCEEDED", (
        f"the copying job must SUCCEED, got {job.get('status')!r} "
        f"statusReason={job.get('statusReason')!r} "
        f"containerReason={(job.get('container') or {}).get('reason')!r}"
    )
    assert (job.get("container") or {}).get("exitCode") == 0, (
        f"aws-cli exits 0 only when the copy completed, got "
        f"{(job.get('container') or {}).get('exitCode')!r}"
    )

    head = _poll_until(
        lambda: _safe(lambda: s3.head_object(Bucket=bucket, Key=dst_key)),
        lambda h: h is not None,
        timeout_s=120,
        interval_s=3,
        description=f"s3://{bucket}/{dst_key} exists",
    )
    body = s3.get_object(Bucket=bucket, Key=dst_key)["Body"].read()
    assert body == payload, (
        f"the object the container wrote must be byte-identical to the payload the check uploaded; "
        f"got {len(body)} bytes {body[:64]!r}... against {len(payload)} bytes {payload[:64]!r}..."
    )
    assert head["ContentLength"] == len(payload), (
        f"ContentLength {head['ContentLength']!r} != {len(payload)!r}"
    )
    assert head["ETag"].strip('"') == hashlib.md5(payload).hexdigest(), (
        f"the ETag of a single-part object must be the MD5 of its bytes, got {head['ETag']!r} "
        f"against {hashlib.md5(payload).hexdigest()!r}"
    )
    # The container wrote to the destination and nowhere else in the bucket.
    keys = sorted(o["Key"] for o in _paginate(s3, "list_objects_v2", "Contents", Bucket=bucket))
    assert keys == sorted([src_key, dst_key]), (
        f"the bucket must hold exactly the source and the destination, got {keys!r}"
    )


# ===== helpers =====

_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = {
    # The tag and the sim2real- name prefix make leftovers discoverable by account cleanup.
    "sim2real:managed": "true",
    "sim2real:prefix": _PREFIX.rstrip("-"),
    "sim2real": "batch-s3-byte-exact",
}

# Bounded deadlines, each with its reason.
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
            err["Code"] not in ("NoSuchBucket", "NoSuchEntity", "ResourceNotFoundException")
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
    """The AWS error code fn() raised.

    Raises when fn() succeeds, so an accepted call is not mistaken for an error-code mismatch.
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

    Other resources in the account can push the one asserted on off page one.
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
    """(subnet_ids, security_group_id) from a VPC this check creates, with public subnets.

    An internet gateway lets public-IP tasks reach ECR Public and awslogs without a NAT gateway.
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


def _net_retry(fn, label, *, budget_s=_NET_TEARDOWN_S, interval_s=2):
    """Run an EC2 delete, retrying DependencyViolation to a deadline; not-found returns, else raise."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return True
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code.endswith(".NotFound") or code == "Gateway.NotAttached":
                return True
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                raise RuntimeError(f"could not delete {label}: {exc}") from exc
            time.sleep(interval_s)


def _teardown_network(ctx, net):
    """Delete the VPC after ECS has released the Fargate task ENIs.

    ECS deletes task ENIs minutes after the job ends; DependencyViolation until then is retried.
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
        timeout_s=_NET_TEARDOWN_S, interval_s=2,
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
    """Create a fresh role trusting ecs-tasks with ONE inline policy; returns (name, arn).

    IAM is eventually consistent, so the policy is polled back; CE provisioning adds settle time.
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

    Account-level and shared, so it is created-or-reused and never deleted.
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
    """Terminate every job, then wait for each to be terminal.

    DeleteJobQueue fails while the queue holds a non-terminal job, which would leak queue and CE.
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

    DeleteJobQueue raises ClientException while the queue drains and accepts the same call later.
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

    An ENABLED compute environment cannot be deleted and the delete is asynchronous, so both poll.
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

    FARGATE, not EC2: an idle Fargate CE bills nothing. Teardown runs queue-then-CE (LIFO).
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

    Not the shared /aws/batch/job group, which other jobs in the account also write to.
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

    GetLogEvents repeats its token when exhausted; an empty page alone does not mean the end.
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

    The awslogs driver opens the stream before the container writes anything.
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

    ListJobs defaults jobStatus to RUNNING, so finished children are omitted unless each is named.
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

    Logs has no ingestion-complete signal, so stability stands in for one before asserting absence.
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


def _create_bucket(ctx):
    """A bucket this check owns; teardown paginates every object out before DeleteBucket."""
    s3 = ctx.client("s3")
    name = ctx.unique_name(_PREFIX + "batch-s3-")
    kwargs = dict(Bucket=name)
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _drop():
        for obj in _paginate(s3, "list_objects_v2", "Contents", Bucket=name):
            _swallow(lambda k=obj["Key"]: s3.delete_object(Bucket=name, Key=k))
        _swallow(lambda: s3.delete_bucket(Bucket=name))
        if _safe(lambda: s3.head_bucket(Bucket=name)) is not None:
            raise RuntimeError(f"S3 bucket {name} still present after DeleteBucket")

    ctx.on_cleanup(_drop)
    _safe(lambda: s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _tags_kv()}))
    return name


# The official AWS CLI v2 image. Its ENTRYPOINT is /usr/local/bin/aws and Batch's
# containerProperties has NO entryPoint member, so `command` is a bare argv of aws arguments and
# there is no shell inside the container. Pinned to the published tag the pull can always resolve.
_AWSCLI_IMAGE = "public.ecr.aws/aws-cli/aws-cli:latest"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
