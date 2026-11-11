"""batch-sequential-array-children-run-one-at-a-time-in-index-order."""

from __future__ import annotations

import json
import sys
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-sequential-array-children-run-one-at-a-time-in-index-order"

GROUP = "container-batch-job"

SERVICES = ["batch", "logs"]

_CHECK_TAG = CHECK

_ARRAY_SIZE = 3
_CHILD_WORK_S = 15  # each child container's own dwell, long enough that an overlap would be visible


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SEQUENTIAL array dependency makes the children of one array job run strictly one after
    another in ascending index order, on capacity that could run them all at once: child i's first
    logged line follows child i-1's last."""
    bat = ctx.client("batch")

    log_group = _create_log_group(ctx)
    _n, exec_role = _iam_role(ctx, "exec", _EXEC_STATEMENTS)
    # 4 vCPUs against 3 x 0.25 vCPU children: capacity is NOT what serialises them.
    queue, ce, net = _fargate_stack(ctx, bat, max_vcpus=4)
    array_id = None
    try:
        job_def = _register_jd(
            ctx, bat,
            ["sh", "-c",
             f"echo BEGIN=$AWS_BATCH_JOB_ARRAY_INDEX; sleep {_CHILD_WORK_S}; "
             f"echo END=$AWS_BATCH_JOB_ARRAY_INDEX"],
            exec_role_arn=exec_role, log_group=log_group,
        )

        # dependsOn with a type and NO jobId is the documented sequential-array form: the dependency is
        # between the children of this very submission.
        array_id = _submit(
            ctx, bat, queue, job_def,
            arrayProperties={"size": _ARRAY_SIZE},
            dependsOn=[{"type": "SEQUENTIAL"}],
        )

        parent = _await_job(bat, array_id, set(_TERMINAL))
        assert parent["status"] == "SUCCEEDED", (
            f"every child exits 0, so the array parent must end SUCCEEDED, got "
            f"{parent.get('status')!r} statusReason={parent.get('statusReason')!r} "
            f"arrayProperties={parent.get('arrayProperties')!r}"
        )
        summary = (parent.get("arrayProperties") or {}).get("statusSummary") or {}
        assert summary.get("SUCCEEDED") == _ARRAY_SIZE, (
            f"the parent's statusSummary must account for all {_ARRAY_SIZE} children as SUCCEEDED, got "
            f"{summary!r}"
        )

        # Enumerated across every status, because ListJobs defaults to RUNNING and the children are
        # already terminal by now.
        children = _array_children(bat, array_id)
        assert len(children) == _ARRAY_SIZE, (
            f"the array must enumerate exactly {_ARRAY_SIZE} children, got {sorted(children)!r}"
        )

        per_index = {}
        for i in range(_ARRAY_SIZE):
            child_id = f"{array_id}:{i}"
            assert child_id in children, (
                f"child index {i} must be listed under the array job as {child_id!r}; ListJobs "
                f"returned {sorted(children)!r}"
            )
            child = _describe_job(bat, child_id)
            assert child is not None, f"DescribeJobs returned nothing for array child {child_id!r}"
            assert child["status"] == "SUCCEEDED", (
                f"array child {i} must end SUCCEEDED, got {child.get('status')!r} "
                f"statusReason={child.get('statusReason')!r} "
                f"containerReason={(child.get('container') or {}).get('reason')!r}"
            )
            assert (child.get("container") or {}).get("exitCode") == 0, (
                f"array child {i} ran echo/sleep/echo and must exit 0, got "
                f"{(child.get('container') or {}).get('exitCode')!r}"
            )
            assert (child.get("arrayProperties") or {}).get("index") == i, (
                f"array child {child_id!r} must report index {i}, got "
                f"{child.get('arrayProperties')!r}"
            )
            stream = _job_stream(child)
            assert stream, f"array child {i} reported no awslogs stream: container={child.get('container')!r}"
            per_index[i] = (child, stream)

        streams = [per_index[i][1] for i in range(_ARRAY_SIZE)]
        assert len(set(streams)) == _ARRAY_SIZE, (
            f"each child runs its own container and must write its own stream, got {streams!r}"
        )

        # The containers' own output, parsed structurally: an emulator that echoed the command back, or
        # that left $AWS_BATCH_JOB_ARRAY_INDEX unexpanded, must not pass.
        spans = {}
        for i in range(_ARRAY_SIZE):
            stream = per_index[i][1]
            _await_log_line(
                ctx, log_group, stream, lambda m, i=i: m.strip() == f"END={i}",
                description=f"array child {i}'s END={i} line",
            )
            events = [(ts, m.strip()) for ts, m in _log_events(ctx, log_group, stream)]
            assert [m for _ts, m in events] == [f"BEGIN={i}", f"END={i}"], (
                f"array child {i}'s stream must hold exactly its own two lines, got {events!r}"
            )
            spans[i] = {m: ts for ts, m in events}

        settled = _await_group_settled(ctx, log_group)
        assert sorted(settled) == sorted(streams), (
            f"the log group belongs to this check alone, so it must hold exactly the {_ARRAY_SIZE} "
            f"streams the children reported, got {sorted(settled)!r} against {sorted(streams)!r}"
        )

        for i in range(1, _ARRAY_SIZE):
            prev_end = spans[i - 1][f"END={i - 1}"]
            this_begin = spans[i][f"BEGIN={i}"]
            assert this_begin >= prev_end, (
                f"a SEQUENTIAL array runs its children one at a time in index order, so child {i}'s "
                f"first line (BEGIN={i} at {this_begin} ms) cannot predate child {i - 1}'s last line "
                f"(END={i - 1} at {prev_end} ms). All spans: {spans!r}"
            )
    finally:
        # The jobs, queue, compute environment and network are released here, within the check's
        # own deadline, on the failure path as on the success path; see _release_estate.
        _release_estate(ctx, bat, queue, ce, net, jobs=[j for j in (array_id,) if j])



# ===== helpers =====

_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = {
    # Tags that mark every resource this check creates as its own.
    # Every create passes it inline rather than tagging afterwards: a create that succeeds and is
    # then tagged in a second call is untagged for the window in between, and that window is
    # exactly when a run dies and leaves the thing behind.
    "sim2real:managed": "true",
    "sim2real:prefix": _PREFIX.rstrip("-"),
    "sim2real": _CHECK_TAG,
}

# Bounded deadlines, each with its reason. Never a bare sleep standing in for a wait.
_CE_TIMEOUT_S = 600            # a MANAGED/FARGATE CE provisions its own backing ECS cluster
_JQ_TIMEOUT_S = 300            # queue VALID follows CE association
_TEARDOWN_TIMEOUT_S = 420      # DISABLED -> settled -> deleted -> gone, per resource
_NET_TEARDOWN_TIMEOUT_S = 420  # ECS releases a Fargate task's ENI minutes after the job is terminal
_JOB_TIMEOUT_S = 1500          # Fargate placement + public.ecr.aws image pull + run
_LOG_TIMEOUT_S = 420           # awslogs stream creation, then first event delivery

# This check's own network. A VPC CIDR need not be unique within an account, so two concurrent
# runs in this account each get their own VPC carrying these same ranges without colliding; the
# two subnets are /20s carved out of it, one per derived availability zone.
_VPC_CIDR = "10.240.0.0/16"
_SUBNET_CIDRS = ("10.240.0.0/20", "10.240.16.0/20")
_SUBNET_COUNT = len(_SUBNET_CIDRS)
# The probe type for the AZ derivation in _usable_azs. Nothing runs on it -- Fargate has no
# instance type -- it is the observable current-generation-capacity signal AWS does publish per
# zone, which is the closest proxy for the Fargate placement AWS does not publish.
_AZ_PROBE_TYPE = "m5.large"
# Bounded, and deliberately tighter than _retry_delete's default: six network deletes run back to
# back inside the check's own budget, so the worst case has to stay well under it.
_NET_RETRY_S = 60

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
        msg = err.get("Message", "")
        if not (
            err["Code"] in ("InvalidNetworkInterfaceID.NotFound", "NoSuchEntity", "ResourceNotFoundException")
            or (err["Code"] == "ClientException" and ("does not exist" in msg or "not found" in msg))
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

    Raises AssertionError on deadline miss -- deliberately: a condition that never arrives is the
    fidelity failure this suite exists to catch, not an infrastructure hiccup to swallow.
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


def _retry_delete(fn, label, *, timeout_s=120):
    """Call an EC2 delete, retrying DependencyViolation every 2 s while a reference is released
    asynchronously; a not-found answer returns, anything else or the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return True
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code.endswith(".NotFound") or code == "Gateway.NotAttached":
                return True
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise RuntimeError(f"could not delete {label}: {code}") from exc
        time.sleep(2)


def _usable_azs(ctx, want):
    """`want` availability zones this region can actually place a Fargate task in, DERIVED.

    Fargate publishes no AZ catalogue, so the zone is derived from the closest proxy real AWS does
    publish: a zone that is reported `available` AND offers a current-generation general-purpose
    instance type. Both halves are needed and neither is sufficient --
    describe_instance_type_offerings does not report zone state, so an impaired zone still appears
    as offering the type, and describe_availability_zones says nothing about what a zone can run.
    The zones with no current-generation capacity are the same ones Fargate is absent from, which
    is what makes the intersection the right filter rather than merely a plausible one.

    Never a literal: an AZ *name* is a per-account alias for a different physical zone, so the one
    that worked in one account is a different zone in the next. And never omitted: create_subnet
    with no AvailabilityZone lets AWS choose, and what it chooses need not be able to run the work.

    An empty intersection FAILS by name rather than falling back to a guess -- it means this region
    cannot run the check, which is a finding, not a zone to pick at random.
    """
    ec2 = ctx.client("ec2")
    offered = {
        o["Location"]
        for o in _paginate(
            ec2, "describe_instance_type_offerings", "InstanceTypeOfferings",
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_AZ_PROBE_TYPE]}],
        )
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert len(usable) >= want, (
        f"need {want} availability zone(s) that are available AND offer {_AZ_PROBE_TYPE!r}, and "
        f"only {len(usable)} qualify: available-and-offering={usable!r}, offering={sorted(offered)!r}"
    )
    return usable[:want]


def _create_network(ctx):
    """Create this check's OWN VPC, subnets, internet gateway, route and security group.

    Returns a mutable dict of ids that _teardown_network consumes. Nothing here is read from the
    account, so the check also runs on an account with no default VPC.

    Public subnets with an internet-gateway route, never a NAT gateway: the task needs egress to
    pull from public.ecr.aws and to open its awslogs stream, assignPublicIp=ENABLED gives it that
    through the IGW, and an IGW bills nothing and deletes in seconds where a NAT gateway does
    neither. The route goes in the VPC's own main route table, which CreateVpc made and DeleteVpc
    takes with it, so teardown has one less resource to converge on.

    Every EC2 resource is tagged in the SAME call that creates it, via TagSpecifications, so it is
    never untagged in the window in which a run can die.
    """
    ec2 = ctx.client("ec2")
    azs = _usable_azs(ctx, _SUBNET_COUNT)
    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    net = {"vpc": vpc_id, "subnets": [], "sg": None, "igw": None, "azs": list(azs)}
    # Registered before anything is put INSIDE the VPC, so ctx's LIFO order runs it after the
    # compute environment that references the subnets has gone.
    ctx.on_cleanup(lambda: _teardown_network(ctx, net))
    _poll_until(
        lambda: (_safe(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])) or {}).get("Vpcs", [{}])[0].get("State"),
        lambda s: s == "available",
        timeout_s=120, interval_s=2,
        description=f"vpc {vpc_id} available",
    )
    # Both attributes explicitly: the task resolves api.ecr.aws and logs.<region>.amazonaws.com
    # through the VPC resolver, and a CreateVpc default is a default, not a guarantee.
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
            for rt in _paginate(
                ec2, "describe_route_tables", "RouteTables",
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "association.main", "Values": ["true"]},
                ],
            )
        ],
        lambda ids: bool(ids),
        timeout_s=120, interval_s=2,
        description=f"main route table of {vpc_id}",
    )[0]
    ec2.create_route(RouteTableId=main_rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            AvailabilityZone=az,
            CidrBlock=_SUBNET_CIDRS[i],
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
        )["Subnet"]["SubnetId"]
        net["subnets"].append(subnet_id)
    _poll_until(
        lambda: [
            sn["State"]
            for sn in _paginate(
                ec2, "describe_subnets", "Subnets",
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
            )
        ],
        lambda states: len(states) == _SUBNET_COUNT and set(states) == {"available"},
        timeout_s=120, interval_s=2,
        description=f"{_SUBNET_COUNT} subnets available in {vpc_id}",
    )

    net["sg"] = ec2.create_security_group(
        GroupName=ctx.unique_name(_PREFIX + "sg-"),
        VpcId=vpc_id,
        Description="SimParity behavioral: Batch Fargate task egress",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv()}],
    )["GroupId"]
    # No ingress rule is added and none is needed: the task only ever makes outbound connections,
    # and a fresh security group already permits all egress.
    return net


def _teardown_network(ctx, net):
    """Delete the VPC estate, waiting for ECS to release the Fargate ENIs first.

    ECS deletes a Fargate task's ENI minutes after the job is terminal and DeleteSubnet raises
    DependencyViolation until then, so the body runs this within its own deadline and the
    registered cleanup re-runs it, returning at once when the VPC is already gone. Order follows
    the references: ENIs, security group and subnets, internet gateway, VPC; a residue raises.
    """
    ec2 = ctx.client("ec2")
    vpc_id = net.get("vpc")
    if not vpc_id or _safe(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])) is None:
        return

    def _enis():
        return _paginate(
            ec2, "describe_network_interfaces", "NetworkInterfaces",
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
        )

    try:
        _poll_until(
            _enis, lambda found: not found,
            timeout_s=_NET_TEARDOWN_TIMEOUT_S, interval_s=10,
            description=f"ECS to release every ENI in {vpc_id}",
        )
    except AssertionError:
        # A detached ENI that ECS abandoned is ours to delete; one still in use is not, and the
        # DependencyViolation retries below are what report it.
        for eni in _enis():
            if eni.get("Status") == "available" and not eni.get("RequesterManaged"):
                _swallow(lambda e=eni: ec2.delete_network_interface(
                    NetworkInterfaceId=e["NetworkInterfaceId"]))

    if net.get("sg"):
        if _retry_delete(lambda: ec2.delete_security_group(GroupId=net["sg"]),
                         f"security group {net['sg']}", timeout_s=_NET_RETRY_S):
            net["sg"] = None
    for subnet_id in list(net.get("subnets") or []):
        if _retry_delete(lambda s=subnet_id: ec2.delete_subnet(SubnetId=s),
                         f"subnet {subnet_id}", timeout_s=_NET_RETRY_S):
            net["subnets"].remove(subnet_id)
    if net.get("igw"):
        _retry_delete(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=net["igw"], VpcId=vpc_id),
            f"internet gateway {net['igw']} detach from {vpc_id}", timeout_s=_NET_RETRY_S,
        )
        if _retry_delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=net["igw"]),
                         f"internet gateway {net['igw']}", timeout_s=_NET_RETRY_S):
            net["igw"] = None
    _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id), f"vpc {vpc_id}", timeout_s=_NET_RETRY_S)
    if _safe(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])) is None:
        net["vpc"] = None
    else:
        raise RuntimeError(f"vpc {vpc_id} still present after DeleteVpc")


def _release_estate(ctx, bat, queue, ce_name, net, jobs):
    """Release jobs, queue, compute environment and network inside the body, on both paths.

    The sequence takes minutes (Fargate ENIs release well after the job is terminal), so it runs
    within the check's own deadline. Every step runs; a failure raises after the last one and
    carries the in-flight error, so it never hides the assertion's verdict.
    """
    left = []
    for step in (lambda: _teardown_jobs(bat, jobs), lambda: _teardown_jq(bat, queue),
                 lambda: _teardown_ce(bat, ce_name), lambda: _teardown_network(ctx, net)):
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - collected, raised after the last step
            left.append(repr(exc))
    if left:
        found = sys.exc_info()[1]
        raise AssertionError(
            (f"{found!r}; " if found else "")
            + f"teardown could not remove everything the check created: {left!r}"
        )


def _iam_role(ctx, kind, statements):
    """Create a role trusting ecs-tasks with ONE inline policy; returns (name, arn).

    Fresh per check rather than a shared account-level role: a shared role lets one check's
    teardown delete the role another check's job is still pulling under, which surfaces as
    CannotPullContainerError and reads exactly like a fidelity failure.

    IAM is eventually consistent and exposes no condition reporting that a role has become
    assumable, so the inline policy is polled back, and the role is created before the compute
    environment: CE provisioning gives the trust policy time to reach ECS before any task
    references the role.
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


_JOB_STATUSES = ("SUBMITTED", "PENDING", "RUNNABLE", "STARTING", "RUNNING", "SUCCEEDED", "FAILED")
_TERMINAL = ("SUCCEEDED", "FAILED")


def _array_children(bat, array_job_id):
    """Every child of an array job, keyed by jobId, across EVERY status.

    ListJobs defaults jobStatus to RUNNING, so enumerating an array's children without naming each
    status returns [] the moment they stop running -- which is precisely when their results are
    read.
    """
    out = {}
    for status in _JOB_STATUSES:
        for js in _paginate(
            bat, "list_jobs", "jobSummaryList", arrayJobId=array_job_id, jobStatus=status
        ) or []:
            out[js["jobId"]] = js
    return out


def _teardown_jobs(bat, job_ids):
    """Terminate every job AND every array child of one, then WAIT for each to be terminal.

    The wait is the load-bearing half: DeleteJobQueue is a 400 while the queue holds a
    non-terminal job, and DeleteComputeEnvironment is a 400 while a queue still references it,
    so skipping it leaks the queue AND the compute environment while the check passes. Array
    children are expanded because a blocked child is exactly the case a dependency check leaves
    behind, and it holds the queue open under an id SubmitJob never returned.
    """
    ids = list(job_ids)
    for jid in list(ids):
        for child in (_safe(lambda jid=jid: _array_children(bat, jid)) or {}):
            if child not in ids:
                ids.append(child)
    for jid in ids:
        _swallow(lambda jid=jid: bat.terminate_job(jobId=jid, reason=_PREFIX + "cleanup"))
    stuck = []
    for jid in ids:
        try:
            _poll_until(
                lambda jid=jid: _describe_job(bat, jid),
                lambda j: j is None or j.get("status") in _TERMINAL,
                timeout_s=_TEARDOWN_TIMEOUT_S,
                interval_s=2,
                description=f"job {jid} terminal before queue teardown",
            )
        except Exception as exc:  # noqa: BLE001
            msg = (f"batch job {jid} never reached a terminal state; the queue and compute "
                   f"environment behind it may not have been deletable")
            stuck.append((msg, exc))
    if stuck:
        raise RuntimeError("; ".join(msg for msg, _ in stuck)) from stuck[0][1]


def _teardown_jq(bat, name):
    """DISABLE -> poll settled -> DeleteJobQueue (retried) -> poll gone.

    DeleteJobQueue raises ClientException for a queue that is still draining and accepts the same
    call seconds later, so the delete retries to a deadline.

    Returns at once if the queue is already gone, and that early exit is load-bearing rather than
    tidy: on the success path the body has already released it (see _release_estate), so this runs
    as the net, and polling for a status a deleted queue never reports would burn the cleanup budget
    and strand every cheaper delete queued behind it.
    """
    if _safe(lambda: _describe_jq(bat, name)) is None:
        return
    _swallow(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _swallow(lambda: _await_jq(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_TIMEOUT_S))
    _delete_while_in_use(lambda: bat.delete_job_queue(jobQueue=name))
    _poll_until(
        lambda: _describe_jq(bat, name),
        lambda jq: jq is None,
        timeout_s=_TEARDOWN_TIMEOUT_S,
        interval_s=2,
        description=f"job queue {name} gone",
    )


def _teardown_ce(bat, name):
    """DISABLE -> poll settled -> DeleteComputeEnvironment (retried) -> poll gone.

    DeleteComputeEnvironment requires the environment to be DISABLED first and does not converge
    otherwise: retrying the delete against an ENABLED environment fails identically forever. The
    delete is then asynchronous, so both halves are polled.
    """
    if _safe(lambda: _describe_ce(bat, name)) is None:
        return  # already released by the body; see the note in _teardown_jq
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _swallow(lambda: _await_ce(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_TIMEOUT_S))
    _delete_while_in_use(lambda: bat.delete_compute_environment(computeEnvironment=name))
    _poll_until(
        lambda: _describe_ce(bat, name),
        lambda ce: ce is None,
        timeout_s=_TEARDOWN_TIMEOUT_S,
        interval_s=2,
        description=f"compute environment {name} gone",
    )


def _fargate_stack(ctx, bat, *, max_vcpus):
    """This check's own network + a MANAGED/FARGATE compute environment + an ENABLED queue.

    Returns (queue_name, ce_name, net) -- the CE name and the network because the body releases the
    whole estate itself (see _release_estate), not only through the registered teardowns.

    FARGATE, never EC2: a MANAGED/EC2 CE with minvCpus > 0 keeps instances alive and is the
    classic Batch cost leak. FARGATE has no minvCpus floor, so an idle CE bills nothing even if
    teardown is interrupted; maxvCpus only caps concurrency, which is what makes it usable as the
    scarce resource a check can set to 1.

    Teardowns are registered network-then-CE-then-queue, so ctx's LIFO order runs
    queue-then-CE-then-network -- which is the only order the references permit.
    """
    net = _create_network(ctx)
    subnets, sg = net["subnets"], net["sg"]
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
                    "subnets": list(subnets),
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
    return jq_name, ce_name, net


def _register_jd(ctx, bat, command, *, exec_role_arn, image=_BUSYBOX, log_group=None,
                 job_role_arn=None, vcpu="0.25", memory="512", retry_strategy=None,
                 timeout=None, environment=None):
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
    output -- which matters twice over here, because this check asserts that certain output is
    ABSENT from the group.
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


def _log_events(ctx, group, stream):
    """Every event in one stream as (timestamp_ms, message), oldest first, paginated to the end.

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
        out.extend((e.get("timestamp"), e.get("message", "")) for e in resp.get("events", []))
        token = resp.get("nextForwardToken")
        if not token or token in seen:
            return out
        seen.add(token)


def _log_messages(ctx, group, stream):
    """Just the messages of one stream, oldest first."""
    return [m for _ts, m in _log_events(ctx, group, stream)]


def _stream_names(ctx, group):
    """Every log stream in the group, paginated. The group belongs to this check alone, so this is
    a complete and account-independent view -- 'exactly these streams' is a property of the query.
    """
    return sorted(
        s["logStreamName"]
        for s in _paginate(
            ctx.client("logs"), "describe_log_streams", "logStreams", logGroupName=group
        )
    )


def _await_log_line(ctx, group, stream, predicate, *, timeout_s=_LOG_TIMEOUT_S,
                    description="log line"):
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


def _await_group_settled(ctx, group, *, timeout_s=_LOG_TIMEOUT_S, stable_reads=3, interval_s=10):
    """Poll the whole group until its (stream -> messages) view is UNCHANGED across N reads.

    A convergence gate, not a sleep. Asserting that a line is ABSENT needs CloudWatch ingestion to
    have caught up, and Logs offers no "complete" signal to poll -- so stability across N reads
    spanning N*interval_s is the observable condition that stands in for one, and a group that
    never settles raises instead of quietly reading a partial view.
    """
    last, stable = None, 0
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        view = {s: _log_messages(ctx, group, s) for s in _stream_names(ctx, group)}
        if last is not None and view == last:
            stable += 1
            if stable >= stable_reads:
                return view
        else:
            stable = 0
        last = view
        time.sleep(interval_s)
    raise AssertionError(
        f"log group {group} never settled within {timeout_s}s; last read was {last!r}"
    )


def _job_stream(job):
    """The awslogs stream a job's container reported, or None if no container ever ran."""
    return (job.get("container") or {}).get("logStreamName")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
