"""batch-maxvcpus-cap-holds-second-job-runnable-then-runs-it."""

from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "batch-maxvcpus-cap-holds-second-job-runnable-then-runs-it"

GROUP = "container-batch-job"

SERVICES = ["batch", "logs"]

_CHECK_TAG = CHECK

_HOLD_S = 150     # how long the first container occupies the whole compute environment
_OBSERVE_S = 75   # how long the second job is watched for a placement it must not get
_MIN_WINDOW_S = 45  # the shortest observation that is worth an assertion


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """With maxvCpus=1, a second 1-vCPU job waits in RUNNABLE (listed by ListJobs, never placed) while the
    first runs, then runs to SUCCEEDED once the first SUCCEEDS: its own log stream holds exactly
    BEGIN=SECOND, DONE=SECOND, and its first line is no earlier than the first container's last."""
    bat = ctx.client("batch")

    log_group = _create_log_group(ctx)
    _n, exec_role = _iam_role(ctx, "exec", _EXEC_STATEMENTS)
    # maxvCpus=1 against a 1-vCPU job definition IS the mechanism under test: it is the only reason
    # the second job cannot be placed.
    queue, ce, net = _fargate_stack(ctx, bat, max_vcpus=1)
    first_id = second_id = None
    try:
        job_def = _register_jd(
            ctx, bat,
            # HOLD and MARKER are bound per job through containerOverrides, so both jobs run the same
            # command and can differ in nothing but the environment they were handed.
            ["sh", "-c", "echo BEGIN=$MARKER; sleep $HOLD; echo DONE=$MARKER"],
            exec_role_arn=exec_role, log_group=log_group, vcpu="1", memory="2048",
        )

        first_id = _submit(
            ctx, bat, queue, job_def,
            containerOverrides={"environment": [
                {"name": "MARKER", "value": "FIRST"},
                {"name": "HOLD", "value": str(_HOLD_S)},
            ]},
        )
        first = _await_job(bat, first_id, {"RUNNING"} | set(_TERMINAL))
        assert first["status"] == "RUNNING", (
            f"the first job must reach RUNNING and occupy the environment before the second is "
            f"submitted, got {first.get('status')!r} statusReason={first.get('statusReason')!r} "
            f"containerReason={(first.get('container') or {}).get('reason')!r}"
        )

        second_id = _submit(
            ctx, bat, queue, job_def,
            containerOverrides={"environment": [
                {"name": "MARKER", "value": "SECOND"},
                {"name": "HOLD", "value": "1"},
            ]},
        )

        # Watch both jobs together: the second job's status is only evidence about capacity while the
        # first one still holds it, so the timeline records both and the loop stops the moment it does
        # not.
        timeline = []
        started = time.monotonic()
        while time.monotonic() - started < _OBSERVE_S:
            j1 = _describe_job(bat, first_id) or {}
            j2 = _describe_job(bat, second_id) or {}
            timeline.append((int(time.monotonic() - started), j1.get("status"), j2.get("status")))
            if j1.get("status") != "RUNNING":
                break
            time.sleep(5)

        window_s = timeline[-1][0] if timeline else 0
        assert timeline and timeline[-1][1] == "RUNNING", (
            f"the first container must stay RUNNING for the whole observation window, otherwise the "
            f"second job's status says nothing about capacity; it left RUNNING after {window_s}s. "
            f"Timeline (t_s, first, second): {timeline!r}"
        )
        assert window_s >= _MIN_WINDOW_S, (
            f"the second job was only observed for {window_s}s, less than the {_MIN_WINDOW_S}s this "
            f"check requires before it will claim anything. Timeline: {timeline!r}"
        )
        seen_second = {s2 for _t, _s1, s2 in timeline}
        assert seen_second <= {"SUBMITTED", "PENDING", "RUNNABLE"}, (
            f"while the environment's only vCPU was held by the first container, the second job must "
            f"not be placed and must not fail; over {window_s}s it was seen in "
            f"{sorted(seen_second)!r}. Timeline: {timeline!r}"
        )
        assert "RUNNABLE" in seen_second, (
            f"a job that cannot be placed for want of capacity must WAIT in RUNNABLE, not stall in "
            f"SUBMITTED/PENDING; over {window_s}s it was only seen in {sorted(seen_second)!r}. "
            f"Timeline: {timeline!r}"
        )
        # The same fact from the queue's own listing, paginated; membership is asserted, never a count.
        runnable_now = {
            js["jobId"]
            for js in _paginate(bat, "list_jobs", "jobSummaryList",
                                jobQueue=queue, jobStatus="RUNNABLE")
        }
        assert second_id in runnable_now, (
            f"the queue's RUNNABLE listing must include the job it is holding back; ListJobs "
            f"(jobStatus=RUNNABLE) on {queue} returned {sorted(runnable_now)!r} without {second_id!r}"
        )

        first = _await_job(bat, first_id, set(_TERMINAL))
        assert first["status"] == "SUCCEEDED", (
            f"the first job must run to SUCCEEDED, got {first.get('status')!r} "
            f"statusReason={first.get('statusReason')!r} "
            f"containerReason={(first.get('container') or {}).get('reason')!r}"
        )
        assert (first.get("container") or {}).get("exitCode") == 0, (
            f"a container whose command is echo/sleep/echo must exit 0, got "
            f"{(first.get('container') or {}).get('exitCode')!r}"
        )
        first_stream = _job_stream(first)
        assert first_stream and first_stream.startswith("batch/"), (
            f"a SUCCEEDED job must report the awslogs stream its container wrote, named from the job "
            f"definition's awslogs-stream-prefix, got {first_stream!r}"
        )
        first_events = _await_log_line(
            ctx, log_group, first_stream, lambda m: m.strip() == "DONE=FIRST",
            description="the first container's DONE=FIRST line",
        )

        # The release is the second half of the claim: nothing cancelled or re-submitted the held job,
        # and it runs on its own once the vCPU is free.
        second = _await_job(bat, second_id, set(_TERMINAL))
        assert second["status"] == "SUCCEEDED", (
            f"the job that waited in RUNNABLE must be placed and run to SUCCEEDED once the first "
            f"container released the environment's vCPU, got {second.get('status')!r} "
            f"statusReason={second.get('statusReason')!r} "
            f"containerReason={(second.get('container') or {}).get('reason')!r}"
        )
        second_stream = _job_stream(second)
        assert second_stream and second_stream != first_stream, (
            f"the released job's container must write its own awslogs stream, got {second_stream!r} "
            f"against the first job's {first_stream!r}"
        )
        second_events = _await_log_line(
            ctx, log_group, second_stream, lambda m: m.strip() == "DONE=SECOND",
            description="the released container's DONE=SECOND line",
        )
        assert [m.strip() for m in second_events] == ["BEGIN=SECOND", "DONE=SECOND"], (
            f"the released container ran `echo BEGIN; sleep 1; echo DONE` with MARKER=SECOND, so its "
            f"stream must hold exactly those two lines and nothing from the other job, got "
            f"{second_events!r}"
        )

        # Ordering, taken from the containers' OWN output rather than from a status field: the cap
        # serialised the two executions, so the second container's first line cannot predate the first
        # container's last one.
        first_done_ts = _first_event_ts(ctx, log_group, first_stream, "DONE=FIRST")
        second_begin_ts = _first_event_ts(ctx, log_group, second_stream, "BEGIN=SECOND")
        assert second_begin_ts >= first_done_ts, (
            f"a one-vCPU environment cannot have run both containers at once: the second container's "
            f"BEGIN=SECOND was logged at {second_begin_ts} (ms), BEFORE the first container's "
            f"DONE=FIRST at {first_done_ts} (ms). First stream {first_stream!r} = {first_events!r}"
        )
    finally:
        # The jobs, the queue, the compute environment and the NETWORK are released here, inside
        # the check's own deadline, as the ENI release makes the sequence take minutes. In a
        # `finally` so the failure path pays the same teardown as the success path. See
        # _release_estate.
        _release_estate(ctx, bat, queue, ce, net, jobs=[j for j in (first_id, second_id) if j])


def _first_event_ts(ctx, group, stream, message):
    """The timestamp (ms) of the first event in `stream` whose message is exactly `message`."""
    for ts, msg in _log_events(ctx, group, stream):
        if msg.strip() == message:
            assert isinstance(ts, int), f"log event {msg!r} carried no integer timestamp: {ts!r}"
            return ts
    raise AssertionError(
        f"no event with message {message!r} in {group}/{stream}; the stream held "
        f"{_log_messages(ctx, group, stream)!r}"
    )


_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = {
    # Every create passes these tags inline: a create that is tagged in a second call is untagged
    # for the window in between, which is exactly when a run dies and leaves the thing behind.
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
# runs in one account each get their own VPC carrying these same ranges without colliding; the
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
_NET_RETRY = {"attempts": 12, "interval_s": 5}

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


def _gone(exc):
    """True when a teardown call's ClientError is the resource's documented not-found answer."""
    err = exc.response.get("Error", {})
    code = err.get("Code", "")
    return (
        code in ("NoSuchEntity", "ResourceNotFoundException", "Gateway.NotAttached")
        or code.endswith(".NotFound")
        or (code == "ClientException" and "does not exist" in err.get("Message", ""))
    )


def _swallow(fn):
    """Run a teardown call fn(); only the resource's not-found answer counts as already gone."""
    try:
        fn()
    except ClientError as exc:
        if not _gone(exc):
            raise


def _retry_refused(call):
    """Run a Batch delete, retrying ClientException (a draining queue, a referenced CE) every 2 s.

    Not-found is done; another error, or a refusal past _TEARDOWN_TIMEOUT_S, raises.
    """
    deadline = time.monotonic() + _TEARDOWN_TIMEOUT_S
    while True:
        try:
            return call()
        except ClientError as exc:
            if _gone(exc):
                return None
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

    Raises when fn() succeeds, so accepting input AWS rejects fails as itself and not as an
    error-code mismatch.
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

    Other resources in the account can push the resource this check asserts membership in off
    page one.
    """
    out = []
    try:
        pages = client.get_paginator(op).paginate(**kwargs)
    except Exception:  # noqa: BLE001 - no paginator modelled for this op
        return getattr(client, op)(**kwargs).get(key, [])
    for page in pages:
        out.extend(page.get(key, []))
    return out


def _retry_delete(fn, label, *, attempts=10, interval_s=10):
    """Call an EC2 delete, retrying DependencyViolation every 2 s for attempts * interval_s seconds.

    A reference released asynchronously refuses the delete for a while; not-found is done, the rest raises.
    """
    deadline = time.monotonic() + attempts * interval_s
    while True:
        try:
            fn()
            return True
        except ClientError as exc:
            if _gone(exc):
                return True
            code = exc.response.get("Error", {}).get("Code")
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise RuntimeError(f"could not delete {label}: {exc}") from exc
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
    account: a FARGATE compute environment cannot exist without subnets, and the check must not
    depend on a default VPC the account may not have.

    Public subnets with an internet-gateway route, never a NAT gateway: the task needs egress to
    pull from public.ecr.aws and to open its awslogs stream, assignPublicIp=ENABLED gives it that
    through the IGW, and an IGW bills nothing and deletes in seconds where a NAT gateway does
    neither. The route goes in the VPC's own main route table, which CreateVpc made and DeleteVpc
    takes with it, so teardown has one less resource to converge on.

    Every EC2 resource is tagged in the SAME call that creates it, via TagSpecifications: a create
    that is tagged in a second call is untagged for exactly the window in which a run dies.
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

    ECS deletes a Fargate task's ENI some minutes AFTER the job is terminal, and DeleteSubnet raises
    DependencyViolation until it has. So the check body calls this on both its success and its
    failure path, inside its own deadline; this stays registered as a cleanup too, and returns
    immediately when the body already did the work, because a deleted VPC never reports the state
    the ENI wait polls for.

    Order is forced by the references: ENIs, then the security group and subnets that hold them,
    then the internet gateway, then the VPC. A residue VPC raises with its id.
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
                         f"security group {net['sg']}", **_NET_RETRY):
            net["sg"] = None
    for subnet_id in list(net.get("subnets") or []):
        if _retry_delete(lambda s=subnet_id: ec2.delete_subnet(SubnetId=s),
                         f"subnet {subnet_id}", **_NET_RETRY):
            net["subnets"].remove(subnet_id)
    if net.get("igw"):
        _retry_delete(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=net["igw"], VpcId=vpc_id),
            f"internet gateway {net['igw']} detach from {vpc_id}", **_NET_RETRY,
        )
        if _retry_delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=net["igw"]),
                         f"internet gateway {net['igw']}", **_NET_RETRY):
            net["igw"] = None
    _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id), f"vpc {vpc_id}", **_NET_RETRY)
    if _safe(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])) is None:
        net["vpc"] = None
    else:
        raise RuntimeError(f"vpc {vpc_id} still present after DeleteVpc")


def _release_estate(ctx, bat, queue, ce_name, net, jobs):
    """Release the whole slow estate INSIDE the check body, on BOTH the success and failure paths.

    DeleteComputeEnvironment is rejected while the CE is ENABLED or while a queue still references
    it, DeleteSubnet is rejected until ECS has released the task ENIs minutes after the job went
    terminal, and every one of those deletes is asynchronous, so the sequence takes minutes and runs
    inside the check's own deadline. The registered teardowns stay as a second pass (every step is
    idempotent, so running twice is free). Called from a `finally`: every step runs, and a failure
    raises after the last one, carrying the in-flight error so a teardown failure never hides the
    check's verdict.

    Order is forced by the references: jobs must be terminal before the queue will delete, the
    queue must be gone before the compute environment will, and the compute environment must be
    gone before its subnets and security group will.
    """
    left = []
    for label, step in (
        ("jobs", lambda: _teardown_jobs(bat, jobs)),
        ("job queue", lambda: _teardown_jq(bat, queue)),
        ("compute environment", lambda: _teardown_ce(bat, ce_name)),
        ("network", lambda: _teardown_network(ctx, net)),
    ):
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - collected, raised after the last step
            left.append(f"{label}: {exc!r}")
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

    A job that never went terminal raises after every job was waited on.
    """
    stuck = []
    ids = list(job_ids)
    for jid in list(ids):
        for child in (_safe(lambda jid=jid: _array_children(bat, jid)) or {}):
            if child not in ids:
                ids.append(child)
    for jid in ids:
        _swallow(lambda jid=jid: bat.terminate_job(jobId=jid, reason=_PREFIX + "cleanup"))
    for jid in ids:
        try:
            _poll_until(
                lambda jid=jid: _describe_job(bat, jid),
                lambda j: j is None or j.get("status") in _TERMINAL,
                timeout_s=_TEARDOWN_TIMEOUT_S,
                interval_s=5,
                description=f"job {jid} terminal before queue teardown",
            )
        except Exception as exc:  # noqa: BLE001
            message = (f"batch job {jid} never reached a terminal state; the queue and "
                       f"compute environment behind it may not have been deletable")
            stuck.append((message, exc))
    if stuck:
        raise RuntimeError("; ".join(m for m, _ in stuck)) from stuck[0][1]


def _teardown_jq(bat, name):
    """DISABLE -> poll settled -> DeleteJobQueue (retried) -> poll gone.

    DeleteJobQueue raises ClientException for a queue that is still draining and accepts the very
    same call seconds later, so the delete is retried.

    Returns at once if the queue is already gone: on the success path the body has already released
    it (see _release_estate), and a deleted queue never reports the status the disable step polls
    for.

    A refusal other than draining, or a queue still present at the end, raises.
    """
    if _safe(lambda: _describe_jq(bat, name)) is None:
        return
    _swallow(lambda: bat.update_job_queue(jobQueue=name, state="DISABLED"))
    _await_jq(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_TIMEOUT_S)
    _retry_refused(lambda: bat.delete_job_queue(jobQueue=name))
    try:
        _poll_until(
            lambda: _describe_jq(bat, name),
            lambda jq: jq is None,
            timeout_s=_TEARDOWN_TIMEOUT_S,
            interval_s=5,
            description=f"job queue {name} gone",
        )
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"batch job queue {name} still present after DeleteJobQueue") from exc


def _teardown_ce(bat, name):
    """DISABLE -> poll settled -> DeleteComputeEnvironment (retried) -> poll gone.

    DeleteComputeEnvironment requires the environment to be DISABLED first and does not converge
    otherwise: retrying the delete against an ENABLED environment fails identically forever. The
    delete is then asynchronous, so both halves are polled. An environment still present at the
    end raises.
    """
    if _safe(lambda: _describe_ce(bat, name)) is None:
        return  # already released by the body; see the note in _teardown_jq
    _swallow(lambda: bat.update_compute_environment(computeEnvironment=name, state="DISABLED"))
    _await_ce(bat, name, {"VALID", "INVALID"}, timeout_s=_TEARDOWN_TIMEOUT_S)
    _retry_refused(lambda: bat.delete_compute_environment(computeEnvironment=name))
    try:
        _poll_until(
            lambda: _describe_ce(bat, name),
            lambda ce: ce is None,
            timeout_s=_TEARDOWN_TIMEOUT_S,
            interval_s=5,
            description=f"compute environment {name} gone",
        )
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"batch compute environment {name} still present after "
                           f"DeleteComputeEnvironment") from exc


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
    never settles raises rather than quietly reading a partial view.
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
