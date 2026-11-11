"""svcreplace-stopped-standalone-task-is-never-relaunched-while-a-service-managed-one-is-replaced."""

from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "svcreplace-stopped-standalone-task-is-never-relaunched-while-a-service-managed-one-is-replaced"
)

GROUP = "service-steady-state"

SERVICES = ["ecs", "logs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After one StopTask each, a desiredCount-1 service's task is replaced by a new RUNNING task
    while an identical standalone RunTask task is never relaunched; both containers log their
    boot and SIGTERM farewell lines and exit with the handler's code 42.
    """
    ecs = ctx.client("ecs")
    td = _Teardown(ctx)
    ok = False
    try:
        subnets, sg = _fargate_network(ctx, td)
        log_group = _create_log_group(ctx, td)
        _n, exec_role = _iam_role(ctx, td, "exec", _EXEC_STATEMENTS)
        _ensure_ecs_slr(ctx)
        cluster = ctx.unique_name(_PREFIX + "cluster-")
        ecs.create_cluster(clusterName=cluster, tags=_ecs_tags())
        td.add(f"ecs cluster {cluster}", lambda: _drop_cluster(ecs, cluster))

        marker = ctx.unique_name("svcreplace-")
        task_def = _register_td(ctx, ecs, td, log_group, exec_role, marker)
        net = {"awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg],
                                       "assignPublicIp": "ENABLED"}}

        # ---- the two tasks: identical but for service membership ----
        service = _create_service(ctx, ecs, td, cluster, task_def, net)
        first = _one_running_service_task(ctx, ecs, cluster, service, _TASK_RUNNING_TIMEOUT_S)
        first_arn = first["taskArn"]

        solo_token = ctx.unique_name("sim2real-solo-")
        solo_arn = _run_standalone(ctx, ecs, td, cluster, task_def, net, solo_token)
        solo = _poll_until(
            lambda: ecs.describe_tasks(cluster=cluster, tasks=[solo_arn])["tasks"][0],
            lambda t: t["lastStatus"] == "RUNNING",
            timeout_s=_TASK_RUNNING_TIMEOUT_S, interval_s=1, ctx=ctx,
            description=f"standalone task {solo_arn} reaches RUNNING")
        assert solo["taskDefinitionArn"] == task_def, (
            f"the standalone task must run the SAME task definition as the service's, so service "
            f"membership is the only difference; got {solo['taskDefinitionArn']!r} vs {task_def!r}")
        assert not solo.get("group", "").startswith("service:"), (
            f"the standalone task must not belong to any service; group={solo.get('group')!r}")
        assert first.get("group") == f"service:{service}", (
            f"the service's task must be attributed to the service; group={first.get('group')!r}")

        # Both containers really ran: each printed its boot line into its OWN log stream.
        first_log = _stream_lines(ctx, log_group, first_arn, f"BOOT-{marker}")
        solo_log = _stream_lines(ctx, log_group, solo_arn, f"BOOT-{marker}")
        assert _stream_name(first_arn) != _stream_name(solo_arn), (
            f"the two tasks must write to two different log streams; both were "
            f"{_stream_name(first_arn)!r}")

        # ---- one StopTask each, in the same moment ----
        reason = "sim2real-svcreplace-stop"
        started = time.monotonic()
        ecs.stop_task(cluster=cluster, task=first_arn, reason=reason)
        ecs.stop_task(cluster=cluster, task=solo_arn, reason=reason)

        # ---- the service replaces its task with a NEW running container ----
        replacement = _poll_until(
            lambda: _service_tasks(ecs, cluster, service, "RUNNING"),
            lambda arns: len(arns) == 1 and arns[0] != first_arn,
            timeout_s=_REPLACEMENT_TIMEOUT_S, interval_s=1, ctx=ctx,
            description=(f"the service replaces {first_arn} with exactly one different RUNNING "
                         f"task"))
        replaced_after_s = time.monotonic() - started
        second_arn = replacement[0]
        second = _poll_until(
            lambda: ecs.describe_tasks(cluster=cluster, tasks=[second_arn])["tasks"][0],
            lambda t: t["lastStatus"] == "RUNNING",
            timeout_s=_TASK_RUNNING_TIMEOUT_S, interval_s=1, ctx=ctx,
            description=f"the replacement task {second_arn} reaches RUNNING")
        assert second["startedBy"] == first["startedBy"], (
            f"the replacement must have been launched by the same service scheduler that launched "
            f"the original, got startedBy={second['startedBy']!r} vs {first['startedBy']!r}")
        second_log = _stream_lines(ctx, log_group, second_arn, f"BOOT-{marker}")
        assert any(line == f"BOOT-{marker}" for line in second_log), (
            f"the replacement task's OWN container must have started and printed its boot line -- "
            f"a new task arn with no container behind it is the divergence this asserts against; "
            f"stream={_stream_name(second_arn)!r} log={second_log!r}")

        # ---- the stop was a real SIGTERM: each container chose its own exit code ----
        for label, arn, log in (("service", first_arn, first_log), ("standalone", solo_arn,
                                                                    solo_log)):
            stopped = _poll_until(
                lambda a=arn: ecs.describe_tasks(cluster=cluster, tasks=[a])["tasks"][0],
                lambda t: t["lastStatus"] == "STOPPED",
                timeout_s=_STOPPED_TIMEOUT_S, interval_s=1, ctx=ctx,
                description=f"the {label} task {arn} reaches STOPPED")
            assert stopped["stopCode"] == "UserInitiated", (
                f"the {label} task was stopped by this check's StopTask, so ECS must attribute it "
                f"to the caller; got stopCode={stopped['stopCode']!r} "
                f"stoppedReason={stopped.get('stoppedReason')!r}")
            assert stopped["stoppedReason"] == reason, (
                f"the {label} task must carry back the reason this check passed to StopTask, got "
                f"{stopped['stoppedReason']!r}")
            assert stopped["containers"][0]["exitCode"] == _TRAP_EXIT_CODE, (
                f"the {label} container traps SIGTERM and exits {_TRAP_EXIT_CODE}, so anything "
                f"else means the platform never delivered the signal to the container's own "
                f"process; got {stopped['containers'][0]!r}")
            farewell = _stream_lines(ctx, log_group, arn, f"BYE-{marker}")
            assert any(line == f"BYE-{marker}" for line in farewell), (
                f"the {label} container's SIGTERM handler must have run and printed its farewell "
                f"line; log={farewell!r} (boot-time log was {log!r})")

        # ---- and the standalone task is NEVER relaunched ----
        # The contrast: the scheduler has already replaced the service's task, stopped at the same
        # moment, and both stopped tasks are STOPPED; a fixed window then samples the namespace.
        deadline = time.monotonic() + _ABSENCE_WINDOW_S
        while time.monotonic() < deadline:
            live = _tasks_started_by(ecs, cluster, solo_token, "RUNNING")
            assert live == [], (
                f"a stopped standalone task must never be relaunched: the scheduler replaced the "
                f"SERVICE's task in {replaced_after_s:.0f}s, and after that replacement the "
                f"startedBy={solo_token!r} namespace -- which only this check can occupy -- holds "
                f"RUNNING tasks {live!r}")
            time.sleep(1)
        ever = sorted(_tasks_started_by(ecs, cluster, solo_token, "RUNNING")
                      + _tasks_started_by(ecs, cluster, solo_token, "STOPPED"))
        assert ever == [solo_arn], (
            f"exactly the ONE standalone task this check launched may ever have existed under "
            f"startedBy={solo_token!r}; got {ever!r}")

        # ---- the positive control's invariant: the service is back at steady state ----
        svc = ecs.describe_services(cluster=cluster, services=[service])["services"][0]
        assert svc["desiredCount"] == 1, (
            f"nothing in this check changed desiredCount, so the replacement must have been the "
            f"scheduler maintaining it rather than a scale event; got {svc['desiredCount']!r}")
        assert svc["taskDefinition"] == task_def, (
            f"the service must still be running the one revision this check registered; got "
            f"{svc['taskDefinition']!r}")
        running = _poll_until(
            lambda: ecs.describe_services(cluster=cluster,
                                          services=[service])["services"][0]["runningCount"],
            lambda n: n == 1,
            timeout_s=_STOPPED_TIMEOUT_S, interval_s=1, ctx=ctx,
            description="the service is back at runningCount 1")
        assert running == 1, running
        ok = True
    finally:
        # Verified teardown INLINE, under this check's own budget: a Fargate teardown (service
        # drain, then the ENI lag that blocks the subnet delete) outlasts the cleanup budget.
        leaks = td.run()
        if ok:
            assert not leaks, f"verified teardown did not remove everything: {leaks!r}"
        elif leaks:
            print(f"teardown after a failing body: {leaks!r}", file=sys.stderr)


_PREFIX = "sim2real-svcreplace-"
_MANAGED_TAGS = {
    "sim2real:managed": "true",
    "sim2real:prefix": "sim2real-svcreplace",
    "sim2real": "ecs-service-replacement",
}
_NET_TAGS = [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]

# The exit code the container's own SIGTERM handler chooses. Arbitrary, and that is the point: it
# is not a signal-derived 137, so it can only appear if the platform ran the handler.
_TRAP_EXIT_CODE = 42

# Bounded deadlines, each with its reason.
_TASK_RUNNING_TIMEOUT_S = 480    # Fargate placement + public-ECR pull + start
_REPLACEMENT_TIMEOUT_S = 480     # the scheduler notices, places and starts a replacement
_STOPPED_TIMEOUT_S = 300         # SIGTERM -> handler -> STOPPED, plus the stop's own bookkeeping
_LOG_TIMEOUT_S = 300             # awslogs stream creation, then event delivery
_SERVICE_DRAIN_TIMEOUT_S = 420   # desiredCount 0 -> runningCount 0 -> INACTIVE
_ENI_TIMEOUT_S = 600             # Fargate ENIs linger after a task stops and block subnet deletion
_TEARDOWN_TIMEOUT_S = 300        # deleted -> polled actually gone, per resource
_ABSENCE_WINDOW_S = 5.0          # fixed sampling window after the service's replacement

# busybox, pinned BY DIGEST rather than the moving `latest`, so the container's behaviour under
# SIGTERM is a property of one image and not of whatever was published today.
_BUSYBOX = ("public.ecr.aws/docker/library/busybox"
            "@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662")

# PID 1 in the container: print a boot line, then sit in a loop that the SIGTERM handler can
# interrupt within a second. The handler prints a farewell line and picks its OWN exit code.
_COMMAND = ["sh", "-c",
            'trap \'echo "BYE-$MARKER"; exit 42\' TERM; echo "BOOT-$MARKER"; '
            'while true; do sleep 1; done']

_STREAM_PREFIX = "svcreplace"
_CONTAINER = "app"

_ECS_TASKS_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
_EXEC_STATEMENTS = [
    {"Effect": "Allow",
     "Action": ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage",
                "logs:CreateLogStream", "logs:PutLogEvents"],
     "Resource": "*"}
]


class _Teardown:
    """Every undo, registered TWICE on purpose: inline (run in the body's `finally`, in reverse
    creation order) and on `ctx.on_cleanup` as the failure-path net, because the cleanup chain is
    time-bounded and a Fargate teardown would be cut mid-way."""

    def __init__(self, ctx):
        self._ctx = ctx
        self._steps = []

    def add(self, label, fn):
        self._steps.append((label, fn))
        self._ctx.on_cleanup(fn)

    def run(self):
        leaks = []
        for label, fn in reversed(self._steps):
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - collected, not swallowed
                leaks.append(f"{label}: {exc!r}")
        return leaks


def _ecs_tags():
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _kv_tags():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown step
        pass


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition",
                ctx=None):
    """Poll probe() until predicate(result); return the final result. Raises on a deadline miss."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
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


def _paginate(client, op, key, **kwargs):
    """Every page of a List*, flattened."""
    out = []
    try:
        pages = client.get_paginator(op).paginate(**kwargs)
    except Exception:  # noqa: BLE001 - no paginator modelled for this op
        return getattr(client, op)(**kwargs).get(key, [])
    for page in pages:
        out.extend(page.get(key, []))
    return out


def _fargate_network(ctx, td):
    """(subnets, sg) for Fargate (awsvpc) tasks, from a DEDICATED VPC with a public subnet + IGW.

    A default VPC may be missing or carry a dangling DHCP option set that fails every Fargate task
    with TaskFailedToStart; no NAT or EIP, so nothing billable. The AZ is derived, not named.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.197.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}])["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    zones = [z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]]
    assert zones, f"no availability zone in {ctx.region} reports state=available"
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.197.0.0/25", AvailabilityZone=zones[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}])["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _NET_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = next(sg["GroupId"] for sg in ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
        if sg["GroupName"] == "default")

    def _drop():
        _poll_until(
            lambda: ec2.describe_network_interfaces(
                Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]).get(
                    "NetworkInterfaces", []),
            lambda enis: not enis,
            timeout_s=_ENI_TIMEOUT_S, interval_s=2,
            description=f"every ENI in {subnet_id} detached before subnet deletion")
        deadline = time.monotonic() + 100.0
        while time.monotonic() < deadline:
            if _safe(lambda: ec2.delete_subnet(SubnetId=subnet_id)) is not None:
                break
            if _safe(lambda: ec2.describe_subnets(SubnetIds=[subnet_id])) is None:
                break
            time.sleep(2)
        _swallow(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
        _swallow(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
        deadline = time.monotonic() + 100.0
        while time.monotonic() < deadline:
            if _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)) is not None:
                break
            if _safe(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])) is None:
                break
            time.sleep(2)
        left = _safe(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]))
        if left and left.get("Vpcs"):
            raise AssertionError(f"VPC {vpc_id} still present after DeleteVpc")

    td.add(f"vpc {vpc_id}", _drop)
    return [subnet_id], sg_id


def _ensure_ecs_slr(ctx):
    """Ensure AWSServiceRoleForECS exists: CreateService creates it implicitly but RunTask does not.

    No teardown: it is account-level, free, and shared by every ECS workload.
    """
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        if code not in ("InvalidInput", "InvalidInputException") or message != (
            "Service role name AWSServiceRoleForECS has been taken in this account, please try a different suffix."
        ):
            raise AssertionError(f"cannot create the ECS service-linked role: {exc}") from exc


_SLR_LAG = "Unable to assume the service linked role"


def _launch_past_slr_lag(call, *, timeout_s=120.0, interval_s=2.0):
    """Run an ECS launch call, retrying (bounded) only while ECS cannot yet assume a just-created
    service-linked role; any other error or failure is returned or raised unchanged."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = call()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "InvalidParameterException" or _SLR_LAG not in str(err.get("Message", "")):
                raise
            last = exc
        else:
            lag = [f for f in resp.get("failures") or [] if _SLR_LAG in str(f.get("reason", ""))]
            if not lag:
                return resp
            last = lag
        if time.monotonic() >= deadline:
            raise AssertionError(f"ECS could not assume its service-linked role within {timeout_s}s: {last!r}")
        time.sleep(interval_s)


def _iam_role(ctx, td, kind, statements):
    """A fresh role trusting ecs-tasks with ONE inline policy; returns (name, arn). IAM exposes no
    signal that a role is assumable, so the policy is polled back and a short settle follows."""
    iam = ctx.client("iam")
    name = ctx.unique_name(_PREFIX + kind + "-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST), Path="/sim2real/",
        Description="SimParity behavioral: ECS service replacement " + kind,
        Tags=_kv_tags())["Role"]["Arn"]

    def _drop():
        _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        _swallow(lambda: iam.delete_role(RoleName=name))
        if _safe(lambda: iam.get_role(RoleName=name)) is not None:
            raise AssertionError(f"IAM role {name} still exists after DeleteRole")

    td.add(f"iam role {name}", _drop)
    iam.put_role_policy(RoleName=name, PolicyName="inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                   "Statement": statements}))
    _poll_until(lambda: _safe(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
                lambda r: r is not None, timeout_s=60, interval_s=2,
                description=f"role {name} inline policy readable")
    # fixed-wait: IAM trust propagation exposes no condition to poll; the settle is not graded
    time.sleep(10)
    return name, arn


def _create_log_group(ctx, td):
    """A log group this check owns outright, so teardown is one call that takes the streams too."""
    logs = ctx.client("logs")
    name = ctx.unique_name(_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))

    def _drop():
        _swallow(lambda: logs.delete_log_group(logGroupName=name))
        left = _safe(lambda: logs.describe_log_groups(logGroupNamePrefix=name))
        if left and left.get("logGroups"):
            raise AssertionError(f"log group {name} still present after DeleteLogGroup")

    td.add(f"log group {name}", _drop)
    return name


def _register_td(ctx, ecs, td, log_group, exec_role, marker):
    """The ONE task definition both tasks run, so service membership is the only difference."""
    family = ctx.unique_name(_PREFIX + "td-")
    arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role,
        containerDefinitions=[{
            "name": _CONTAINER,
            "image": _BUSYBOX,
            "essential": True,
            "command": _COMMAND,
            "environment": [{"name": "MARKER", "value": marker}],
            # Pinned rather than left to the platform default, so the SIGTERM window is a property
            # of this task definition: the handler needs ~1 s and gets 30 before SIGKILL.
            "stopTimeout": 30,
            "logConfiguration": {"logDriver": "awslogs",
                                 "options": {"awslogs-group": log_group,
                                             "awslogs-region": ctx.region,
                                             "awslogs-stream-prefix": _STREAM_PREFIX}},
        }],
        tags=_ecs_tags())["taskDefinition"]["taskDefinitionArn"]
    td.add(f"ecs task definition {arn}",
           lambda: (_swallow(lambda: ecs.deregister_task_definition(taskDefinition=arn)),
                    _swallow(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))))
    return arn


def _create_service(ctx, ecs, td, cluster, task_def, net):
    """A desiredCount 1 Fargate service with no load balancer, so the only thing that can drive a
    replacement is the scheduler maintaining its own count."""
    name = ctx.unique_name(_PREFIX + "svc-")
    _launch_past_slr_lag(lambda: ecs.create_service(
        cluster=cluster, serviceName=name, taskDefinition=task_def, desiredCount=1,
        launchType="FARGATE", networkConfiguration=net,
        deploymentConfiguration={"minimumHealthyPercent": 0, "maximumPercent": 200},
        tags=_ecs_tags()))

    def _drop():
        _swallow(lambda: ecs.update_service(cluster=cluster, service=name, desiredCount=0))
        _poll_until(
            lambda: (_safe(lambda: ecs.describe_services(
                cluster=cluster, services=[name])["services"][0]["runningCount"])),
            lambda n: n in (0, None),
            timeout_s=_SERVICE_DRAIN_TIMEOUT_S, interval_s=2,
            description=f"service {name} drains to runningCount 0")
        _swallow(lambda: ecs.delete_service(cluster=cluster, service=name, force=True))
        _poll_until(
            lambda: (_safe(lambda: ecs.describe_services(
                cluster=cluster, services=[name])["services"][0]["status"])),
            lambda s: s in ("INACTIVE", None),
            timeout_s=_TEARDOWN_TIMEOUT_S, interval_s=2,
            description=f"service {name} reaches INACTIVE")

    td.add(f"ecs service {name}", _drop)
    return name


def _run_standalone(ctx, ecs, td, cluster, task_def, net, token):
    """One RunTask task, stamped with a startedBy token only this check uses, so 'nothing was
    relaunched' is a property of the query rather than of other workloads in the account."""
    resp = _launch_past_slr_lag(lambda: ecs.run_task(
        cluster=cluster, taskDefinition=task_def, launchType="FARGATE", count=1,
        networkConfiguration=net, startedBy=token, tags=_ecs_tags()))
    assert not resp.get("failures"), (
        f"RunTask for the standalone task reported failures: {resp.get('failures')!r}")
    arn = resp["tasks"][0]["taskArn"]
    td.add(f"ecs task {arn}",
           lambda: _swallow(lambda: ecs.stop_task(cluster=cluster, task=arn,
                                                  reason="behavioral-cleanup")))
    return arn


def _service_tasks(ecs, cluster, service, desired_status):
    return sorted(_paginate(ecs, "list_tasks", "taskArns", cluster=cluster, serviceName=service,
                            desiredStatus=desired_status))


def _tasks_started_by(ecs, cluster, token, desired_status):
    return sorted(_paginate(ecs, "list_tasks", "taskArns", cluster=cluster, startedBy=token,
                            desiredStatus=desired_status))


def _one_running_service_task(ctx, ecs, cluster, service, timeout_s):
    arns = _poll_until(
        lambda: _service_tasks(ecs, cluster, service, "RUNNING"),
        lambda a: len(a) == 1,
        timeout_s=timeout_s, interval_s=1, ctx=ctx,
        description=f"service {service} has exactly one RUNNING task")
    return _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster, tasks=arns)["tasks"][0],
        lambda t: t["lastStatus"] == "RUNNING",
        timeout_s=timeout_s, interval_s=1, ctx=ctx,
        description=f"service task {arns[0]} reports lastStatus RUNNING")


def _stream_name(task_arn):
    return f"{_STREAM_PREFIX}/{_CONTAINER}/{task_arn.rsplit('/', 1)[-1]}"


def _stream_lines(ctx, group, task_arn, sentinel):
    """Every line this task's container wrote, waited on until `sentinel` has been DELIVERED.

    Two waits, not one: the awslogs driver opens the stream when the task is INITIALISED,
    measurably before the container writes anything, so the stream existing is no evidence that
    output arrived -- only its events are.
    """
    logs = ctx.client("logs")
    stream = _stream_name(task_arn)

    def _read():
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

    return _poll_until(_read, lambda msgs: any(sentinel in m for m in msgs),
                       timeout_s=_LOG_TIMEOUT_S, interval_s=1, ctx=ctx,
                       description=f"{sentinel!r} delivered to {group}/{stream}")


def _drop_cluster(ecs, cluster):
    _swallow(lambda: ecs.delete_cluster(cluster=cluster))
    left = _safe(lambda: ecs.describe_clusters(clusters=[cluster]))
    for c in (left or {}).get("clusters", []):
        if c.get("status") not in ("INACTIVE", None):
            raise AssertionError(f"ECS cluster {cluster} still {c.get('status')!r} after "
                                 f"DeleteCluster")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
