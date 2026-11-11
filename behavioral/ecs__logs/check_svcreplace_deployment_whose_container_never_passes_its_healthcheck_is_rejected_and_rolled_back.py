"""svcreplace-deployment-whose-container-never-passes-its-healthcheck-is-rejected-and-rolled-back."""

from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "svcreplace-deployment-whose-container-never-passes-its-healthcheck-is-rejected-and-rolled-back"
)

GROUP = "service-deployment-rollback"

SERVICES = ["ecs", "logs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A revision whose container runs but never passes its health probe is retried, fails, and
    is rolled back; the surviving container's own stdout proves revision 1 serves, none of 2.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-circuit-breaker.html
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
        family = ctx.unique_name(_PREFIX + "td-")
        good = _register_td(ctx, ecs, td, family, log_group, exec_role, marker, rev="1", health="0")
        bad = _register_td(ctx, ecs, td, family, log_group, exec_role, marker, rev="2", health="1")
        assert good != bad, f"the two revisions must be distinct task definitions, both are {good!r}"

        net = {"awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg],
                                       "assignPublicIp": "ENABLED"}}
        service = _create_service(ctx, ecs, td, cluster, good, net)
        first = _poll_until(
            lambda: _one_task(ecs, cluster, service),
            lambda t: t is not None and t["lastStatus"] == "RUNNING"
            and t.get("healthStatus") == "HEALTHY",
            timeout_s=_CONVERGE_TIMEOUT_S, interval_s=1, ctx=ctx,
            description=("the revision-1 task reaches RUNNING and its container health probe "
                         "reports HEALTHY"))
        first_arn = first["taskArn"]
        assert first["taskDefinitionArn"] == good, first["taskDefinitionArn"]
        good_deploy = _poll_until(
            lambda: _deployment_for(ecs, cluster, service, good),
            lambda d: d is not None and d.get("rolloutState") == "COMPLETED",
            timeout_s=_CONVERGE_TIMEOUT_S, interval_s=1, ctx=ctx,
            description="the revision-1 deployment reaches rolloutState COMPLETED")
        assert good_deploy["status"] == "PRIMARY", (
            f"the converged deployment must be the service's PRIMARY one; got {good_deploy!r}")
        first_log = _stream_lines(ctx, log_group, first_arn, f"REV1-{marker}")
        assert any(line == f"REV1-{marker}" for line in first_log), (
            f"the revision-1 container must have printed its own revision line; "
            f"stream={_stream_name(first_arn)!r} log={first_log!r}")

        # HEALTH=1 makes the probe exit non-zero; it is the only difference from revision 1.
        ecs.update_service(cluster=cluster, service=service, taskDefinition=bad)
        failed, attempts = _await_rollout_failure(ecs, cluster, service, bad,
                                                  _budget_s(ctx, _DEPLOY_FAIL_TIMEOUT_S), ctx)
        assert len(attempts) >= 2, (
            f"the scheduler must RETRY a failing revision before giving up on it -- a single "
            f"attempt would mean the deployment was refused at admission rather than failing on "
            f"the containers' behaviour; revision-2 tasks observed: {attempts!r}")
        assert failed.get("failedTasks", 0) >= 1, (
            f"the failed deployment must account for at least one failed task; got {failed!r}")
        started = [a for a, r in attempts.items() if "RUNNING" in r["statuses"]]
        assert started, (
            f"at least one revision-2 task must have REACHED RUNNING: a revision that never starts "
            f"is the case the shipped rollback checks already cover, and it would let an emulator "
            f"pass this one without ever evaluating a health probe; observed {attempts!r}")
        bad_arn = sorted(started)[0]
        bad_log = _stream_lines(ctx, log_group, bad_arn, f"REV2-{marker}")
        assert any(line == f"REV2-{marker}" for line in bad_log), (
            f"the revision-2 container's own stdout must prove it ran -- the rollback below is "
            f"then about a container that started and stayed unhealthy, not one that failed to "
            f"launch; stream={_stream_name(bad_arn)!r} log={bad_log!r}")
        unhealthy = [a for a, r in attempts.items() if "UNHEALTHY" in r["health"]]
        probe_blamed = [a for a, r in attempts.items()
                        if any("health check" in reason.lower() for reason in r["reasons"])]
        assert unhealthy or probe_blamed, (
            f"the failure must be attributed to the health probe -- either a task observed in "
            f"healthStatus UNHEALTHY or a stoppedReason naming the container health check. Both "
            f"forms are accepted because the UNHEALTHY window can close before a poll sees it, but "
            f"neither appearing means the deployment failed for some other reason and this check "
            f"would be asserting the wrong mechanism; observed {attempts!r}")

        rolled = _poll_until(
            lambda: _primary(ecs, cluster, service),
            lambda d: d is not None and d.get("taskDefinition") == good
            and d.get("rolloutState") == "COMPLETED",
            timeout_s=_ROLLBACK_TIMEOUT_S, interval_s=1, ctx=ctx,
            description="the PRIMARY deployment is revision 1 again, COMPLETED")
        assert rolled["taskDefinition"] == good, rolled
        svc = ecs.describe_services(cluster=cluster, services=[service])["services"][0]
        assert svc["taskDefinition"] == good, (
            f"the rollback must move the SERVICE's task definition back, not merely retire the "
            f"deployment; got {svc['taskDefinition']!r} (wanted {good!r})")
        assert svc["desiredCount"] == 1, (
            f"nothing here changed desiredCount, so a rollback that altered it would be a "
            f"different behaviour; got {svc['desiredCount']!r}")

        final = _poll_until(
            lambda: _one_task(ecs, cluster, service),
            lambda t: t is not None and t["lastStatus"] == "RUNNING"
            and t.get("healthStatus") == "HEALTHY",
            timeout_s=_CONVERGE_TIMEOUT_S, interval_s=1, ctx=ctx,
            description="exactly one RUNNING, HEALTHY task after the rollback")
        assert final["taskDefinitionArn"] == good, (
            f"the container left serving must be a revision-1 one; got "
            f"{final['taskDefinitionArn']!r}")
        final_log = _stream_lines(ctx, log_group, final["taskArn"], f"REV1-{marker}")
        assert any(line == f"REV1-{marker}" for line in final_log), (
            f"read off the surviving container's OWN stdout, the converged revision must be 1; "
            f"stream={_stream_name(final['taskArn'])!r} log={final_log!r}")
        assert not any(line == f"REV2-{marker}" for line in final_log), (
            f"the surviving container must not be a revision-2 one; log={final_log!r}")

        live = ecs.describe_tasks(
            cluster=cluster,
            tasks=_service_tasks(ecs, cluster, service, "RUNNING"))["tasks"]
        left = [t["taskArn"] for t in live if t["taskDefinitionArn"] == bad]
        assert left == [], (
            f"a rejected revision must leave nothing running: revision-2 tasks still RUNNING "
            f"{left!r}")
        ok = True
    finally:
        # Teardown runs inline: a Fargate stack (service drain, then the ENI lag that blocks the
        # subnet delete) outlasts the short cleanup timeout.
        leaks = td.run()
        if ok:
            assert not leaks, f"verified teardown did not remove everything: {leaks!r}"
        elif leaks:
            print(f"teardown after a failing body: {leaks!r}", file=sys.stderr)


_PREFIX = "sim2real-svcroll-"
_MANAGED_TAGS = {
    "sim2real:managed": "true",
    "sim2real:prefix": "sim2real-svcroll",
    "sim2real": "ecs-deployment-rollback",
}
_NET_TAGS = [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]

# Bounded deadlines, each with its reason.
_CONVERGE_TIMEOUT_S = 480        # placement + public-ECR pull + start + first passing probe
_DEPLOY_FAIL_TIMEOUT_S = 900     # the circuit breaker's >=3 attempts, each start-then-unhealthy
_ROLLBACK_TIMEOUT_S = 480        # the rollback deployment back onto the last COMPLETED revision
_LOG_TIMEOUT_S = 300             # awslogs stream creation, then event delivery
_SERVICE_DRAIN_TIMEOUT_S = 420   # desiredCount 0 -> runningCount 0 -> INACTIVE
_ENI_TIMEOUT_S = 600             # Fargate ENIs linger after a task stops and block subnet deletion
_TEARDOWN_TIMEOUT_S = 300        # deleted -> polled actually gone, per resource

# busybox, pinned BY DIGEST rather than the moving `latest`, so the container's behaviour is a
# property of one image and not of whatever was published today.
_BUSYBOX = ("public.ecr.aws/docker/library/busybox"
            "@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662")

# Byte-identical across both revisions: the container names its own revision from the environment,
# so stdout identifies which revision is talking without the two command lines differing.
_COMMAND = ["sh", "-c",
            'echo "REV$REV-$MARKER"; trap \'exit 42\' TERM; while true; do sleep 1; done']

# Also byte-identical across both revisions. $HEALTH is the integer the probe exits with, which is
# the ONE thing the broken revision changes.
_HEALTH_COMMAND = ["CMD-SHELL", "exit $HEALTH"]

_STREAM_PREFIX = "svcroll"
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
    """Undo steps run inline in reverse order, and also registered on ctx.on_cleanup as a net,
    because the cleanup chain's short timeout would cut a Fargate teardown mid-way."""

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
    """(subnets, sg) for Fargate (awsvpc) tasks, from a dedicated VPC.

    An account need not have a usable default VPC. Public subnet + IGW for the ECR Public pull, no
    NAT or EIP; the AZ is derived because AZ names are per-account aliases.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.196.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}])["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    zones = [z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]]
    assert zones, f"no availability zone in {ctx.region} reports state=available"
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.196.0.0/25", AvailabilityZone=zones[0],
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
    """Ensure AWSServiceRoleForECS exists; CreateService's implicit creation is not in time.

    Not torn down: it is account-level, free, and DeleteServiceLinkedRole fails while referenced.
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
    """A fresh role trusting ecs-tasks with one inline policy; returns (name, arn)."""
    iam = ctx.client("iam")
    name = ctx.unique_name(_PREFIX + kind + "-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST), Path="/sim2real/",
        Description="SimParity behavioral: ECS deployment rollback " + kind,
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


def _register_td(ctx, ecs, td, family, log_group, exec_role, marker, *, rev, health):
    """One revision of ONE family. Every field is shared between the two revisions except the two
    environment values, so the deployment's fate can only be about the health probe's exit code."""
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
            "environment": [{"name": "MARKER", "value": marker},
                            {"name": "REV", "value": rev},
                            {"name": "HEALTH", "value": health}],
            # The shortest probe ECS accepts: one failed run marks the container UNHEALTHY.
            "healthCheck": {"command": _HEALTH_COMMAND, "interval": 5, "timeout": 2,
                            "retries": 1, "startPeriod": 0},
            # Pinned rather than left to the platform default: a failing revision has to be torn
            # down three times before the circuit breaker trips, so the SIGTERM grace period is
            # part of this check's budget.
            "stopTimeout": 5,
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
    """A desiredCount 1 Fargate service with the deployment circuit breaker and rollback ENABLED,
    and no load balancer -- so the only signal that can fail a deployment is the container's own
    health probe."""
    name = ctx.unique_name(_PREFIX + "svc-")
    _launch_past_slr_lag(lambda: ecs.create_service(
        cluster=cluster, serviceName=name, taskDefinition=task_def, desiredCount=1,
        launchType="FARGATE", networkConfiguration=net,
        deploymentConfiguration={
            "deploymentCircuitBreaker": {"enable": True, "rollback": True},
            "minimumHealthyPercent": 100, "maximumPercent": 200},
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


def _service_tasks(ecs, cluster, service, desired_status):
    return sorted(_paginate(ecs, "list_tasks", "taskArns", cluster=cluster, serviceName=service,
                            desiredStatus=desired_status))


def _one_task(ecs, cluster, service):
    arns = _service_tasks(ecs, cluster, service, "RUNNING")
    if len(arns) != 1:
        return None
    tasks = _safe(lambda: ecs.describe_tasks(cluster=cluster, tasks=arns)["tasks"])
    return tasks[0] if tasks else None


def _deployments(ecs, cluster, service):
    svc = _safe(lambda: ecs.describe_services(cluster=cluster,
                                              services=[service])["services"][0])
    return (svc or {}).get("deployments", [])


def _deployment_for(ecs, cluster, service, task_def):
    for d in _deployments(ecs, cluster, service):
        if d.get("taskDefinition") == task_def:
            return d
    return None


def _primary(ecs, cluster, service):
    for d in _deployments(ecs, cluster, service):
        if d.get("status") == "PRIMARY":
            return d
    return None


def _await_rollout_failure(ecs, cluster, service, bad_def, timeout_s, ctx):
    """Poll until the bad revision's deployment reports rolloutState FAILED, accumulating what each
    of its tasks was observed doing on the way. The accumulation is the point: an attempt's RUNNING
    and UNHEALTHY states are transient, so they have to be sampled while they exist rather than
    reconstructed from the wreckage afterwards."""
    seen = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        arns = (_service_tasks(ecs, cluster, service, "RUNNING")
                + _service_tasks(ecs, cluster, service, "STOPPED"))
        for i in range(0, len(arns), 100):
            for t in (_safe(lambda c=arns[i:i + 100]: ecs.describe_tasks(
                    cluster=cluster, tasks=c)["tasks"]) or []):
                if t.get("taskDefinitionArn") != bad_def:
                    continue
                rec = seen.setdefault(t["taskArn"],
                                      {"statuses": set(), "health": set(), "reasons": set()})
                rec["statuses"].add(t.get("lastStatus"))
                rec["health"].add(t.get("healthStatus", "UNKNOWN"))
                if t.get("stoppedReason"):
                    rec["reasons"].add(t["stoppedReason"])
        deployment = _deployment_for(ecs, cluster, service, bad_def)
        if deployment is not None and deployment.get("rolloutState") == "FAILED":
            return deployment, seen
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError("the revision-2 deployment reporting rolloutState FAILED: the run budget "
                           "ended first; not graded")
    raise AssertionError(
        f"the revision-2 deployment never reported rolloutState FAILED within {timeout_s}s -- a "
        f"deployment whose container can never pass its health probe must be given up on, not "
        f"converged on. Deployments: {_deployments(ecs, cluster, service)!r} tasks: {seen!r}")


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
