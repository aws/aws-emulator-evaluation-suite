"""awslogs-exec-role-scoped-to-one-group-is-denied-on-another."""
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "awslogs-exec-role-scoped-to-one-group-is-denied-on-another"
GROUP = "log-workload-producers"
SERVICES = ["ecs", "logs"]

_IMAGE = "public.ecr.aws/docker/library/busybox:stable"
_MANAGED_TAGS = {"sim2real": CHECK}
_TASK_TIMEOUT_S = 600
_LOG_TIMEOUT_S = 180
_REPAIR_ATTEMPTS = 4


def _grant(account: str, region: str, groups: list[str]) -> list[dict]:
    arns = [f"arn:aws:logs:{region}:{account}:log-group:{g}:*" for g in groups]
    return [{"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
             "Resource": arns}]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An execution role whose log grant is resource-scoped to one group delivers a task logging
    there, fails to start the identical task pointed at a second group (which stays empty), and
    starts it once the grant names that group too: the resource scope alone blocked it."""
    ecs = ctx.client("ecs")
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    nonce = ctx.unique_name("nonce-")
    net = _build_network(ctx, "scope")
    try:
        allowed = _create_log_group(ctx)
        denied = _create_log_group(ctx)
        exec_role = _iam_role(ctx, "exec", _grant(account, ctx.region, [allowed]))
        cluster = _create_cluster(ctx, net)

        def taskdef(group: str) -> str:
            return _register_task_def(ctx, ctx.unique_name("sim2real-scope-"), [{
                "name": "app", "image": _IMAGE, "essential": True,
                "entryPoint": ["sh", "-c"], "command": [f'echo "TOKEN {nonce}"; sleep 2; exit 0'],
                "logConfiguration": _awslogs(group, ctx.region)}], exec_role)["taskDefinitionArn"]

        td_ok, td_bad = taskdef(allowed), taskdef(denied)

        # ---- positive control: same role, same image, the permitted group ----------------------
        ok_arn, ok = _run_until_started(ctx, cluster, td_ok, net)
        bad_arn = _run_task(ctx, cluster, td_bad, net)
        assert [c.get("exitCode") for c in ok["containers"]] == [0], (
            f"control task containers {[(c.get('exitCode'), c.get('reason')) for c in ok['containers']]!r}"
            f", stoppedReason {ok.get('stoppedReason')!r} — the scoped grant must permit its own group"
        )
        ok_id = ok_arn.rsplit("/", 1)[-1]
        ok_lines = _poll(lambda: _log_messages(ctx, allowed, f"ecs/app/{ok_id}"),
                         lambda m: f"TOKEN {nonce}" in m, _LOG_TIMEOUT_S,
                         what="the control task's token in the permitted group")
        assert ok_lines == [f"TOKEN {nonce}"], f"control stream carried {ok_lines!r}"

        # ---- the broken path: identical task, a group outside the grant -------------------------
        bad = _await_task(ctx, cluster, bad_arn, "STOPPED", _TASK_TIMEOUT_S)
        assert bad.get("stopCode") == "TaskFailedToStart", (
            f"the task logging to the unpermitted group stopped with stopCode "
            f"{bad.get('stopCode')!r} (reason {bad.get('stoppedReason')!r}), expected "
            f"'TaskFailedToStart'"
        )
        reason = bad.get("stoppedReason") or ""
        assert reason.startswith("ResourceInitializationError") and "AccessDeniedException" in reason, (
            f"stoppedReason {reason!r} — expected a ResourceInitializationError carrying the "
            f"logs AccessDeniedException"
        )
        assert [c.get("exitCode") for c in bad["containers"]] == [None], (
            f"the denied task's container reports exit codes "
            f"{[c.get('exitCode') for c in bad['containers']]!r}; it must never have run"
        )
        streams = logs.describe_log_streams(logGroupName=denied)["logStreams"]
        assert streams == [], (
            f"the unpermitted group {denied!r} gained streams {[s['logStreamName'] for s in streams]!r}"
        )

        # ---- repair the ONE broken thing, rerun the SAME task definition ------------------------
        iam.put_role_policy(RoleName=exec_role.rsplit("/", 1)[-1], PolicyName="inline",
                            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement":
                                                       _grant(account, ctx.region, [allowed, denied])}))
        delivered: list[str] = []
        attempts: list[str] = []
        for _ in range(_REPAIR_ATTEMPTS):  # bounded: IAM propagation exposes no condition to poll
            arn = _run_task(ctx, cluster, td_bad, net)
            t = _await_task(ctx, cluster, arn, "STOPPED", _TASK_TIMEOUT_S)
            attempts.append(f"{t.get('stopCode')}: {(t.get('stoppedReason') or '')[:120]}")
            if [c.get("exitCode") for c in t["containers"]] == [0]:
                delivered = _poll(
                    lambda arn=arn: _log_messages(ctx, denied, f"ecs/app/{arn.rsplit('/', 1)[-1]}"),
                    lambda m: f"TOKEN {nonce}" in m, _LOG_TIMEOUT_S,
                    what="the repaired task's token in the formerly denied group")
                break
        assert delivered == [f"TOKEN {nonce}"], (
            f"after widening the grant to {denied!r} the same task definition still did not "
            f"deliver; attempts {attempts!r}, delivered {delivered!r}"
        )
    finally:
        _settle(ctx, net)


# ===== helpers =====


def _ec2_tags(name: str) -> list[dict]:
    return [{"Key": "Name", "Value": name}] + [
        {"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags() -> list[dict]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


#: Error codes saying the resource does not exist: already deleted, or not created yet.
_GONE = ("ClusterNotFoundException", "ResourceNotFoundException", "NoSuchEntity",
         "Gateway.NotAttached")
#: Error codes of a delete refused while a dependency (a task ENI, a stopping task) is released.
_IN_USE = ("DependencyViolation", "ClusterContainsTasksException",
           "ClusterContainsServicesException", "ResourceInUseException")
_RELEASE_S = 120.0


def _unless_gone(fn, retry_s: float = 0.0):
    """fn(), or None when the target answers that the resource does not exist; within retry_s an
    in-use refusal is retried every 2 s; every other error raises."""
    deadline = time.monotonic() + retry_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith("NotFound") or code in _GONE:
                return None
            if code not in _IN_USE or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll(probe, predicate, timeout_s, interval_s=5.0, what="condition"):
    """Bounded retry that RAISES on timeout. Never a bare sleep standing in for a wait."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)


def _usable_zone(ec2) -> str:
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert zones, "no available availability zone in this region"
    return zones[0]


def _build_network(ctx, label: str) -> dict:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"sim2real-awsl-{label}-")
    net: dict = {"name": name, "tasks": []}
    vpc = ec2.create_vpc(CidrBlock="10.87.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _ec2_tags(name)}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_vpc(VpcId=vpc), _RELEASE_S))
    net["vpc"] = vpc
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})

    igw = ec2.create_internet_gateway(TagSpecifications=[
        {"ResourceType": "internet-gateway", "Tags": _ec2_tags(name)}])[
        "InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _unless_gone(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc))
        _unless_gone(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw), _RELEASE_S)

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rts = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc]}])["RouteTables"]
    assert len(rts) == 1, f"a fresh VPC must have exactly one route table; got {rts!r}"
    ec2.create_route(RouteTableId=rts[0]["RouteTableId"], DestinationCidrBlock="0.0.0.0/0",
                     GatewayId=igw)

    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.87.1.0/24",
                               AvailabilityZone=_usable_zone(ec2), TagSpecifications=[
                                   {"ResourceType": "subnet", "Tags": _ec2_tags(name)}])[
        "Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_subnet(SubnetId=subnet), _RELEASE_S))
    net["subnet"] = subnet

    sg = ec2.create_security_group(
        GroupName=name, Description="sim2real awslogs task SG (egress only)", VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _ec2_tags(name)}])["GroupId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_security_group(GroupId=sg), _RELEASE_S))
    net["sg"] = sg
    return net


def _settle(ctx, net: dict) -> None:
    """In-band teardown of the slow half: stop every task and wait for the subnet's ENIs to be
    released before the registered deletes run; a task or ENI that outlasts the wait raises,
    carrying any failure in flight."""
    found = sys.exc_info()[1]
    try:
        ecs = ctx.client("ecs")
        ec2 = ctx.client("ec2")
        tasks, cluster = list(net.get("tasks", [])), net.get("cluster")
        for t in tasks:
            _unless_gone(lambda t=t: ecs.stop_task(cluster=cluster, task=t,
                                                   reason="sim2real teardown"))
        if tasks:
            _poll(
                lambda: [x["lastStatus"] for x in ecs.describe_tasks(
                    cluster=cluster, tasks=tasks)["tasks"]],
                lambda ss: len(ss) == len(tasks) and all(x == "STOPPED" for x in ss), 300, 2,
                what="every task this check started reaching STOPPED")
        if net.get("subnet"):
            _poll(
                lambda: ec2.describe_network_interfaces(Filters=[
                    {"Name": "subnet-id", "Values": [net["subnet"]]}])["NetworkInterfaces"],
                lambda enis: not enis, 300, 2, what="subnet releasing its task ENIs")
    except Exception as exc:
        raise AssertionError(
            (f"{found!r}; " if found else "") + f"teardown could not settle the tasks: {exc!r}"
        ) from exc


def _iam_role(ctx, kind: str, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-awsl-{kind}-")
    arn = iam.create_role(
        RoleName=name, Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
             "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()])["Role"]["Arn"]

    def _drop():
        _unless_gone(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        _unless_gone(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_drop)
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    _poll(lambda: _unless_gone(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
          lambda r: r is not None, 60, 2, what=f"role {name} inline policy readable")
    # IAM propagation to the assuming service has no observable condition; a control task whose
    # launch races it is relaunched by _run_until_started.
    return arn


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-awsl-lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: _unless_gone(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _awslogs(group: str, region: str) -> dict:
    return {"logDriver": "awslogs", "options": {
        "awslogs-group": group, "awslogs-region": region, "awslogs-stream-prefix": "ecs"}}


def _create_cluster(ctx, net: dict) -> str:
    ecs = ctx.client("ecs")
    arn = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-awsl-cl-"),
                             tags=_ecs_tags())["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ecs.delete_cluster(cluster=arn), _RELEASE_S))
    net["cluster"] = arn
    return arn


def _register_task_def(ctx, family, containers, exec_role, cpu="256", memory="512") -> dict:
    ecs = ctx.client("ecs")
    td = ecs.register_task_definition(
        family=family, containerDefinitions=containers, requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc", cpu=cpu, memory=memory, executionRoleArn=exec_role,
        tags=_ecs_tags())["taskDefinition"]
    arn = td["taskDefinitionArn"]
    # LIFO: deregister runs first, then the delete that requires an INACTIVE revision.
    ctx.on_cleanup(lambda: _unless_gone(lambda: ecs.delete_task_definitions(taskDefinitions=[arn])))
    ctx.on_cleanup(lambda: _unless_gone(lambda: ecs.deregister_task_definition(taskDefinition=arn)))
    return td


def _run_task(ctx, cluster, td_arn, net) -> str:
    ecs = ctx.client("ecs")
    kwargs = dict(cluster=cluster, taskDefinition=td_arn, launchType="FARGATE", count=1,
                  tags=_ecs_tags(), networkConfiguration={"awsvpcConfiguration": {
                      "subnets": [net["subnet"]], "securityGroups": [net["sg"]],
                      "assignPublicIp": "ENABLED"}})
    deadline = time.monotonic() + 120
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:  # a just-created role may not be assumable by ECS yet: retry to the deadline
        try:
            resp = ecs.run_task(**kwargs)
            break
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            text = str(exc).lower()
            if not ((code == "InvalidParameterException" and "role" in text) or (
                    code == "ClientException" and "unable to assume the role" in text)):
                raise
            assert time.monotonic() < deadline, "RunTask kept rejecting the freshly created roles"
        time.sleep(2)
    assert resp["failures"] == [], f"RunTask failures: {resp['failures']!r}"
    arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ecs.stop_task(cluster=cluster, task=arn)))
    net["tasks"].append(arn)
    return arn


def _run_until_started(ctx, cluster, td_arn, net, timeout_s=120.0) -> tuple[str, dict]:
    """Run the task to STOPPED, relaunching for up to timeout_s while it fails to start before its
    container ran (a just-created role not yet usable by ECS); returns (task_arn, stopped task)."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        task_arn = _run_task(ctx, cluster, td_arn, net)
        task = _await_task(ctx, cluster, task_arn, "STOPPED", _TASK_TIMEOUT_S)
        never_ran = all(c.get("exitCode") is None for c in task.get("containers", []))
        if task.get("stopCode") != "TaskFailedToStart" or not never_ran or (
                time.monotonic() >= deadline):
            return task_arn, task
        time.sleep(2)


def _await_task(ctx, cluster, task_arn, status, timeout_s) -> dict:
    ecs = ctx.client("ecs")

    def probe():
        found = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        return found[0] if found else {}

    task = _poll(probe, lambda t: t.get("lastStatus") in (status, "STOPPED"), timeout_s,
                 what=f"task {task_arn} reaching {status}")
    assert task["lastStatus"] == status, (
        f"task {task_arn} is {task['lastStatus']!r}, expected {status!r}: stopCode="
        f"{task.get('stopCode')!r} stoppedReason={task.get('stoppedReason')!r} containers="
        f"{[(c['name'], c.get('exitCode'), c.get('reason')) for c in task.get('containers', [])]!r}"
    )
    return task


def _log_messages(ctx, group: str, stream: str) -> list[str]:
    """Every event in the stream, paginated forward from the head ([] until it exists)."""
    logs = ctx.client("logs")
    msgs: list[str] = []
    token = None
    while True:
        kwargs: dict = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
        if token:
            kwargs["nextToken"] = token
        page = _unless_gone(lambda: logs.get_log_events(**kwargs))
        if page is None:
            return msgs
        events = page.get("events", [])
        msgs += [e.get("message", "") for e in events]
        nxt = page.get("nextForwardToken")
        if not events or nxt == token:
            return msgs
        token = nxt


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
