"""exec-disabled-task-session-rejected-while-enabled-streams."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import time
import urllib.parse
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "exec-disabled-task-session-rejected-while-enabled-streams"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c6",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """ExecuteCommand on a task run with enableExecuteCommand=False is rejected with the exact error
    and the task gets no ExecuteCommandAgent or active SSM session and stays RUNNING, while an
    identical enabled task in the same cluster streams real container stdout over ssmmessages."""
    ecs = ctx.client("ecs")
    ssm = ctx.client("ssm")
    nonce = ctx.unique_name("")

    subnet_id, sg_id = _dedicated_fargate_network(ctx)
    exec_role_arn, task_role_arn = _exec_task_roles(ctx)
    estate = _run_exec_task(
        ctx, ecs, subnet_id, sg_id, exec_role_arn, task_role_arn, enable_exec=True
    )
    cluster_arn, container, enabled_task = (
        estate["cluster"],
        estate["container"],
        estate["task"],
    )
    # The same definition, the same cluster, the same roles -- one flag flipped.
    disabled_task = _run_task_with_iam_retry(
        ecs, cluster_arn, estate["taskdef"], estate["net"], enable_exec=False, ctx=ctx
    )
    # ONE wait covering BOTH tasks: cleanup has one overall bound, and two
    # sequential stop-waits spend the budget the cluster, role and VPC deletes need.
    ctx.on_cleanup(lambda: _stop_all(ecs, cluster_arn, [disabled_task, enabled_task]))
    disabled_id = disabled_task.rsplit("/", 1)[-1]

    _wait_for_exec_agent(ecs, cluster_arn, enabled_task, timeout_s=_budget_s(ctx, 240), ctx=ctx)
    _wait_for_running(ecs, cluster_arn, disabled_task, timeout_s=_budget_s(ctx, 240), ctx=ctx)

    # --- the positive control: the enabled task really streams its container's stdout.
    resp = ecs.execute_command(
        cluster=cluster_arn,
        task=enabled_task,
        container=container,
        interactive=True,
        command="/bin/sh",
    )
    good_session_id = resp["session"]["sessionId"]
    ctx.on_cleanup(lambda: _terminate_session(ssm, good_session_id))
    term = _ExecTerminal(resp["session"], ctx=ctx)
    ctx.on_cleanup(term.close)
    assert term.wait_ready(timeout_s=60), (
        f"the enabled task's exec channel never produced a shell prompt; agent traffic was "
        f"{term.trace!r}"
    )
    term.type(f"echo CONTROL$((20+22))-{nonce}=$?")
    out = term.pump(until=f"CONTROL42-{nonce}=".encode(), timeout_s=30)
    assert f"CONTROL42-{nonce}=0" in out, (
        f"the positive control never got container stdout back: {out[-500:]!r}"
    )

    # --- the negative: the same call against the task that did not opt in.
    code, message = _error(
        lambda: ecs.execute_command(
            cluster=cluster_arn,
            task=disabled_task,
            container=container,
            interactive=True,
            command="/bin/sh",
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a task launched with "
        f"enableExecuteCommand=False, got {code!r}"
    )
    assert message == "The execute command failed because execute command was not enabled when the task was run or the execute command agent isn't running. Wait and try again or run a new task with execute command enabled and try again.", f"unexpected message: {message!r}"

    # --- absence 1: no exec agent was ever attached to the disabled task.
    described = {
        t["taskArn"]: t
        for t in ecs.describe_tasks(cluster=cluster_arn, tasks=[enabled_task, disabled_task])[
            "tasks"
        ]
    }
    disabled_agents = [
        a for c in described[disabled_task].get("containers", []) for a in c.get("managedAgents", [])
    ]
    assert not [a for a in disabled_agents if a.get("name") == "ExecuteCommandAgent"], (
        f"the disabled task has an ExecuteCommandAgent managed agent: {disabled_agents!r}"
    )
    enabled_agents = [
        a for c in described[enabled_task].get("containers", []) for a in c.get("managedAgents", [])
    ]
    assert [
        a
        for a in enabled_agents
        if a.get("name") == "ExecuteCommandAgent" and a.get("lastStatus") == "RUNNING"
    ], f"the enabled task lost its RUNNING ExecuteCommandAgent: {enabled_agents!r}"
    assert described[disabled_task]["lastStatus"] == "RUNNING", (
        f"the rejected ExecuteCommand disturbed the disabled task, now "
        f"{described[disabled_task]['lastStatus']!r}"
    )
    assert described[disabled_task].get("enableExecuteCommand") is False, (
        "DescribeTasks reports enableExecuteCommand="
        f"{described[disabled_task].get('enableExecuteCommand')!r} for the task launched without it"
    )

    # --- absence 2: SSM brokered a session for the enabled task and none for the disabled one.
    #     Scoped to the task ids this check created, so other sessions in the account do not count.
    targets = _active_session_targets(ssm, {good_session_id: None}, [disabled_id])
    assert good_session_id in targets["by_id"], (
        f"the positive control's session {good_session_id!r} was never visible in "
        f"ssm:DescribeSessions(State=Active) -- the session data was not backed by a real "
        f"Session Manager session; active ids seen: {sorted(targets['all_ids'])[:20]!r}"
    )
    assert targets["disabled_matches"] == [], (
        f"Session Manager has active session(s) targeting the disabled task {disabled_id!r}: "
        f"{targets['disabled_matches']!r}"
    )


def _wait_for_running(ecs, cluster_arn, task_arn, timeout_s=240.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        tasks = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"]
        if tasks:
            last = tasks[0]
            if last["lastStatus"] == "STOPPED":
                raise AssertionError(f"task stopped early: {last.get('stoppedReason')!r}")
            if last["lastStatus"] == "RUNNING":
                return
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"task {task_arn} reaching RUNNING: the run budget ended first; not graded")
    raise AssertionError(
        f"task never reached RUNNING within {timeout_s}s: last describe_tasks was {last!r}"
    )


def _error(fn):
    """Return the AWS error (code, message) `fn` raised; an unexpected success raises."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to fail but succeeded with {resp!r}")


def _active_session_targets(ssm, wanted_ids, task_ids):
    """Paginated ssm:DescribeSessions(State=Active), filtered to the session ids and task ids this
    check minted, since unrelated sessions may exist in the account."""
    all_ids, disabled_matches, by_id = set(), [], {}
    token = None
    while True:
        kwargs = {"State": "Active", "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = ssm.describe_sessions(**kwargs)
        for s in page.get("Sessions", []):
            sid = s.get("SessionId", "")
            all_ids.add(sid)
            if sid in wanted_ids:
                by_id[sid] = s
            target = s.get("Target") or ""
            if any(tid in target or tid in sid for tid in task_ids):
                disabled_matches.append({"SessionId": sid, "Target": target})
        token = page.get("NextToken")
        if not token:
            break
    return {"all_ids": all_ids, "disabled_matches": disabled_matches, "by_id": by_id}




# The teardown steps below share ONE latched 600 s budget, with 300 s reserved for the tail that
# can only run last (subnet, IGW, VPC); both fit inside the ecs suite's 900 s cleanup budget.
_CLEANUP_BUDGET_S = 600.0
_NET_RESERVE_S = 300.0
_teardown_deadline = None


def _deadline(reserve=0.0):
    """The monotonic cutoff shared by every teardown entry, latched by the first one to ask."""
    global _teardown_deadline
    if _teardown_deadline is None:
        _teardown_deadline = time.monotonic() + _CLEANUP_BUDGET_S
    return _teardown_deadline - reserve

_PREFIX = "sim2real-ecsexec-"
_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:check", "Value": CHECK},
]
_ECS_TAGS = [
    {"key": "sim2real:managed", "value": "true"},
    {"key": "sim2real:check", "value": CHECK},
]
_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)
_SSMMESSAGES = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Resource": "*",
                "Action": [
                    "ssmmessages:CreateControlChannel",
                    "ssmmessages:CreateDataChannel",
                    "ssmmessages:OpenControlChannel",
                    "ssmmessages:OpenDataChannel",
                ],
            }
        ],
    }
)


def _dedicated_fargate_network(ctx):
    """A VPC this check owns outright, never the account's default VPC, which a fresh account
    need not have."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.207.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _teardown_network(ec2, vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )
    assert zones, f"no available availability zone in {ctx.region!r} to place the Fargate subnet in"
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.207.0.0/25",
        AvailabilityZone=zones[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _NET_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["SecurityGroups"]
        if sg["GroupName"] == "default"
    )
    return subnet_id, sg_id


def _teardown_network(ec2, vpc_id):
    """One net for the whole VPC: the Fargate ENI outlives the task by a minute or so, and the
    subnet is undeletable until it is gone. Registered BEFORE the subnet/IGW exist so it runs
    LAST, after the task stop, inside the reserved slice of the teardown budget."""
    deadline = _deadline()
    eni_cutoff = deadline - 8
    subnets = [
        s["SubnetId"]
        for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    ]
    while time.monotonic() < eni_cutoff:
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        ).get("NetworkInterfaces", [])
        if not enis:
            break
        time.sleep(3)
    for subnet_id in subnets:
        _delete_when_released(lambda s=subnet_id: ec2.delete_subnet(SubnetId=s),
                              ("InvalidSubnetID.NotFound",), deadline)
    for igw in ec2.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
    ).get("InternetGateways", []):
        igw_id = igw["InternetGatewayId"]
        _delete_when_released(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
                              ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"), deadline)
        _delete_when_released(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id),
                              ("InvalidInternetGatewayID.NotFound",), deadline)
    _delete_when_released(lambda: ec2.delete_vpc(VpcId=vpc_id), ("InvalidVpcID.NotFound",), deadline)


def _delete_when_released(call, gone_codes, deadline):
    """Run one network delete: a not-found code means already gone, DependencyViolation (an ENI or
    mapped address not yet released) is retried every 2 s to the deadline, anything else raises."""
    while True:
        try:
            call()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _create_role(ctx, iam, prefix, *, managed=(), inline=None):
    role_name = ctx.unique_name(prefix)
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST,
        Tags=[{"Key": t["Key"], "Value": t["Value"]} for t in _NET_TAGS],
    )["Role"]["Arn"]

    def _cleanup():
        for name in inline or {}:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for arn in managed:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    for arn in managed:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    for name, doc in (inline or {}).items():
        iam.put_role_policy(RoleName=role_name, PolicyName=name, PolicyDocument=doc)
    return role_arn


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _exec_task_roles(ctx):
    """The execution role Fargate needs to pull the image, and a task role carrying exactly the
    ssmmessages grants ECS Exec requires. IAM is eventually consistent and exposes no condition
    to poll, so the bounded RunTask retry below absorbs the propagation delay."""
    iam = ctx.client("iam")
    exec_role_arn = _create_role(
        ctx,
        iam,
        _PREFIX + "exrole-",
        managed=["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"],
    )
    task_role_arn = _create_role(
        ctx, iam, _PREFIX + "taskrole-", inline={"ecs-exec-ssmmessages": _SSMMESSAGES}
    )
    return exec_role_arn, task_role_arn


def _run_exec_task(ctx, ecs, subnet_id, sg_id, exec_role_arn, task_role_arn, *, enable_exec):
    cluster_name = ctx.unique_name(_PREFIX + "cluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name, tags=_ECS_TAGS)["cluster"][
        "clusterArn"
    ]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    container = "app"
    taskdef_arn = ecs.register_task_definition(
        family=ctx.unique_name(_PREFIX + "td-"),
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        taskRoleArn=task_role_arn,
        tags=_ECS_TAGS,
        containerDefinitions=[
            {
                "name": container,
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sleep", "1800"],
                "linuxParameters": {"initProcessEnabled": True},
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _purge_taskdef(ecs, taskdef_arn))

    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    task_arn = _run_task_with_iam_retry(
        ecs, cluster_arn, taskdef_arn, net_cfg, enable_exec=enable_exec, ctx=ctx
    )
    ctx.on_cleanup(lambda: _stop_and_wait(ecs, cluster_arn, task_arn))
    return {
        "cluster": cluster_arn,
        "container": container,
        "task": task_arn,
        "taskdef": taskdef_arn,
        "net": net_cfg,
    }


def _purge_taskdef(ecs, taskdef_arn):
    ecs.deregister_task_definition(taskDefinition=taskdef_arn)
    ecs.delete_task_definitions(taskDefinitions=[taskdef_arn])


def _stop_and_wait(ecs, cluster_arn, task_arn):
    try:
        ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real check cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise
        return
    deadline = _deadline(reserve=_NET_RESERVE_S)
    while time.monotonic() < deadline:
        found = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn]).get("tasks", [])
        if not found or found[0]["lastStatus"] == "STOPPED":
            return
        time.sleep(3)
    raise AssertionError(f"task {task_arn} not STOPPED before the teardown deadline")


def _stop_all(ecs, cluster_arn, task_arns):
    """Issue every stop first and wait once: the tasks drain in parallel, so teardown pays one
    wait instead of one per task and stays inside the cleanup budget."""
    for task_arn in task_arns:
        try:
            ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="sim2real check cleanup")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
            return
    deadline = _deadline(reserve=_NET_RESERVE_S)
    pending = list(task_arns)
    while pending and time.monotonic() < deadline:
        found = ecs.describe_tasks(cluster=cluster_arn, tasks=pending).get("tasks", [])
        pending = [t["taskArn"] for t in found if t["lastStatus"] != "STOPPED"]
        if pending:
            time.sleep(3)
    if pending:
        raise AssertionError(f"tasks {pending} not STOPPED before the teardown deadline")


def _run_task_with_iam_retry(ecs, cluster_arn, taskdef_arn, net_cfg, *, enable_exec, ctx,
                             timeout_s=120.0):
    """A just-created role is not yet assumable by ECS, and no API reports when it becomes so:
    RunTask answers ClientException 'unable to assume the role'. Retry, bounded."""
    last = None
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        try:
            resp = ecs.run_task(
                cluster=cluster_arn,
                taskDefinition=taskdef_arn,
                launchType="FARGATE",
                platformVersion="LATEST",
                count=1,
                enableExecuteCommand=enable_exec,
                networkConfiguration=net_cfg,
                tags=_ECS_TAGS,
            )
        except ClientError as exc:
            last = f"{exc.response['Error']['Code']}: {exc}"
            if time.monotonic() >= deadline:
                break
            time.sleep(2)
            continue
        if resp.get("tasks"):
            task = resp["tasks"][0]
            assert task.get("enableExecuteCommand") is enable_exec, (
                f"RunTask echoed enableExecuteCommand={task.get('enableExecuteCommand')!r}, "
                f"asked for {enable_exec!r}"
            )
            return task["taskArn"]
        last = f"failures={resp.get('failures')}"
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"RunTask placing a task: the run budget ended first; not graded ({last})")
    raise AssertionError(f"RunTask never placed a task within {timeout_s}s: {last}")


def _wait_for_exec_agent(ecs, cluster_arn, task_arn, timeout_s=240.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        tasks = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"]
        if tasks:
            last = tasks[0]
            if last["lastStatus"] == "STOPPED":
                raise AssertionError(
                    f"task stopped before it was execable: {last.get('stoppedReason')!r}"
                )
            for c in last.get("containers", []):
                for agent in c.get("managedAgents", []):
                    if agent.get("name") == "ExecuteCommandAgent" and (
                        agent.get("lastStatus") == "RUNNING"
                    ):
                        return
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(
            f"ExecuteCommandAgent on {task_arn} reaching RUNNING: the run budget ended first; "
            f"not graded")
    raise AssertionError(
        f"ExecuteCommandAgent never reached RUNNING within {timeout_s}s: last describe_tasks was "
        f"{last!r}"
    )


def _terminate_session(ssm, session_id):
    try:
        ssm.terminate_session(SessionId=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DoesNotExistException":
            raise


# --- the Session Manager wire protocol -----------------------------------------------------
# ECS Exec's data plane is a WebSocket to ssmmessages carrying SSM's binary agent-message
# framing (the protocol session-manager-plugin speaks). There is no boto3 client for it, so the
# frames are built here: RFC 6455 over a raw TLS socket, then the 116-byte agent-message header,
# the agent handshake, per-message acknowledgements, and the terminal payloads.

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_HEADER_LEN = 116
_PT_OUTPUT = 1
_PT_SIZE = 3
_PT_HANDSHAKE_REQUEST = 5
_PT_HANDSHAKE_RESPONSE = 6
_PT_HANDSHAKE_COMPLETE = 7


class _WebSocket:
    def __init__(self, url, timeout=30.0, *, ctx=None):
        parts = urllib.parse.urlsplit(url)
        # Graded by scheme family and host; a target served over TLS publishes wss.
        assert not (p := ctx.published_url_mismatch(url, websocket=True)), p
        assert parts.scheme == "wss" or not ctx.client("ecs").meta.endpoint_url.startswith("https://"), (
            f"expected a wss:// stream url, got {url!r}"
        )
        tls = parts.scheme == "wss"
        host, port = parts.hostname, parts.port or (443 if tls else 80)
        target = parts.path + (f"?{parts.query}" if parts.query else "")
        _t = urllib.parse.urlsplit(ctx.endpoint_url(f"{'https' if tls else 'http'}://{host}"))
        raw = socket.create_connection((_t.hostname, _t.port or port), timeout=timeout)
        # An emulator serving the stream at a plaintext endpoint takes no TLS.
        secure = _t.scheme == "https"
        self._sock = _ssl_context(ctx.http_verify).wrap_socket(raw, server_hostname=host) if secure else raw
        key = base64.b64encode(os.urandom(16)).decode()
        self._sock.sendall(
            (
                f"GET {target} HTTP/1.1\r\nHost: {host}\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError(f"stream url closed during upgrade: {buf[:400]!r}")
            buf += chunk
        head, _, self._buf = buf.partition(b"\r\n\r\n")
        self.headers = head.decode(errors="replace")
        self.status_line = self.headers.splitlines()[0]
        if " 101 " not in f" {self.status_line} ":
            self.close()
            raise ConnectionError(f"websocket upgrade refused: {self.status_line}")
        expect = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
        assert expect.lower() in self.headers.lower(), (
            f"Sec-WebSocket-Accept did not match the key we sent: {self.headers!r}"
        )

    def settimeout(self, seconds):
        self._sock.settimeout(seconds)

    def _need(self, n):
        while len(self._buf) < n:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise ConnectionError("websocket closed by peer")
            self._buf += chunk

    def send(self, payload, opcode=0x2):
        mask = os.urandom(4)
        n = len(payload)
        head = bytearray([0x80 | opcode])
        if n < 126:
            head.append(0x80 | n)
        elif n < 65536:
            head.append(0x80 | 126)
            head += struct.pack("!H", n)
        else:
            head.append(0x80 | 127)
            head += struct.pack("!Q", n)
        head += mask
        self._sock.sendall(
            bytes(head) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        )

    def recv(self):
        frames, first_op = [], None
        while True:
            self._need(2)
            b0, b1 = self._buf[0], self._buf[1]
            fin, op, masked, ln = b0 & 0x80, b0 & 0x0F, b1 & 0x80, b1 & 0x7F
            off = 2
            if ln == 126:
                self._need(4)
                ln = struct.unpack("!H", self._buf[2:4])[0]
                off = 4
            elif ln == 127:
                self._need(10)
                ln = struct.unpack("!Q", self._buf[2:10])[0]
                off = 10
            mask = b""
            if masked:
                self._need(off + 4)
                mask = self._buf[off:off + 4]
                off += 4
            self._need(off + ln)
            data = self._buf[off:off + ln]
            if masked:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            self._buf = self._buf[off + ln:]
            if op == 0x9:  # ping
                self.send(data, opcode=0xA)
                continue
            if op == 0xA:  # pong
                continue
            if op == 0x8:
                raise ConnectionError(f"websocket close frame: {data[:200]!r}")
            if first_op is None:
                first_op = op
            frames.append(data)
            if fin:
                return first_op, b"".join(frames)

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


def _agent_message(msg_type, seq, flags, payload_type, payload):
    return b"".join(
        [
            struct.pack("!I", _HEADER_LEN),
            msg_type.encode().ljust(32, b" "),
            struct.pack("!I", 1),
            struct.pack("!Q", int(time.time() * 1000)),
            struct.pack("!q", seq),
            struct.pack("!Q", flags),
            os.urandom(16),
            hashlib.sha256(payload).digest(),
            struct.pack("!I", payload_type),
            struct.pack("!I", len(payload)),
            payload,
        ]
    )


def _parse_agent_message(buf):
    assert len(buf) >= _HEADER_LEN + 4, f"agent message truncated at {len(buf)} bytes"
    plen = struct.unpack("!I", buf[116:120])[0]
    # MessageId is stored least-significant-long first, the way the agent writes a UUID.
    return {
        "message_type": buf[4:36].decode(errors="replace").strip(" \x00"),
        "sequence_number": struct.unpack("!q", buf[48:56])[0],
        "message_id": str(uuid.UUID(bytes=buf[72:80] + buf[64:72])),
        "payload_type": struct.unpack("!I", buf[112:116])[0],
        "payload": buf[120:120 + plen],
    }


class _ExecTerminal:
    """A live ECS Exec terminal: opens the data channel with the session token, answers the
    agent handshake, types into the container's pty and accumulates what came back."""

    def __init__(self, session, timeout=30.0, *, ctx=None):
        self.ws = _WebSocket(session["streamUrl"], timeout=timeout, ctx=ctx)
        self._ctx = ctx
        self._seq = 0
        self._ready = False
        self._out = bytearray()
        self.trace = []
        self.ws.send(
            json.dumps(
                {
                    "MessageSchemaVersion": "1.0",
                    "RequestId": str(uuid.uuid4()),
                    "TokenValue": session["tokenValue"],
                    "ClientId": str(uuid.uuid4()),
                    "ClientVersion": "1.2.633.0",
                }
            ).encode(),
            opcode=0x1,
        )

    def _send_input(self, payload_type, payload):
        self.ws.send(
            _agent_message("input_stream_data", self._seq, 1 if self._seq == 0 else 0,
                           payload_type, payload)
        )
        self._seq += 1

    def _acknowledge(self, msg):
        self.ws.send(
            _agent_message(
                "acknowledge",
                0,
                3,
                0,
                json.dumps(
                    {
                        "AcknowledgedMessageType": msg["message_type"],
                        "AcknowledgedMessageId": msg["message_id"],
                        "AcknowledgedMessageSequenceNumber": msg["sequence_number"],
                        "IsSequentialMessage": True,
                    }
                ).encode(),
            )
        )

    def _read_once(self, budget):
        self.ws.settimeout(max(1.0, budget))
        try:
            op, raw = self.ws.recv()
        except (socket.timeout, TimeoutError):
            return False
        if op != 0x2:  # a text frame is a service-level message, not agent traffic
            return True
        msg = _parse_agent_message(raw)
        self.trace.append((msg["message_type"], msg["payload_type"], len(msg["payload"])))
        if msg["message_type"] != "output_stream_data":
            return True
        self._acknowledge(msg)
        if msg["payload_type"] == _PT_HANDSHAKE_REQUEST:
            requested = json.loads(msg["payload"])["RequestedClientActions"]
            self._send_input(
                _PT_HANDSHAKE_RESPONSE,
                json.dumps(
                    {
                        "ClientVersion": "1.2.633.0",
                        "ProcessedClientActions": [
                            {"ActionType": a["ActionType"], "ActionStatus": 1} for a in requested
                        ],
                        "Errors": [],
                    }
                ).encode(),
            )
        elif msg["payload_type"] == _PT_HANDSHAKE_COMPLETE:
            self._send_input(_PT_SIZE, json.dumps({"cols": 120, "rows": 40}).encode())
            self._ready = True
        elif msg["payload_type"] == _PT_OUTPUT:
            self._out += msg["payload"]
        return True

    def wait_ready(self, timeout_s=60.0):
        """Ready == the container has written its first byte (a shell prompt). ECS Exec's
        Standard_Stream sessions send `start_publication` and then output straight away, with no
        HandshakeRequest, so waiting for a handshake here would wait forever."""
        deadline = time.monotonic() + (
            timeout_s if self._ctx is None else _budget_s(self._ctx, timeout_s))
        while time.monotonic() < deadline:
            if self._out:
                return True
            if not self._read_once(deadline - time.monotonic()):
                break
        if not self._out and self._ctx is not None and _budget_spent(self._ctx):
            raise TimeoutError("the exec session's first output: the run budget ended first; not graded")
        return bool(self._out)

    def type(self, line):
        self._send_input(_PT_OUTPUT, (line + "\n").encode())

    def pump(self, until, timeout_s=30.0):
        """Read agent traffic until `until` appears in the accumulated container output."""
        deadline = time.monotonic() + (
            timeout_s if self._ctx is None else _budget_s(self._ctx, timeout_s))
        while time.monotonic() < deadline:
            if until in bytes(self._out):
                break
            if not self._read_once(deadline - time.monotonic()):
                break
        if until not in bytes(self._out) and self._ctx is not None and _budget_spent(self._ctx):
            raise TimeoutError(f"{until!r} in the exec output: the run budget ended first; not graded")
        return bytes(self._out).decode(errors="replace")

    def close(self):
        self.ws.close()


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
