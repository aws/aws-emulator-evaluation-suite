"""deep-ecs-guest-identity-awsvpc-task-reachable-on-its-eni-ip-only-while-its-sg-allows-it."""

from __future__ import annotations

import json
import re
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-ecs-guest-identity-awsvpc-task-reachable-on-its-eni-ip-only-while-its-sg-allows-it"

GROUP = "guest-identity"

SERVICES = ["ecs", "logs"]

_IMAGE = "public.ecr.aws/docker/library/python:3.12-alpine"
_PORT = 8080

#: Server guest: reports its own metadata-v4 Networks, then serves a per-run nonce on _PORT and
#: logs the source address of every request it answers.
_SERVER = r"""
import http.server, json, os, urllib.request
with urllib.request.urlopen(os.environ["ECS_CONTAINER_METADATA_URI_V4"], timeout=10) as r:
    print("SRVMETA " + json.dumps(json.loads(r.read()).get("Networks")), flush=True)
nonce = os.environ["NONCE"].encode()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(nonce)))
        self.end_headers()
        self.wfile.write(nonce)
        print("SRVHIT " + self.client_address[0], flush=True)
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
""".replace("PORT", str(_PORT))

#: Client guest: a fresh TCP connection to the server's ENI address every 2 s, each logged as
#: `PROBE <seq> OK <body>` or `PROBE <seq> FAIL <kind>`; kind `timeout` is a silently dropped SYN.
_CLIENT = r"""
import os, socket, time, urllib.request
url = "http://%s:PORT/" % os.environ["SERVER_IP"]
seq = 0
while True:
    seq += 1
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            print("PROBE %d OK %s" % (seq, r.read().decode()), flush=True)
    except Exception as exc:
        reason = getattr(exc, "reason", exc)
        timed_out = isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason)
        print("PROBE %d FAIL %s" % (seq, "timeout" if timed_out else type(reason).__name__), flush=True)
    time.sleep(2)
""".replace("PORT", str(_PORT))

_TASK_RUNNING_TIMEOUT_S = 600
_LOG_TIMEOUT_S = 480
_SG_EFFECT_TIMEOUT_S = 300
_STREAK = 3

_PROBE_RE = re.compile(r"^PROBE (\d+) (OK|FAIL) ?(.*)$")


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An awsvpc task answers on its own ENI address, and its security group alone decides who
    reaches it: revoking one client's ingress rule drops that client's connections (timeouts) while
    a still-allowed client keeps getting through, and re-authorizing restores delivery."""
    ecs = ctx.client("ecs")
    net = _build_network(ctx, "sgr")
    try:
        _body(ctx, ecs, net)
    finally:
        _settle(ctx, net)


def _new_sg(ctx, net, role: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"sim2real-deg-sgr-{role}-")
    sg = ec2.create_security_group(
        GroupName=name, Description=f"sim2real guest-identity {role}", VpcId=net["vpc"],
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _ec2_tags(name)}])["GroupId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_security_group(GroupId=sg), _RELEASE_S))
    return sg


def _perm(src_sg: str) -> list[dict]:
    return [{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
             "UserIdGroupPairs": [{"GroupId": src_sg}]}]


def _probes(ctx, group: str, stream: str) -> list[tuple[int, str, str]]:
    out = []
    for m in _log_messages(ctx, group, stream):
        hit = _PROBE_RE.match(m)
        if hit:
            out.append((int(hit.group(1)), hit.group(2), hit.group(3).strip()))
    return sorted(out)


def _after(probes, seq):
    return [p for p in probes if p[0] > seq]


def _fail_streak(probes) -> bool:
    run_ = 0
    for _, status, detail in probes:
        run_ = run_ + 1 if (status == "FAIL" and detail == "timeout") else 0
        if run_ >= _STREAK:
            return True
    return False


def _body(ctx, ecs, net) -> None:
    ec2 = ctx.client("ec2")
    log_group = _create_log_group(ctx)
    exec_role = _iam_role(ctx, "sgr-exec", [
        {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"}])
    # Created client-first so LIFO cleanup deletes the referencing server group before them.
    sg_a, sg_b = _new_sg(ctx, net, "a"), _new_sg(ctx, net, "b")
    sg_srv = _new_sg(ctx, net, "srv")
    ec2.authorize_security_group_ingress(GroupId=sg_srv, IpPermissions=_perm(sg_a) + _perm(sg_b))

    cluster_arn = _create_cluster(ctx, net)
    nonce = ctx.unique_name("nonce-")
    lc = _awslogs(log_group, ctx.region)
    srv_td = _register_task_def(ctx, ctx.unique_name("sim2real-deg-sgr-srv-"), [{
        "name": "server", "image": _IMAGE, "essential": True,
        "command": ["python3", "-c", _SERVER],
        "environment": [{"name": "NONCE", "value": nonce}],
        "portMappings": [{"containerPort": _PORT, "protocol": "tcp"}],
        "logConfiguration": lc}], exec_role)
    srv_arn, srv_task = _launch_running(ctx, cluster_arn, srv_td["taskDefinitionArn"], net,
                                        sgs=[sg_srv])
    srv_ip = _eni_details(srv_task)["privateIPv4Address"]

    cli_td = _register_task_def(ctx, ctx.unique_name("sim2real-deg-sgr-cli-"), [{
        "name": "client", "image": _IMAGE, "essential": True,
        "command": ["python3", "-c", _CLIENT], "logConfiguration": lc}], exec_role)
    over = {"containerOverrides": [{"name": "client",
                                    "environment": [{"name": "SERVER_IP", "value": srv_ip}]}]}
    a_arn = _run_task(ctx, cluster_arn, cli_td["taskDefinitionArn"], net, sgs=[sg_a], overrides=over)
    b_arn = _run_task(ctx, cluster_arn, cli_td["taskDefinitionArn"], net, sgs=[sg_b], overrides=over)
    a_ip = _eni_details(_await_task(ctx, cluster_arn, a_arn, "RUNNING", _TASK_RUNNING_TIMEOUT_S))[
        "privateIPv4Address"]
    b_ip = _eni_details(_await_task(ctx, cluster_arn, b_arn, "RUNNING", _TASK_RUNNING_TIMEOUT_S))[
        "privateIPv4Address"]
    assert len({srv_ip, a_ip, b_ip}) == 3, f"tasks share an address: {srv_ip}, {a_ip}, {b_ip}"

    srv_stream = f"ecs/server/{srv_arn.rsplit('/', 1)[-1]}"
    a_stream = f"ecs/client/{a_arn.rsplit('/', 1)[-1]}"
    b_stream = f"ecs/client/{b_arn.rsplit('/', 1)[-1]}"

    # --- the guest's own address is the ENI's -------------------------------------------------
    srv_lines = _poll(lambda: _log_messages(ctx, log_group, srv_stream),
                      lambda ms: any(m.startswith("SRVMETA ") for m in ms),
                      _LOG_TIMEOUT_S, what=f"server metadata line in {srv_stream}")
    networks = json.loads([m for m in srv_lines if m.startswith("SRVMETA ")][0][len("SRVMETA "):])
    assert isinstance(networks, list) and len(networks) == 1 and \
        networks[0].get("IPv4Addresses") == [srv_ip], (
            f"the server guest reports Networks {networks!r}; its ENI attachment IP is {srv_ip!r}"
        )

    # --- effect: both allowed clients reach the server on its ENI IP ---------------------------
    def ok_nonce(ps):
        return any(s == "OK" and d == nonce for _, s, d in ps)

    for label, stream in (("A", a_stream), ("B", b_stream)):
        _poll(lambda s=stream: _probes(ctx, log_group, s), ok_nonce, _LOG_TIMEOUT_S,
              what=f"client {label} fetching the nonce from {srv_ip}:{_PORT}")
    hits = _poll(lambda: {m[len("SRVHIT "):] for m in _log_messages(ctx, log_group, srv_stream)
                          if m.startswith("SRVHIT ")},
                 lambda h: {a_ip, b_ip} <= h, _LOG_TIMEOUT_S,
                 what="the server logging requests from both client ENI addresses")
    assert hits <= {a_ip, b_ip}, (
        f"the server saw requests from {sorted(hits)!r}; only clients {a_ip} and {b_ip} exist"
    )

    # --- effect-absent: revoke only A's rule -> A's SYNs are dropped, B unaffected --------------
    a_seen = max(p[0] for p in _probes(ctx, log_group, a_stream))
    ec2.revoke_security_group_ingress(GroupId=sg_srv, IpPermissions=_perm(sg_a))
    a_after = _poll(lambda: _after(_probes(ctx, log_group, a_stream), a_seen),
                    lambda ps: _fail_streak(ps) or any(s == "FAIL" and d != "timeout"
                                                       for _, s, d in ps),
                    _SG_EFFECT_TIMEOUT_S,
                    what=f"client A's probes failing after its ingress rule was revoked")
    wrong = [p for p in a_after if p[1] == "FAIL" and p[2] != "timeout"]
    assert not wrong, (
        f"with its rule revoked, client A's connections failed as {wrong[0]!r} rather than timing "
        f"out: a security group drops the SYN, it does not refuse the connection"
    )
    b_seen = max(p[0] for p in _probes(ctx, log_group, b_stream))
    b_after = _poll(lambda: _after(_probes(ctx, log_group, b_stream), b_seen),
                    lambda ps: len(ps) >= _STREAK, _LOG_TIMEOUT_S,
                    what="client B's probes after client A lost access")
    assert all(s == "OK" and d == nonce for _, s, d in b_after[:_STREAK]), (
        f"client B, whose rule was untouched, stopped reaching the server once A's rule was "
        f"revoked: {b_after[:_STREAK]!r}"
    )

    # --- restore A's rule -> A reaches the server again ----------------------------------------
    a_seen = max(p[0] for p in _probes(ctx, log_group, a_stream))
    ec2.authorize_security_group_ingress(GroupId=sg_srv, IpPermissions=_perm(sg_a))
    _poll(lambda: _after(_probes(ctx, log_group, a_stream), a_seen), ok_nonce,
          _SG_EFFECT_TIMEOUT_S, what="client A reaching the server again after re-authorization")


# ===== helpers =====
# Own VPC + IGW + one public subnet + one security group, all created here (no default VPC).
# Cleanup is registered immediately after each create and ordered so LIFO runs:
# stop task -> deregister task def -> delete cluster -> delete SG -> delete subnet -> delete
# IGW -> delete VPC -> delete log group -> delete roles. The slow half (tasks reaching STOPPED,
# ENIs released) is waited for IN BAND by _settle, because the engine gives teardown 60 s.

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK[:200]}


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
    name = ctx.unique_name(f"sim2real-deg-{label}-")
    net: dict = {"name": name, "subnet_cidr": "10.86.1.0/24", "tasks": []}
    vpc = ec2.create_vpc(CidrBlock="10.86.0.0/16", TagSpecifications=[
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

    net["az"] = _usable_zone(ec2)
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=net["subnet_cidr"],
                               AvailabilityZone=net["az"], TagSpecifications=[
                                   {"ResourceType": "subnet", "Tags": _ec2_tags(name)}])[
        "Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_subnet(SubnetId=subnet), _RELEASE_S))
    net["subnet"] = subnet

    sg = ec2.create_security_group(
        GroupName=name, Description="sim2real deep-ecs-guest-identity task SG", VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _ec2_tags(name)}])["GroupId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_security_group(GroupId=sg), _RELEASE_S))
    net["sg"] = sg
    return net


def _drain_enis(ctx, subnet: str, timeout_s: float) -> None:
    ec2 = ctx.client("ec2")
    _poll(
        lambda: ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet]}])["NetworkInterfaces"],
        lambda enis: not enis, timeout_s, 2, what=f"subnet {subnet} releasing its task ENIs")


def _settle(ctx, net: dict) -> None:
    """In-band teardown of the slow half: stop every task and wait for the subnet's ENIs to be
    released before the registered deletes run; a task or ENI that outlasts the wait raises,
    carrying any failure in flight."""
    found = sys.exc_info()[1]
    try:
        ecs = ctx.client("ecs")
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
            _drain_enis(ctx, net["subnet"], 300)
    except Exception as exc:
        raise AssertionError(
            (f"{found!r}; " if found else "") + f"teardown could not settle the tasks: {exc!r}"
        ) from exc


def _iam_role(ctx, kind: str, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-deg-{kind}-")
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
    # IAM propagation to the assuming service has no observable condition; the first task whose
    # launch races it is relaunched by _launch_running.
    return arn


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-deg-lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: _unless_gone(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _awslogs(group: str, region: str) -> dict:
    return {"logDriver": "awslogs", "options": {
        "awslogs-group": group, "awslogs-region": region, "awslogs-stream-prefix": "ecs"}}


def _create_cluster(ctx, net: dict) -> str:
    ecs = ctx.client("ecs")
    arn = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-deg-cl-"),
                             tags=_ecs_tags())["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ecs.delete_cluster(cluster=arn), _RELEASE_S))
    net["cluster"] = arn
    return arn


def _register_task_def(ctx, family, containers, exec_role, task_role=None, cpu="256",
                       memory="512") -> dict:
    ecs = ctx.client("ecs")
    kwargs = dict(family=family, containerDefinitions=containers,
                  requiresCompatibilities=["FARGATE"], networkMode="awsvpc", cpu=cpu,
                  memory=memory, executionRoleArn=exec_role, tags=_ecs_tags())
    if task_role:
        kwargs["taskRoleArn"] = task_role
    td = ecs.register_task_definition(**kwargs)["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return td


def _run_task(ctx, cluster, td_arn, net, sgs=None, overrides=None) -> str:
    ecs = ctx.client("ecs")
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:  # InvalidInput: the account already holds ECS's linked role
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise
    kwargs = dict(cluster=cluster, taskDefinition=td_arn, launchType="FARGATE", count=1,
                  tags=_ecs_tags(), networkConfiguration={"awsvpcConfiguration": {
                      "subnets": [net["subnet"]], "securityGroups": sgs or [net["sg"]],
                      "assignPublicIp": "ENABLED"}})
    if overrides:
        kwargs["overrides"] = overrides
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


def _launch_running(ctx, cluster, td_arn, net, timeout_s=120.0, **kw) -> tuple[str, dict]:
    """RunTask and await RUNNING, relaunching for up to timeout_s while the task fails to start
    before its container ran (a just-created execution role not yet usable by ECS)."""
    ecs = ctx.client("ecs")
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        arn = _run_task(ctx, cluster, td_arn, net, **kw)
        task = _poll(lambda: (ecs.describe_tasks(cluster=cluster, tasks=[arn]).get("tasks")
                              or [{}])[0],
                     lambda t: t.get("lastStatus") in ("RUNNING", "STOPPED"),
                     _TASK_RUNNING_TIMEOUT_S, what=f"task {arn} reaching RUNNING")
        never_ran = all(c.get("exitCode") is None for c in task.get("containers", []))
        if task.get("stopCode") != "TaskFailedToStart" or not never_ran or (
                time.monotonic() >= deadline):
            return arn, _await_task(ctx, cluster, arn, "RUNNING", _TASK_RUNNING_TIMEOUT_S)
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


def _eni_details(task: dict) -> dict:
    atts = [a for a in task.get("attachments", []) if a["type"] == "ElasticNetworkInterface"]
    assert len(atts) == 1, f"an awsvpc task has exactly one ENI attachment; got {atts!r}"
    return {d["name"]: d["value"] for d in atts[0]["details"]}


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


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
