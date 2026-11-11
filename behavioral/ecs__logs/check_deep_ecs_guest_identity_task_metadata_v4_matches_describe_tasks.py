"""deep-ecs-guest-identity-task-metadata-v4-matches-describe-tasks."""

from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import tarfile
import time

from behavioral_harness import tags

CHECK = "deep-ecs-guest-identity-task-metadata-v4-matches-describe-tasks"

GROUP = "guest-identity"

SERVICES = ["ecs", "logs"]


#: The guest program. It runs inside BOTH containers of the task, reads the task metadata
#: endpoint v4 the way every in-container SDK and agent does (the URI comes ONLY from the
#: environment ECS injected), and prints what it saw as one JSON line per endpoint. The
#: check never talks to the endpoint itself -- it is link-local to the task -- so the guest's
#: view reaches the check only as text in its own awslogs stream.
_GUEST = r"""
import json, os, sys, time, urllib.request
base = os.environ.get("ECS_CONTAINER_METADATA_URI_V4")
print("MDENV " + json.dumps({"ECS_CONTAINER_METADATA_URI_V4": base}), flush=True)
if not base:
    print("MDERR ECS_CONTAINER_METADATA_URI_V4 is not set", flush=True)
    time.sleep(900)
    sys.exit(3)
def get(path):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return json.loads(r.read())
task = {}
for _ in range(60):
    task = get("/task")
    if all(c.get("KnownStatus") == "RUNNING" for c in task.get("Containers", [])) and \
            len(task.get("Containers", [])) == 2:
        break
    time.sleep(2)
print("MDCONTAINER " + json.dumps(get(""), separators=(",", ":")), flush=True)
print("MDTASK " + json.dumps(task, separators=(",", ":")), flush=True)
time.sleep(900)
"""

_TASK_CPU, _TASK_MEMORY = "512", "1024"
_CONTAINERS = {"probe": ("256", "512"), "sibling": ("128", "256")}

_TASK_RUNNING_TIMEOUT_S = 600
_LOG_TIMEOUT_S = 420


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Both containers' task metadata endpoint v4 views match DescribeTasks of the RUNNING task:
    task identity, AZ, limits, container list, labels and ENI network; each `${URI}` answers with
    its own container, while both `${URI}/task` name the same task.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v4-fargate.html
    """
    ecs = ctx.client("ecs")
    net = _build_network(ctx, "tmd")
    try:
        _body(ctx, ecs, net)
    finally:
        _settle(ctx, net)


def _body(ctx, ecs, net) -> None:
    log_group = _create_log_group(ctx)
    exec_role = _iam_role(ctx, "tmd-exec", [
        {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"},
        {"Effect": "Allow", "Action": ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"], "Resource": "*"}])
    cluster_arn = _create_cluster(ctx, net)
    family = ctx.unique_name("sim2real-deg-tmd-")
    td = _register_task_def(ctx, family, [
        {
            "name": name,
            "image": _target_image(ctx, "python"),
            "essential": name == "probe",
            "cpu": int(cpu),
            "memory": int(mem),
            "command": ["python3", "-c", _GUEST],
            "logConfiguration": _awslogs(log_group, ctx.region),
        }
        for name, (cpu, mem) in _CONTAINERS.items()
    ], exec_role, cpu=_TASK_CPU, memory=_TASK_MEMORY)

    task_arn, running = _start_task(ctx, cluster_arn, td["taskDefinitionArn"], net, "RUNNING",
                                    _TASK_RUNNING_TIMEOUT_S)
    task_id = task_arn.rsplit("/", 1)[-1]

    seen = {}
    for name in _CONTAINERS:
        stream = f"ecs/{name}/{task_id}"
        lines = _poll(lambda s=stream: _log_messages(ctx, log_group, s),
                      lambda ms: any(m.startswith(("MDTASK ", "MDERR ")) for m in ms),
                      _LOG_TIMEOUT_S, what=f"the metadata probe's output in {stream}")
        assert not [m for m in lines if m.startswith("MDERR ")], (
            f"container {name!r} could not use the metadata endpoint: {lines!r}"
        )
        seen[name] = {
            "env": _tagged(lines, "MDENV ")["ECS_CONTAINER_METADATA_URI_V4"],
            "container": _tagged(lines, "MDCONTAINER "),
            "task": _tagged(lines, "MDTASK "),
        }

    # Re-read the task NOW, after both guests reported, so the comparison is between two views
    # of the same RUNNING task rather than against the first RUNNING snapshot.
    task = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
    assert task["lastStatus"] == "RUNNING", (
        f"the task left RUNNING while the guests were reporting: {task['lastStatus']!r} "
        f"stoppedReason={task.get('stoppedReason')!r}"
    )
    eni = _eni_details(task)
    api_containers = {c["name"]: c for c in task["containers"]}
    assert set(api_containers) == set(_CONTAINERS), (
        f"DescribeTasks lists containers {sorted(api_containers)!r}, expected "
        f"{sorted(_CONTAINERS)!r}"
    )

    for name, view in seen.items():
        uri = view["env"]
        assert isinstance(uri, str) and uri.startswith("http://"), (
            f"ECS_CONTAINER_METADATA_URI_V4 in {name!r} is not an http URL: {uri!r}"
        )
        md_task, md_self = view["task"], view["container"]

        # --- task identity -----------------------------------------------------------------
        assert md_task.get("TaskARN") == task["taskArn"] == task_arn, (
            f"{name!r} sees TaskARN {md_task.get('TaskARN')!r}; DescribeTasks says "
            f"{task['taskArn']!r}"
        )
        assert md_task.get("Family") == td["family"] == family, (
            f"{name!r} sees Family {md_task.get('Family')!r}; the task definition is "
            f"{td['family']!r}"
        )
        assert str(md_task.get("Revision")) == str(td["revision"]), (
            f"{name!r} sees Revision {md_task.get('Revision')!r}; the registered revision is "
            f"{td['revision']!r}"
        )
        assert task["taskDefinitionArn"].endswith(f"/{family}:{md_task.get('Revision')}"), (
            f"the guest's family:revision {family}:{md_task.get('Revision')} does not name the "
            f"task definition DescribeTasks reports, {task['taskDefinitionArn']!r}"
        )
        assert md_task.get("Cluster") == task["clusterArn"] == cluster_arn, (
            f"{name!r} sees Cluster {md_task.get('Cluster')!r}; DescribeTasks says "
            f"{task['clusterArn']!r}"
        )
        assert md_task.get("AvailabilityZone") == task["availabilityZone"] == net["az"], (
            f"{name!r} sees AvailabilityZone {md_task.get('AvailabilityZone')!r}; DescribeTasks "
            f"says {task['availabilityZone']!r}; the task's only subnet is in {net['az']!r}"
        )
        assert md_task.get("LaunchType") == task["launchType"] == "FARGATE", (
            f"{name!r} sees LaunchType {md_task.get('LaunchType')!r}; DescribeTasks says "
            f"{task['launchType']!r}"
        )
        limits = md_task.get("Limits") or {}
        assert limits.get("CPU") is not None and round(float(limits["CPU"]) * 1024) == int(
            task["cpu"]) == int(_TASK_CPU), (
            f"{name!r} sees task Limits.CPU {limits.get('CPU')!r} vCPU; DescribeTasks cpu is "
            f"{task['cpu']!r} units (requested {_TASK_CPU})"
        )
        assert limits.get("Memory") is not None and int(limits["Memory"]) == int(
            task["memory"]) == int(_TASK_MEMORY), (
            f"{name!r} sees task Limits.Memory {limits.get('Memory')!r} MiB; DescribeTasks memory "
            f"is {task['memory']!r} (requested {_TASK_MEMORY})"
        )

        # --- the container list --------------------------------------------------------------
        md_containers = {c.get("Name"): c for c in md_task.get("Containers", [])}
        assert set(md_containers) == set(api_containers), (
            f"{name!r} sees containers {sorted(md_containers)!r}; DescribeTasks lists "
            f"{sorted(api_containers)!r}"
        )
        for cname, api_c in api_containers.items():
            md_c = md_containers[cname]
            want_cpu, want_mem = _CONTAINERS[cname]
            assert md_c.get("DockerId") == api_c.get("runtimeId"), (
                f"{name!r} sees {cname}.DockerId {md_c.get('DockerId')!r}; DescribeTasks "
                f"runtimeId is {api_c.get('runtimeId')!r}"
            )
            assert md_c.get("ContainerARN") == api_c.get("containerArn"), (
                f"{name!r} sees {cname}.ContainerARN {md_c.get('ContainerARN')!r}; DescribeTasks "
                f"containerArn is {api_c.get('containerArn')!r}"
            )
            assert md_c.get("Image") == api_c.get("image") == _target_image(ctx, "python"), (
                f"{name!r} sees {cname}.Image {md_c.get('Image')!r}; DescribeTasks image is "
                f"{api_c.get('image')!r}"
            )
            c_limits = md_c.get("Limits") or {}
            assert int(c_limits.get("CPU", -1)) == int(api_c.get("cpu", -2)) == int(want_cpu), (
                f"{name!r} sees {cname}.Limits.CPU {c_limits.get('CPU')!r}; DescribeTasks cpu is "
                f"{api_c.get('cpu')!r} (defined {want_cpu})"
            )
            assert int(c_limits.get("Memory", -1)) == int(api_c.get("memory", -2)) == int(
                want_mem), (
                f"{name!r} sees {cname}.Limits.Memory {c_limits.get('Memory')!r}; DescribeTasks "
                f"memory is {api_c.get('memory')!r} (defined {want_mem})"
            )
            labels = md_c.get("Labels") or {}
            assert labels.get("com.amazonaws.ecs.task-arn") == task_arn and labels.get(
                "com.amazonaws.ecs.container-name") == cname and labels.get(
                "com.amazonaws.ecs.cluster") == cluster_arn and labels.get(
                "com.amazonaws.ecs.task-definition-family") == family and str(labels.get(
                    "com.amazonaws.ecs.task-definition-version")) == str(td["revision"]), (
                f"{name!r} sees {cname}'s ECS labels {labels!r}; expected task-arn {task_arn!r}, "
                f"container-name {cname!r}, cluster {cluster_arn!r}, family {family!r}, "
                f"version {td['revision']!r}"
            )

        # --- the per-container endpoint is scoped to the caller -----------------------------
        assert md_self.get("Name") == name, (
            f"container {name!r}'s own ${{URI}} answered as {md_self.get('Name')!r} -- the "
            f"per-container endpoint is not scoped to the container that asked"
        )
        assert md_self.get("DockerId") == api_containers[name]["runtimeId"], (
            f"container {name!r}'s own ${{URI}} reports DockerId {md_self.get('DockerId')!r}; "
            f"DescribeTasks says its runtimeId is {api_containers[name]['runtimeId']!r}"
        )

        # --- the network the guest believes it has is the task's own ENI --------------------
        nets = md_self.get("Networks") or []
        assert len(nets) == 1 and nets[0].get("NetworkMode") == "awsvpc", (
            f"{name!r} reports Networks {nets!r}; an awsvpc task has exactly one awsvpc network"
        )
        guest_net = nets[0]
        assert guest_net.get("IPv4Addresses") == [eni["privateIPv4Address"]], (
            f"{name!r} reports IPv4Addresses {guest_net.get('IPv4Addresses')!r}; the task's ENI "
            f"attachment privateIPv4Address is {eni['privateIPv4Address']!r}"
        )
        assert api_containers[name]["networkInterfaces"][0]["privateIpv4Address"] == (
            eni["privateIPv4Address"]), (
            f"DescribeTasks' own container view {api_containers[name]['networkInterfaces']!r} "
            f"disagrees with its attachment {eni!r}"
        )
        assert str(guest_net.get("MACAddress", "")).lower() == eni["macAddress"].lower(), (
            f"{name!r} reports MACAddress {guest_net.get('MACAddress')!r}; the ENI attachment "
            f"macAddress is {eni['macAddress']!r}"
        )
        assert guest_net.get("IPv4SubnetCIDRBlock") == net["subnet_cidr"], (
            f"{name!r} reports IPv4SubnetCIDRBlock {guest_net.get('IPv4SubnetCIDRBlock')!r}; "
            f"the task's subnet {net['subnet']} was created as {net['subnet_cidr']!r}"
        )
        assert eni["subnetId"] == net["subnet"], (
            f"the ENI attachment names subnet {eni['subnetId']!r}; the task was placed in "
            f"{net['subnet']!r}"
        )

    # Both guests name one task, but each saw ITS OWN DockerId: two distinct identities.
    assert seen["probe"]["container"]["DockerId"] != seen["sibling"]["container"]["DockerId"], (
        f"both containers' own metadata named the same DockerId "
        f"{seen['probe']['container']['DockerId']!r}"
    )
    assert seen["probe"]["env"] != seen["sibling"]["env"], (
        f"both containers were handed the same metadata URI {seen['probe']['env']!r}; v4 URIs "
        f"are per container"
    )
    assert running["taskArn"] == task_arn


def _tagged(lines: list[str], prefix: str) -> dict:
    hits = [m[len(prefix):] for m in lines if m.startswith(prefix)]
    assert hits, f"no {prefix.strip()} line in the guest output {lines!r}"
    return json.loads(hits[-1])


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


def _swallow(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - best-effort teardown / probe
        return None


def _poll(probe, predicate, timeout_s, interval_s=2.0, what="condition"):
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


def _retry_delete(fn, attempts=4, interval_s=5.0):
    """Delete with retries: an ENI or a stopping task can hold a dependency for a while."""
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code.endswith("NotFound") or code in ("ClusterNotFoundException",):
                return
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
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    net["vpc"] = vpc
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})

    igw = ec2.create_internet_gateway(TagSpecifications=[
        {"ResourceType": "internet-gateway", "Tags": _ec2_tags(name)}])[
        "InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _swallow(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc))
        _retry_delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw))

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
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    net["subnet"] = subnet

    sg = ec2.create_security_group(
        GroupName=name, Description="sim2real deep-ecs-guest-identity task SG", VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _ec2_tags(name)}])["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg)))
    net["sg"] = sg
    return net


def _drain_enis(ctx, subnet: str, timeout_s: float) -> None:
    ec2 = ctx.client("ec2")
    _swallow(lambda: _poll(
        lambda: ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet]}])["NetworkInterfaces"],
        lambda enis: not enis, timeout_s, 10, what=f"subnet {subnet} releasing its task ENIs"))


def _settle(ctx, net: dict) -> None:
    """In-band teardown of the slow half, run from the body's `finally`: a Fargate task takes longer
    than the 60 s cleanup bound to stop and release its ENI. Never raises, so it cannot mask the
    body's failure."""
    ecs = ctx.client("ecs")
    tasks, cluster = list(net.get("tasks", [])), net.get("cluster")
    for t in tasks:
        _swallow(lambda t=t: ecs.stop_task(cluster=cluster, task=t, reason="sim2real teardown"))
    if tasks:
        _swallow(lambda: _poll(
            lambda: [x["lastStatus"] for x in ecs.describe_tasks(
                cluster=cluster, tasks=tasks)["tasks"]],
            lambda ss: len(ss) == len(tasks) and all(x == "STOPPED" for x in ss), 300, 5,
            what="every task this check started reaching STOPPED"))
    if net.get("subnet"):
        _drain_enis(ctx, net["subnet"], 300)


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
        _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        _swallow(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_drop)
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    _poll(lambda: _swallow(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
          lambda r: r is not None, 60, 2, what=f"role {name} inline policy readable")
    return arn


#: Bound for a fresh execution role to become usable by ECS.
_IAM_PROPAGATION_S = 120.0


def _deadline(ctx, budget_s):
    """A monotonic deadline `budget_s` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (budget_s if left is None else min(budget_s, max(0.0, left - 5)))


def _role_not_yet_usable(task):
    """A start failure from the execution role not yet usable: unassumable or a grant denied."""
    reason = task.get("stoppedReason") or ""
    return task.get("stopCode") == "TaskFailedToStart" and (
        "unable to assume" in reason.lower() or "is not authorized to perform" in reason)


def _start_task(ctx, cluster, td_arn, net, status, timeout_s):
    """RunTask, rerun while the task fails to start on the fresh role; return (arn, task)."""
    ecs = ctx.client("ecs")
    deadline = _deadline(ctx, _IAM_PROPAGATION_S)
    while True:
        arn = _run_task(ctx, cluster, td_arn, net)
        task = _poll(lambda: (ecs.describe_tasks(cluster=cluster, tasks=[arn]).get("tasks")
                              or [{}])[0],
                     lambda t: t.get("lastStatus") in (status, "STOPPED"), timeout_s,
                     what=f"task {arn} reaching {status}")
        if not _role_not_yet_usable(task) or time.monotonic() >= deadline:
            return arn, _await_task(ctx, cluster, arn, status, timeout_s)
        time.sleep(2)


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-deg-lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: _swallow(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _awslogs(group: str, region: str) -> dict:
    return {"logDriver": "awslogs", "options": {
        "awslogs-group": group, "awslogs-region": region, "awslogs-stream-prefix": "ecs"}}


def _create_cluster(ctx, net: dict) -> str:
    ecs = ctx.client("ecs")
    arn = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-deg-cl-"),
                             tags=_ecs_tags())["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ecs.delete_cluster(cluster=arn)))
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
    _swallow(lambda: ctx.client("iam").create_service_linked_role(
        AWSServiceName="ecs.amazonaws.com"))
    kwargs = dict(cluster=cluster, taskDefinition=td_arn, launchType="FARGATE", count=1,
                  tags=_ecs_tags(), networkConfiguration={"awsvpcConfiguration": {
                      "subnets": [net["subnet"]], "securityGroups": sgs or [net["sg"]],
                      "assignPublicIp": "ENABLED"}})
    if overrides:
        kwargs["overrides"] = overrides
    deadline = _deadline(ctx, _IAM_PROPAGATION_S)
    while True:  # a just-created role may not be assumable by ECS yet
        try:
            resp = ecs.run_task(**kwargs)
            break
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            msg = str(exc).lower()
            role_not_ready = (
                (code == "InvalidParameterException" and "role" in msg)
                or (code == "ClientException" and "unable to assume the role" in msg)
            )
            if not role_not_ready or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    assert resp["failures"] == [], f"RunTask failures: {resp['failures']!r}"
    arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.stop_task(cluster=cluster, task=arn)))
    net["tasks"].append(arn)
    return arn


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
        page = _swallow(lambda: logs.get_log_events(**kwargs))
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


# ===== target-sourced container image (self-contained) =====
#: Images the tasks run: the reference, its linux/amd64 image ID (the config digest), and the file
#: the runner pre-seeds it as with `docker save`. The check never pulls from a registry.
_SEED_IMAGES = {
    "python": (
        "public.ecr.aws/docker/library/python:3.12-alpine",
        "sha256:f4b7b8044a873fcc0f348549a19b9075cd77bd56ead7177192cfec38d85bce4a",
        "python-3.12-alpine.tar",
    ),
}
_SEED_DIR = pathlib.Path.home() / ".cache" / "sim2real" / "images"
_LAYER_PART_BYTES = 8 * 1024 * 1024
_PUSHED: dict[tuple[int, str], tuple[object, str]] = {}


def _seeded_image(key: str) -> tuple[bytes, list[bytes]]:
    """The pre-seeded image's config and gzip layers, verified against its pinned image ID.

    A runner without the archive, or with one holding another image, is a runner fault:
    ``tool_missing``, never a finding about the target.
    """
    from fidelity_tests_runner import RequiredToolMissing

    ref, image_id, archive_name = _SEED_IMAGES[key]
    path = _SEED_DIR / archive_name
    need = (
        f"{ref} ({image_id}) saved at {path}; pre-seed it with `docker pull --platform "
        f"linux/amd64 {ref} && docker save {ref} -o {path}`"
    )
    try:
        with tarfile.open(path) as archive:
            entry = json.load(archive.extractfile("manifest.json"))[0]
            config = archive.extractfile(entry["Config"]).read()
            raw = [archive.extractfile(name).read() for name in entry["Layers"]]
        plain = [gzip.decompress(b) if b[:2] == b"\x1f\x8b" else b for b in raw]
        recorded = json.loads(config).get("rootfs", {}).get("diff_ids")
    except (OSError, EOFError, tarfile.TarError, KeyError, IndexError, ValueError, TypeError,
            AttributeError) as exc:
        raise RequiredToolMissing([f"{need} ({type(exc).__name__}: {exc})"]) from None
    diff_ids = ["sha256:" + hashlib.sha256(b).hexdigest() for b in plain]
    if "sha256:" + hashlib.sha256(config).hexdigest() != image_id or recorded != diff_ids:
        raise RequiredToolMissing([f"{need} (the archive there holds another image)"])
    return config, [gzip.compress(b, compresslevel=1, mtime=0) for b in plain]


def _target_image(ctx, key: str = "python") -> str:
    """The URI of the pre-seeded image in an ECR repository this check creates, pushed once.

    Every blob goes through the target's own ECR layer-upload API (InitiateLayerUpload,
    UploadLayerPart, CompleteLayerUpload, PutImage), so the task's image comes from the target.
    """
    hit = _PUSHED.get((id(ctx), key))
    if hit and hit[0] is ctx:
        return hit[1]
    config, layers = _seeded_image(key)
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-img-").lower()
    repo = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    descriptors = []
    for blob in [config, *layers]:
        digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
        for first in range(0, len(blob), _LAYER_PART_BYTES):
            part = blob[first:first + _LAYER_PART_BYTES]
            ecr.upload_layer_part(
                repositoryName=name, uploadId=upload_id, partFirstByte=first,
                partLastByte=first + len(part) - 1, layerPartBlob=part,
            )
        ecr.complete_layer_upload(repositoryName=name, uploadId=upload_id, layerDigests=[digest])
        descriptors.append({"size": len(blob), "digest": digest})
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json", **descriptors[0]},
        "layers": [
            {"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", **d}
            for d in descriptors[1:]
        ],
    }
    ecr.put_image(
        repositoryName=name, imageManifest=json.dumps(manifest), imageTag="seeded",
        imageManifestMediaType=manifest["mediaType"],
    )
    uri = f"{repo['repositoryUri']}:seeded"
    _PUSHED[(id(ctx), key)] = (ctx, uri)
    return uri
# ===== end target-sourced container image =====


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
