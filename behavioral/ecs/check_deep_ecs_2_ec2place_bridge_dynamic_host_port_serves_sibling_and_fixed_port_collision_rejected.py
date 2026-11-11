"""deep-ecs-2-ec2place-bridge-dynamic-host-port-serves-sibling-and-fixed-port-collision-rejected."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-ecs-2-ec2place-bridge-dynamic-host-port-serves-sibling-and-fixed-port-collision-rejected"
GROUP = "ec2-placement"
SERVICES = ["ecs"]

_CONTAINER_PORT = 8080
# A fixed host port outside the ephemeral range the dynamic mapping draws from.
_FIXED_HOST_PORT = 8090

# Runs on the other host; exits 0 only if the body served at TARGET is exactly MARKER.
_CLIENT_SCRIPT = """
import os, sys, time, urllib.request
url = os.environ["TARGET"]
last = None
for _ in range(10):
    try:
        body = urllib.request.urlopen(url, timeout=10).read().decode()
        print("BODY=" + body, flush=True)
        sys.exit(0 if body == os.environ["MARKER"] else 3)
    except OSError as exc:
        last = exc
        time.sleep(3)
print("ERROR=" + repr(last), flush=True)
sys.exit(4)
"""


@tags(
    "axis:rejection",
    "dp:endpoint",
    "plane:data",
    "concern:data-plane",
    "concern:negative-classes",
    "cap:c3",
    "cap:c5",
)
def run(ctx) -> None:
    """A bridge hostPort:0 mapping gets a non-zero dynamic port a task on another host can reach,
    and a second task asking for an already-held fixed hostPort on the same host is refused with
    RESOURCE:PORTS while the identical task places on the other host.
    """
    logs = ctx.client("logs")
    ecs = ctx.client("ecs")
    cluster, hosts = _two_host_estate(ctx, ecs)
    by_arn = {h["ci_arn"]: h for h in hosts}

    marker = ctx.unique_name("sim2real-marker-")
    server_td = _register_td(
        ctx,
        ecs,
        "sim2real-behav-ecs-bridge-srv-",
        [
            {
                "name": "web",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "cpu": 64,
                "memory": 64,
                "environment": [{"name": "MARKER", "value": marker}],
                "command": [
                    "sh",
                    "-c",
                    f'mkdir -p /www && printf %s "$MARKER" > /www/index.html '
                    f"&& exec httpd -f -p {_CONTAINER_PORT} -h /www",
                ],
                "portMappings": [
                    {"containerPort": _CONTAINER_PORT, "hostPort": 0, "protocol": "tcp"}
                ],
            }
        ],
    )

    srv = ecs.run_task(
        cluster=cluster, taskDefinition=server_td, launchType="EC2", count=1, tags=_ecs_tags()
    )
    srv_arns = [t["taskArn"] for t in srv.get("tasks", [])]
    _stop_tasks_on_cleanup(ctx, ecs, cluster, srv_arns)
    assert len(srv_arns) == 1 and not srv.get("failures"), (
        f"the bridge server task must place: tasks={srv_arns!r} failures={srv.get('failures')!r}"
    )
    server = _wait_tasks(ctx, ecs, cluster, srv_arns, "RUNNING", timeout_s=300)[0]
    bindings = server["containers"][0].get("networkBindings") or []
    assert len(bindings) == 1, f"expected exactly one networkBinding, got {bindings!r}"
    host_port = bindings[0].get("hostPort")
    assert isinstance(host_port, int) and host_port != 0, (
        f"hostPort:0 must be replaced by a dynamically assigned NON-ZERO port, got {bindings!r}"
    )
    assert host_port != _CONTAINER_PORT, (
        f"the dynamic hostPort must come from the ephemeral range, not echo the containerPort: "
        f"{bindings!r}"
    )
    assert bindings[0].get("containerPort") == _CONTAINER_PORT and bindings[0].get("protocol") == "tcp", (
        f"the binding must map containerPort {_CONTAINER_PORT}/tcp, got {bindings!r}"
    )
    server_host = by_arn[server["containerInstanceArn"]]
    other_ci = next(a for a in by_arn if a != server["containerInstanceArn"])

    log_group = ctx.unique_name("sim2real-behav-ecs-bridge-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: _ignore_missing(lambda: logs.delete_log_group(logGroupName=log_group)))
    target = f"http://{server_host['private_ip']}:{host_port}/"
    client_td = _register_td(
        ctx,
        ecs,
        "sim2real-behav-ecs-bridge-cli-",
        [
            {
                "name": "client",
                "image": "public.ecr.aws/docker/library/python:3.12-alpine",
                "essential": True,
                "cpu": 64,
                "memory": 96,
                "environment": [
                    {"name": "TARGET", "value": target},
                    {"name": "MARKER", "value": marker},
                ],
                "command": ["python", "-c", _CLIENT_SCRIPT],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": log_group,
                        "awslogs-region": ctx.region,
                        "awslogs-stream-prefix": "client",
                    },
                },
            }
        ],
    )
    started = ecs.start_task(
        cluster=cluster, taskDefinition=client_td, containerInstances=[other_ci], tags=_ecs_tags()
    )
    cli_arns = [t["taskArn"] for t in started.get("tasks", [])]
    _stop_tasks_on_cleanup(ctx, ecs, cluster, cli_arns)
    assert len(cli_arns) == 1 and not started.get("failures"), (
        f"the sibling client must start on {other_ci!r}: tasks={cli_arns!r} "
        f"failures={started.get('failures')!r}"
    )
    done = _wait_tasks(ctx, ecs, cluster, cli_arns, "STOPPED", timeout_s=360)[0]
    container = done["containers"][0]
    task_id = cli_arns[0].rsplit("/", 1)[-1]
    stream = f"client/client/{task_id}"

    def _log_lines():
        try:
            events = logs.get_log_events(
                logGroupName=log_group, logStreamName=stream, startFromHead=True
            )["events"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return []
            raise
        return [e["message"] for e in events]

    lines = _poll_until(
        ctx,
        _log_lines,
        lambda ls: any(line.startswith(("BODY=", "ERROR=")) for line in ls),
        timeout_s=120,
        interval_s=2,
        description=f"the sibling client's output in {log_group}/{stream}",
    )
    assert container.get("exitCode") == 0, (
        f"GET {target} from the other host must return the marker: client exitCode "
        f"{container.get('exitCode')!r}, reason {container.get('reason')!r}, output {lines!r}"
    )
    assert f"BODY={marker}" in lines, (
        f"the body served through {target} must be exactly {marker!r}, client printed {lines!r}"
    )

    # Placement tracks fixed host ports, not dynamically assigned ones, so the collision uses two
    # tasks asking for the same fixed hostPort on one host.
    fixed_td = _register_td(
        ctx,
        ecs,
        "sim2real-behav-ecs-bridge-fixed-",
        [
            {
                "name": "fixed",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "cpu": 64,
                "memory": 64,
                "command": ["sh", "-c", f"exec httpd -f -p {_CONTAINER_PORT} -h /"],
                "portMappings": [
                    {"containerPort": _CONTAINER_PORT, "hostPort": _FIXED_HOST_PORT, "protocol": "tcp"}
                ],
            }
        ],
    )

    def _run_fixed_on(instance_id, started_by):
        resp = ecs.run_task(
            cluster=cluster,
            taskDefinition=fixed_td,
            launchType="EC2",
            count=1,
            placementConstraints=[
                {"type": "memberOf", "expression": f"ec2InstanceId == {instance_id}"}
            ],
            startedBy=started_by,
            tags=_ecs_tags(),
        )
        arns = [t["taskArn"] for t in resp.get("tasks", [])]
        # Registered BEFORE any assertion: a wrongly placed task must still be stopped.
        _stop_tasks_on_cleanup(ctx, ecs, cluster, arns)
        return resp, arns

    other_host = by_arn[other_ci]
    first, first_arns = _run_fixed_on(server_host["instance_id"], ctx.unique_name("sim2real-fx1-"))
    assert len(first_arns) == 1 and not first.get("failures"), (
        f"the first fixed-port task must place on {server_host['instance_id']}: "
        f"tasks={first_arns!r} failures={first.get('failures')!r}"
    )
    holder = _wait_tasks(ctx, ecs, cluster, first_arns, "RUNNING", timeout_s=300)[0]
    assert holder["containerInstanceArn"] == server["containerInstanceArn"], (
        f"memberOf must pin the first fixed-port task to the server host, got "
        f"{holder['containerInstanceArn']!r}"
    )
    holder_ports = [x.get("hostPort") for x in holder["containers"][0].get("networkBindings") or []]
    assert holder_ports == [_FIXED_HOST_PORT], (
        f"the first fixed-port task must bind hostPort {_FIXED_HOST_PORT}, got {holder_ports!r}"
    )

    collide_tag = ctx.unique_name("sim2real-col-")
    collide, collide_arns = _run_fixed_on(server_host["instance_id"], collide_tag)
    assert collide_arns == [], (
        f"a second task asking for fixed hostPort {_FIXED_HOST_PORT} on "
        f"{server_host['instance_id']} (already held) must NOT place, but got {collide_arns!r}"
    )
    failures = collide.get("failures", [])
    server_ci_id = server["containerInstanceArn"].rsplit("/", 1)[-1]
    on_server = [f for f in failures if (f.get("arn") or "").rsplit("/", 1)[-1] == server_ci_id]
    assert len(on_server) == 1 and on_server[0].get("reason") == "RESOURCE:PORTS", (
        f"the collision on the server host must be refused as RESOURCE:PORTS, got {failures!r}"
    )
    assert _list_tasks_started_by(ecs, cluster, collide_tag) == set(), (
        f"the refused RunTask must create no task under startedBy={collide_tag!r}"
    )

    # Positive control: the identical task on the other host places.
    control, control_arns = _run_fixed_on(other_host["instance_id"], ctx.unique_name("sim2real-fxc-"))
    assert len(control_arns) == 1 and not control.get("failures"), (
        f"the identical fixed-port task must place on the other host {other_host['instance_id']}: "
        f"tasks={control_arns!r} failures={control.get('failures')!r}"
    )
    ctl = _wait_tasks(ctx, ecs, cluster, control_arns, "RUNNING", timeout_s=300)[0]
    assert ctl["containerInstanceArn"] == other_ci, (
        f"the control must run on {other_ci!r}, got {ctl['containerInstanceArn']!r}"
    )
    ctl_ports = [x.get("hostPort") for x in ctl["containers"][0].get("networkBindings") or []]
    assert ctl_ports == [_FIXED_HOST_PORT], (
        f"the control task must bind the FIXED hostPort {_FIXED_HOST_PORT}, got {ctl_ports!r}"
    )


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_INSTANCE_TYPE = "t3.micro"
_ECS_AMI_PARAM = "/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
_ECS_INSTANCE_MANAGED_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
)


def _ecs_tags() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _ec2_tags() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


_MISSING_CODES = frozenset(
    {
        "ClusterNotFoundException",
        "ServiceNotFoundException",
        "ResourceNotFoundException",
        "NoSuchEntity",
        "InvalidInstanceID.NotFound",
        "InvalidInternetGatewayID.NotFound",
        "Gateway.NotAttached",
    }
)


def _ignore_missing(fn) -> None:
    """Run a teardown step; return only when its target is already gone, raise anything else."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _MISSING_CODES:
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll until predicate holds within timeout_s and the check's remaining budget; raise on timeout."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}; last observed {last!r}"
    )


def _describe_tasks(ecs, cluster, arns) -> list[dict]:
    out: list[dict] = []
    for i in range(0, len(arns), 100):
        out.extend(ecs.describe_tasks(cluster=cluster, tasks=arns[i : i + 100])["tasks"])
    return out


def _wait_tasks(ctx, ecs, cluster, arns, want, *, timeout_s) -> list[dict]:
    """Poll until every task in arns reports lastStatus == want; a task that STOPS while we
    wait for RUNNING fails immediately, quoting its stoppedReason."""

    def probe():
        described = _describe_tasks(ecs, cluster, list(arns))
        if want == "RUNNING":
            dead = [t for t in described if t.get("lastStatus") == "STOPPED"]
            if dead:
                raise AssertionError(
                    "a task stopped while waiting for RUNNING: "
                    f"{[(t['taskArn'], t.get('stopCode'), t.get('stoppedReason')) for t in dead]!r}"
                )
        return described

    return _poll_until(
        ctx,
        probe,
        lambda ts: len(ts) == len(arns) and all(t.get("lastStatus") == want for t in ts),
        timeout_s=timeout_s,
        interval_s=2,
        description=f"tasks {list(arns)!r} to reach {want}",
    )


def _list_tasks_started_by(ecs, cluster, started_by) -> set[str]:
    arns: set[str] = set()
    for desired in ("RUNNING", "PENDING", "STOPPED"):
        token = None
        while True:
            kwargs = {"cluster": cluster, "startedBy": started_by, "desiredStatus": desired}
            if token:
                kwargs["nextToken"] = token
            resp = ecs.list_tasks(**kwargs)
            arns.update(resp["taskArns"])
            token = resp.get("nextToken")
            if not token:
                break
    return arns


def _stop_tasks_on_cleanup(ctx, ecs, cluster, arns) -> None:
    for arn in list(arns):
        ctx.on_cleanup(
            lambda a=arn: _ignore_missing(
                lambda: ecs.stop_task(cluster=cluster, task=a, reason="behavioral-cleanup")
            )
        )


def _register_td(ctx, ecs, prefix, containers, network_mode="bridge") -> str:
    family = ctx.unique_name(prefix)
    td_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=containers,
        networkMode=network_mode,
        requiresCompatibilities=["EC2"],
        tags=_ecs_tags(),
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn])))
    ctx.on_cleanup(lambda: _ignore_missing(lambda: ecs.deregister_task_definition(taskDefinition=td_arn)))
    return td_arn


def _two_host_estate(ctx, ecs):
    """An EC2-launch-type ECS cluster with two container instances in two AZs, in its own VPC.

    Returns (cluster_name, hosts), each host a dict {ci_arn, instance_id, private_ip, az}.
    """
    ec2 = ctx.client("ec2")
    zones = _two_usable_zones(ec2)
    subnets, sg_id = _public_network(ctx, ec2, zones)
    profile_arn = _instance_profile(ctx)
    cluster = _create_cluster(ctx, ecs)
    hosts = _launch_hosts(ctx, ec2, ecs, cluster, subnets, sg_id, profile_arn)
    return cluster, hosts


def _two_usable_zones(ec2) -> list[str]:
    """Two available AZs that offer the instance type."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert len(usable) >= 2, (
        f"need two available AZs offering {_INSTANCE_TYPE!r}; usable were {usable!r}"
    )
    return usable[:2]


def _public_network(ctx, ec2, zones):
    """A VPC with one public subnet per zone and an IGW, so the ECS agent can reach ECS and ECR.
    The default security group admits traffic between members, so hosts reach each other's ports."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.199.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags()}],
    )["Vpc"]["VpcId"]
    subnet_ids: list[str] = []
    igw_holder: list[str] = []

    def _teardown_network():
        deadline = time.monotonic() + 600
        for sid in subnet_ids:
            while time.monotonic() < deadline:
                if not ec2.describe_network_interfaces(
                    Filters=[{"Name": "subnet-id", "Values": [sid]}]
                ).get("NetworkInterfaces", []):
                    break
                time.sleep(2)
            while time.monotonic() < deadline:
                try:
                    ec2.delete_subnet(SubnetId=sid)
                    break
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") == "InvalidSubnetID.NotFound":
                        break
                    time.sleep(2)
        for igw_id in igw_holder:
            _ignore_missing(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
            _ignore_missing(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
        while time.monotonic() < deadline:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidVpcID.NotFound":
                    return
                time.sleep(2)
        raise RuntimeError(
            f"vpc {vpc_id} / subnets {subnet_ids} not deleted within the teardown deadline"
        )

    ctx.on_cleanup(_teardown_network)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _ec2_tags()}]
    )["InternetGateway"]["InternetGatewayId"]
    igw_holder.append(igw_id)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    subnets = []
    for zone, cidr in zip(zones, ("10.199.0.0/25", "10.199.0.128/25")):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr,
            AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _ec2_tags()}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        subnets.append((sid, zone))
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
            "SecurityGroups"
        ]
        if sg["GroupName"] == "default"
    )
    return subnets, sg_id


def _instance_profile(ctx) -> str:
    """An IAM role + same-named instance profile carrying the ECS container-instance policy."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-ecsInstanceRole-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps(trust), Tags=_ec2_tags())
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_role(RoleName=role)))
    iam.attach_role_policy(RoleName=role, PolicyArn=_ECS_INSTANCE_MANAGED_POLICY)
    ctx.on_cleanup(
        lambda: _ignore_missing(
            lambda: iam.detach_role_policy(RoleName=role, PolicyArn=_ECS_INSTANCE_MANAGED_POLICY)
        )
    )
    iam.create_instance_profile(InstanceProfileName=role, Tags=_ec2_tags())
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_instance_profile(InstanceProfileName=role)))
    iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
    ctx.on_cleanup(
        lambda: _ignore_missing(
            lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role, RoleName=role)
        )
    )
    return iam.get_instance_profile(InstanceProfileName=role)["InstanceProfile"]["Arn"]


def _create_cluster(ctx, ecs) -> str:
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=_ecs_tags())

    def _delete_cluster():
        # Services deleted with force=True drain to INACTIVE asynchronously, and the cluster
        # refuses deletion until they have; retry on a bounded deadline.
        deadline = time.monotonic() + 300
        while True:
            try:
                ecs.delete_cluster(cluster=name)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ClusterNotFoundException":
                    return
                if time.monotonic() > deadline:
                    raise RuntimeError(f"ecs cluster {name} not deleted: {exc}") from exc
                time.sleep(2)

    ctx.on_cleanup(_delete_cluster)
    return name


def _try_run_instance(ec2, ami_id, profile_arn, subnet_id, sg_id, user_data, ctx):
    """RunInstances once; return the instance id on success or the ClientError on failure."""
    try:
        return ec2.run_instances(
            ImageId=ami_id,
            InstanceType=_INSTANCE_TYPE,
            MinCount=1,
            MaxCount=1,
            IamInstanceProfile={"Arn": profile_arn},
            SubnetId=subnet_id,
            SecurityGroupIds=[sg_id],
            UserData=base64.b64encode(user_data.encode()).decode(),
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": _ec2_tags()
                    + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ecs-ci-")}],
                },
                {"ResourceType": "volume", "Tags": _ec2_tags()},
            ],
        )["Instances"][0]["InstanceId"]
    except ClientError as exc:
        return exc


def _launch_hosts(ctx, ec2, ecs, cluster, subnets, sg_id, profile_arn) -> list[dict]:
    """Launch one EC2 host per subnet; each registers itself through the ECS agent."""
    ami_id = ctx.client("ssm").get_parameter(Name=_ECS_AMI_PARAM)["Parameter"]["Value"]
    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster} >> /etc/ecs/ecs.config\n"
    instance_ids: list[str] = []

    def _terminate_all():
        if not instance_ids:
            return
        try:
            ec2.terminate_instances(InstanceIds=list(instance_ids))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                return
            raise
        try:
            ec2.get_waiter("instance_terminated").wait(
                InstanceIds=list(instance_ids), WaiterConfig={"Delay": 2, "MaxAttempts": 180}
            )
        except Exception as exc:  # noqa: BLE001 - WaiterError carries the last state
            raise RuntimeError(f"instances {instance_ids} were not terminated: {exc!r}") from exc

    ctx.on_cleanup(_terminate_all)
    for subnet_id, _zone in subnets:
        # EC2's view of a new instance profile lags IAM, so RunInstances itself is retried.
        iid = _poll_until(
            ctx,
            lambda s=subnet_id: _try_run_instance(
                ec2, ami_id, profile_arn, s, sg_id, user_data, ctx
            ),
            lambda r: isinstance(r, str),
            timeout_s=180,
            interval_s=2,
            description="the freshly created instance profile becomes usable by RunInstances",
        )
        instance_ids.append(iid)

    def _registered():
        arns: list[str] = []
        token = None
        while True:
            kwargs = {"cluster": cluster}
            if token:
                kwargs["nextToken"] = token
            resp = ecs.list_container_instances(**kwargs)
            arns.extend(resp.get("containerInstanceArns", []))
            token = resp.get("nextToken")
            if not token:
                break
        if not arns:
            return {}
        return {
            ci["ec2InstanceId"]: ci
            for ci in ecs.describe_container_instances(cluster=cluster, containerInstances=arns)[
                "containerInstances"
            ]
            if ci.get("status") == "ACTIVE" and ci.get("agentConnected")
        }

    cis = _poll_until(
        ctx,
        _registered,
        lambda m: all(i in m for i in instance_ids),
        timeout_s=480,
        interval_s=2,
        description=f"EC2 instances {instance_ids!r} register as ACTIVE, connected container instances",
    )
    for iid in instance_ids:
        ci_arn = cis[iid]["containerInstanceArn"]
        ctx.on_cleanup(
            lambda a=ci_arn: _ignore_missing(
                lambda: ecs.deregister_container_instance(
                    cluster=cluster, containerInstance=a, force=True
                )
            )
        )
    described = {
        i["InstanceId"]: i
        for r in ec2.describe_instances(InstanceIds=instance_ids)["Reservations"]
        for i in r["Instances"]
    }
    hosts = [
        {
            "ci_arn": cis[iid]["containerInstanceArn"],
            "instance_id": iid,
            "private_ip": described[iid]["PrivateIpAddress"],
            "az": described[iid]["Placement"]["AvailabilityZone"],
        }
        for iid in instance_ids
    ]
    assert len({h["az"] for h in hosts}) == 2, f"hosts must be in two AZs, got {hosts!r}"
    return hosts


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
