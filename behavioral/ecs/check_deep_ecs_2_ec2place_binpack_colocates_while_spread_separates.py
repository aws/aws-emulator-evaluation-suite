"""deep-ecs-2-ec2place-binpack-colocates-while-spread-separates."""
from __future__ import annotations

import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-ecs-2-ec2place-binpack-colocates-while-spread-separates"
GROUP = "ec2-placement"
SERVICES = ["ecs"]

_BINPACK_MEM = 256
_SPREAD_MEM = 128


@tags("dp:api", "plane:data", "concern:data-plane", "axis:happy-path", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """Two services created together on two hosts, binpack(memory) and spread(instanceId), each
    desiredCount=2: binpack co-locates its tasks on ONE host while spread uses BOTH hosts.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-placement-strategies.html
    """
    ecs = ctx.client("ecs")
    cluster, hosts = _two_host_estate(ctx, ecs)
    host_arns = {h["ci_arn"] for h in hosts}

    # Both strategies are best-effort; with room for all four tasks on either host, capacity cannot
    # force binpack to split. binpack's tasks are larger, so its first host stays the fuller one.
    need = 2 * _BINPACK_MEM + 2 * _SPREAD_MEM
    for ci in ecs.describe_container_instances(cluster=cluster, containerInstances=sorted(host_arns))[
        "containerInstances"
    ]:
        free = {r["name"]: r.get("integerValue") for r in ci["remainingResources"]}
        assert (free.get("MEMORY") or 0) >= need, (
            f"precondition: host {ci['containerInstanceArn']!r} must have >= {need} MiB free so "
            f"neither strategy is capacity-constrained, has {free!r}"
        )

    def _td(prefix, mem):
        return _register_td(
            ctx,
            ecs,
            prefix,
            [
                {
                    "name": "app",
                    "image": "public.ecr.aws/docker/library/busybox:1.36",
                    "essential": True,
                    "cpu": 64,
                    "memory": mem,
                    "command": ["sh", "-c", "sleep 1800"],
                }
            ],
        )

    td_binpack = _td("sim2real-behav-ecs-binpack-", _BINPACK_MEM)
    td_spread = _td("sim2real-behav-ecs-spread-", _SPREAD_MEM)
    svc_binpack = ctx.unique_name("sim2real-binpack-")
    svc_spread = ctx.unique_name("sim2real-spread-")
    for svc in (svc_binpack, svc_spread):
        ctx.on_cleanup(
            lambda s=svc: _ignore_missing(lambda: ecs.delete_service(cluster=cluster, service=s, force=True))
        )

    def _create(name, td, strategy):
        return ecs.create_service(
            cluster=cluster,
            serviceName=name,
            taskDefinition=td,
            desiredCount=2,
            launchType="EC2",
            placementStrategy=strategy,
            tags=_ecs_tags(),
        )["service"]

    # Both services at essentially the same instant, so the two schedulers compete for the hosts.
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_bin = pool.submit(_create, svc_binpack, td_binpack, [{"type": "binpack", "field": "memory"}])
        f_spr = pool.submit(_create, svc_spread, td_spread, [{"type": "spread", "field": "instanceId"}])
        created = {svc_binpack: f_bin.result(), svc_spread: f_spr.result()}
    # CreateService normalises binpack's field to upper case ("MEMORY").
    assert created[svc_binpack]["placementStrategy"] == [{"type": "binpack", "field": "MEMORY"}], (
        f"binpack service must echo its strategy, got {created[svc_binpack].get('placementStrategy')!r}"
    )
    assert created[svc_spread]["placementStrategy"] == [{"type": "spread", "field": "instanceId"}], (
        f"spread service must echo its strategy, got {created[svc_spread].get('placementStrategy')!r}"
    )

    def _steady():
        svcs = ecs.describe_services(cluster=cluster, services=[svc_binpack, svc_spread])["services"]
        return {s["serviceName"]: (s["runningCount"], s["pendingCount"]) for s in svcs}

    _poll_until(
        _steady,
        lambda m: m.get(svc_binpack) == (2, 0) and m.get(svc_spread) == (2, 0),
        timeout_s=420,
        interval_s=10,
        description="both services reach runningCount=2, pendingCount=0",
    )

    def _hosts_of(service):
        arns = []
        token = None
        while True:
            kwargs = {"cluster": cluster, "serviceName": service, "desiredStatus": "RUNNING"}
            if token:
                kwargs["nextToken"] = token
            resp = ecs.list_tasks(**kwargs)
            arns.extend(resp["taskArns"])
            token = resp.get("nextToken")
            if not token:
                break
        tasks = _wait_tasks(ecs, cluster, arns, "RUNNING", timeout_s=120)
        return [t["containerInstanceArn"] for t in tasks]

    binpack_hosts = _hosts_of(svc_binpack)
    spread_hosts = _hosts_of(svc_spread)
    assert len(binpack_hosts) == 2 and len(spread_hosts) == 2, (
        f"each service must have exactly 2 RUNNING tasks: binpack={binpack_hosts!r} "
        f"spread={spread_hosts!r}"
    )
    assert set(binpack_hosts) <= host_arns and set(spread_hosts) <= host_arns, (
        f"tasks must be on this cluster's hosts {sorted(host_arns)!r}: binpack={binpack_hosts!r} "
        f"spread={spread_hosts!r}"
    )
    # The differential, both halves on the same hosts at the same moment.
    assert len(set(spread_hosts)) == 2, (
        f"spread(instanceId) with 2 tasks over 2 hosts must use BOTH hosts, got {spread_hosts!r} "
        f"(binpack placed {binpack_hosts!r})"
    )
    assert len(set(binpack_hosts)) == 1, (
        f"binpack(memory) with room for both tasks on either host must CO-LOCATE them, got "
        f"{binpack_hosts!r} (spread placed {spread_hosts!r})"
    )


# ===== helpers =====

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


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}; last observed {last!r}"
    )


def _describe_tasks(ecs, cluster, arns) -> list[dict]:
    out: list[dict] = []
    for i in range(0, len(arns), 100):
        out.extend(ecs.describe_tasks(cluster=cluster, tasks=arns[i : i + 100])["tasks"])
    return out


def _wait_tasks(ecs, cluster, arns, want, *, timeout_s) -> list[dict]:
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
        probe,
        lambda ts: len(ts) == len(arns) and all(t.get("lastStatus") == want for t in ts),
        timeout_s=timeout_s,
        interval_s=5,
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
    """An EC2-launch-type ECS cluster with two container instances in two AZs, in a dedicated VPC.

    Returns (cluster_name, hosts); each host is {ci_arn, instance_id, private_ip, az}.
    """
    ec2 = ctx.client("ec2")
    zones = _two_usable_zones(ec2)
    subnets, sg_id = _public_network(ctx, ec2, zones)
    profile_arn = _instance_profile(ctx)
    cluster = _create_cluster(ctx, ecs)
    hosts = _launch_hosts(ctx, ec2, ecs, cluster, subnets, sg_id, profile_arn)
    return cluster, hosts


def _two_usable_zones(ec2) -> list[str]:
    """Two available AZs that offer the instance type — derived, never hardcoded."""
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
    """A dedicated VPC with one public subnet per zone, an IGW and a default route.
    The ECS agent needs egress to reach the ECS control plane and pull the public-ECR image."""
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
                time.sleep(10)
            while time.monotonic() < deadline:
                try:
                    ec2.delete_subnet(SubnetId=sid)
                    break
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") == "InvalidSubnetID.NotFound":
                        break
                    time.sleep(10)
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
                time.sleep(10)
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
                time.sleep(10)

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
    """Launch one EC2 host per subnet; each self-registers via the real ECS agent.
    RegisterContainerInstance validates a genuine instance-identity document, so a real instance
    is the only way to get a container instance."""
    ami_id = ctx.client("ssm").get_parameter(Name=_ECS_AMI_PARAM)["Parameter"]["Value"]
    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster} >> /etc/ecs/ecs.config\n"
    instance_ids: list[str] = []

    def _terminate_all():
        if not instance_ids:
            return
        _ignore_missing(lambda: ec2.terminate_instances(InstanceIds=list(instance_ids)))
        _ignore_missing(
            lambda: ec2.get_waiter("instance_terminated").wait(
                InstanceIds=list(instance_ids), WaiterConfig={"Delay": 2, "MaxAttempts": 180}
            )
        )

    ctx.on_cleanup(_terminate_all)
    for subnet_id, _zone in subnets:
        # The instance profile was just created; EC2's view of it lags IAM, so retry RunInstances
        # itself rather than sleeping. Raises if it never becomes launchable.
        iid = _poll_until(
            lambda s=subnet_id: _try_run_instance(
                ec2, ami_id, profile_arn, s, sg_id, user_data, ctx
            ),
            lambda r: isinstance(r, str),
            timeout_s=180,
            interval_s=10,
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
        _registered,
        lambda m: all(i in m for i in instance_ids),
        timeout_s=480,
        interval_s=10,
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
