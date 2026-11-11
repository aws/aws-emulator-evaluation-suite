"""deep-ecs-2-ec2place-distinct-instance-third-task-on-two-hosts-rejected."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-ecs-2-ec2place-distinct-instance-third-task-on-two-hosts-rejected"
GROUP = "ec2-placement"
SERVICES = ["ecs"]

# Reason on each failures[] entry when count exceeds the number of container instances.
_DISTINCT_UNSATISFIED = "DistinctInstance placement constraint unsatisfied."


@tags(
    "axis:rejection",
    "dp:api",
    "plane:data",
    "concern:data-plane",
    "concern:negative-classes",
    "cap:c3",
    "cap:c5",
)
def run(ctx) -> None:
    """distinctInstance binds on the EC2 launch type: with two container instances RunTask(count=2)
    places both on distinct hosts, while count=3 places exactly two and reports the third as one
    failures[] entry per host; ListTasks shows only the two placed tasks, which reach RUNNING."""
    ecs = ctx.client("ecs")
    cluster, hosts = _two_host_estate(ctx, ecs)
    host_arns = {h["ci_arn"] for h in hosts}

    td_arn = _register_td(
        ctx,
        ecs,
        "sim2real-behav-ecs-distinct-",
        [
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "cpu": 64,
                "memory": 64,
                "command": ["sh", "-c", "sleep 900"],
            }
        ],
    )
    constraint = [{"type": "distinctInstance"}]

    # Control: count equals the number of hosts.
    control_tag = ctx.unique_name("sim2real-ctl-")
    control = ecs.run_task(
        cluster=cluster,
        taskDefinition=td_arn,
        launchType="EC2",
        count=2,
        placementConstraints=constraint,
        startedBy=control_tag,
        tags=_ecs_tags(),
    )
    control_arns = [t["taskArn"] for t in control.get("tasks", [])]
    _stop_tasks_on_cleanup(ctx, ecs, cluster, control_arns)
    assert not control.get("failures"), (
        "count=2 with distinctInstance on a two-host cluster must place both tasks; a failure here "
        f"means the estate is broken and nothing below is evidence: {control.get('failures')!r}"
    )
    assert len(control_arns) == 2, f"expected 2 control tasks, got {control_arns!r}"
    control_hosts = {t["containerInstanceArn"] for t in control["tasks"]}
    assert control_hosts == host_arns, (
        f"distinctInstance count=2 must use BOTH hosts {sorted(host_arns)!r}, got "
        f"{sorted(control_hosts)!r}"
    )
    _wait_tasks(ecs, cluster, control_arns, "RUNNING", timeout_s=300)
    for arn in control_arns:
        ecs.stop_task(cluster=cluster, task=arn, reason="freeing hosts for the count=3 attempt")
    _wait_tasks(ecs, cluster, control_arns, "STOPPED", timeout_s=300)

    probe_tag = ctx.unique_name("sim2real-dst-")
    over = ecs.run_task(
        cluster=cluster,
        taskDefinition=td_arn,
        launchType="EC2",
        count=3,
        placementConstraints=constraint,
        startedBy=probe_tag,
        tags=_ecs_tags(),
    )
    placed = over.get("tasks", [])
    placed_arns = [t["taskArn"] for t in placed]
    # Registered BEFORE any assertion: if the target wrongly places three, all three must go.
    _stop_tasks_on_cleanup(ctx, ecs, cluster, placed_arns)
    assert len(placed) == 2, (
        "with two container instances, distinctInstance must cap RunTask(count=3) at exactly two "
        f"placed tasks, got {len(placed)}: "
        f"{[(t['taskArn'], t.get('containerInstanceArn')) for t in placed]!r}"
    )
    placed_hosts = [t["containerInstanceArn"] for t in placed]
    assert len(set(placed_hosts)) == 2 and set(placed_hosts) == host_arns, (
        f"the two placed tasks must be on two DIFFERENT hosts covering {sorted(host_arns)!r}, got "
        f"{placed_hosts!r}"
    )
    # The unplaceable task yields one failures[] entry per rejected host, each naming the host by
    # its short container-instance ARN (no cluster segment).
    failures = over.get("failures", [])
    failure_ids = sorted((f.get("arn") or "").rsplit("/", 1)[-1] for f in failures)
    host_ids = sorted(a.rsplit("/", 1)[-1] for a in host_arns)
    assert failure_ids == host_ids, (
        "the third task's refusal must list each rejected host exactly once: expected container "
        f"instance ids {host_ids!r}, got {failure_ids!r} (failures {failures!r})"
    )
    reasons = [f.get("reason") for f in failures]
    assert reasons == [_DISTINCT_UNSATISFIED] * len(host_ids), (
        f"every failures[] entry must carry reason {_DISTINCT_UNSATISFIED!r}, got {reasons!r}"
    )

    listed = _list_tasks_started_by(ecs, cluster, probe_tag)
    assert listed == set(placed_arns), (
        f"ListTasks(startedBy={probe_tag!r}) must show exactly the two placed tasks "
        f"{sorted(placed_arns)!r}, got {sorted(listed)!r}"
    )

    running = _wait_tasks(ecs, cluster, placed_arns, "RUNNING", timeout_s=300)
    running_hosts = {t["containerInstanceArn"] for t in running}
    assert running_hosts == host_arns, (
        f"the RUNNING tasks must sit on both hosts {sorted(host_arns)!r}, got {sorted(running_hosts)!r}"
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
    """Create an EC2-launch-type ECS cluster with two container instances in two AZs.

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
    """A dedicated VPC with one public subnet per zone, an IGW and a default route. The ECS agent
    needs egress to reach the ECS control plane and pull the public-ECR image. The VPC's own
    default security group admits all traffic between members, which is what lets one host reach
    another's mapped port."""
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
