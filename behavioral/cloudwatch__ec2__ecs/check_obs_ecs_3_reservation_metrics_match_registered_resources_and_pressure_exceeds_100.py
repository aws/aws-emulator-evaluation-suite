"""obs-ecs-3-reservation-metrics-match-registered-resources-and-pressure-exceeds-100."""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "obs-ecs-3-reservation-metrics-match-registered-resources-and-pressure-exceeds-100"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "ec2", "ecs"]

_VPC_CIDR = "10.96.0.0/16"
_SUBNET_CIDR = "10.96.1.0/24"
_INSTANCE_TYPE = "t3.micro"
_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_AMI_PARAM = "/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
_TASK_A_CPU = 256
_TASK_A_MEM = 256
# Percentage points. Both sides of the ratio are integers ECS itself reports, so the only slack
# needed is float rounding in the published value (measured: 27.94759825327511 published for
# 256/916, i.e. exact to the last digit).
_TOLERANCE_PP = 0.05
_METRIC_BUDGET_S = 600.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonECS/latest/developerguide/available-metrics.html
@tags("axis:happy-path", "cap:c3", "concern:metrics", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """On an EC2 capacity-provider cluster, AWS/ECS MemoryReservation and CPUReservation equal the
    task's share of the instance's REGISTERED resources, and CapacityProviderReservation reads 100
    with one placed task, then exceeds 100 once a second task cannot be placed."""
    ec2 = ctx.client("ec2")
    ecs = ctx.client("ecs")
    asg = ctx.client("autoscaling")
    cw = ctx.client("cloudwatch")

    _ensure_ecs_slr(ctx)
    subnet, sg = _public_network(ctx, ec2)
    role_name = _instance_role(ctx)
    profile = _instance_profile(ctx, role_name)

    cluster = ctx.unique_name("sim2real-xsvc-obs3-")
    ecs.create_cluster(clusterName=cluster, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    cluster_created = datetime.now(timezone.utc)

    ami = ctx.client("ssm").get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AMI_PARAM} resolved to {ami!r}"
    lt_name = _launch_template(ctx, ec2, ami, cluster, profile, sg)
    asg_name, asg_arn = _create_asg(ctx, asg, lt_name, subnet)

    cp_name = ctx.unique_name("sim2real-xsvc-obs3-cp-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {"status": "ENABLED", "targetCapacity": 100,
                               "minimumScalingStepSize": 1, "maximumScalingStepSize": 1,
                               "instanceWarmupPeriod": 60},
            "managedTerminationProtection": "DISABLED",
        },
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_capacity_provider(ecs, cp_name))
    _associate(ecs, cluster, cp_name)
    ctx.on_cleanup(lambda: _disassociate(ecs, cluster))

    # --- The consumer: ECS bound a target-tracking policy on the ASG to the reservation metric.
    policy = _poll_until(
        lambda: [p for p in asg.describe_policies(AutoScalingGroupName=asg_name)["ScalingPolicies"]
                 if p.get("PolicyType") == "TargetTrackingScaling"],
        lambda ps: len(ps) == 1, timeout_s=300.0, interval_s=10.0,
        description=f"ECS creating its target-tracking policy on {asg_name}",
    )[0]
    ttc = policy["TargetTrackingConfiguration"]
    spec = ttc.get("CustomizedMetricSpecification") or {}
    assert spec.get("Namespace") == "AWS/ECS/ManagedScaling", f"policy metric spec {spec!r}"
    assert spec.get("MetricName") == "CapacityProviderReservation", f"policy metric spec {spec!r}"
    dims = {d["Name"]: d["Value"] for d in spec.get("Dimensions", [])}
    assert dims == {"CapacityProviderName": cp_name, "ClusterName": cluster}, (
        f"policy metric dimensions {dims!r}, expected CapacityProviderName={cp_name!r} and "
        f"ClusterName={cluster!r}"
    )
    assert ttc.get("TargetValue") == 100.0, f"policy TargetValue {ttc.get('TargetValue')!r}"

    td_a = _register_task_def(ctx, ecs, "a", cpu=_TASK_A_CPU, memory=_TASK_A_MEM)
    tasks: list[str] = []
    ctx.on_cleanup(lambda: _stop_tasks(ecs, cluster, tasks))
    task_a = _run_task(ecs, cluster, cp_name, td_a)
    tasks.append(task_a)

    # --- ECS scales the ASG off zero and the instance registers into THIS cluster.
    ci_arn = _poll_until(
        lambda: ecs.list_container_instances(cluster=cluster, status="ACTIVE")["containerInstanceArns"],
        lambda arns: len(arns) == 1, timeout_s=900.0, interval_s=15.0,
        description=f"managed scaling launching one container instance into {cluster}",
    )[0]
    placed = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster, tasks=[task_a])["tasks"][0],
        lambda t: t.get("lastStatus") in ("RUNNING", "STOPPED"), timeout_s=600.0, interval_s=10.0,
        description=f"task {task_a} reaching RUNNING",
    )
    assert placed["lastStatus"] == "RUNNING", (
        f"task A did not run: stopCode={placed.get('stopCode')!r} reason={placed.get('stoppedReason')!r}"
    )
    assert placed.get("containerInstanceArn") == ci_arn, (
        f"task A placed on {placed.get('containerInstanceArn')!r}, not {ci_arn!r}"
    )
    a_running = datetime.now(timezone.utc)

    ci = ecs.describe_container_instances(cluster=cluster, containerInstances=[ci_arn])["containerInstances"][0]
    registered = {r["name"]: r.get("integerValue") for r in ci["registeredResources"]}
    reg_cpu, reg_mem = registered.get("CPU"), registered.get("MEMORY")
    assert isinstance(reg_cpu, int) and reg_cpu > _TASK_A_CPU, f"registered CPU {reg_cpu!r}"
    assert isinstance(reg_mem, int) and reg_mem > _TASK_A_MEM + 128, f"registered MEMORY {reg_mem!r}"
    want_mem = _TASK_A_MEM * 100.0 / reg_mem
    want_cpu = _TASK_A_CPU * 100.0 / reg_cpu

    # A full minute that began after task A was RUNNING: exactly one task reserved all minute.
    steady_from = _minute_floor(a_running) + timedelta(minutes=1)
    cluster_dims = [{"Name": "ClusterName", "Value": cluster}]
    cpr_dims = [{"Name": "CapacityProviderName", "Value": cp_name},
                {"Name": "ClusterName", "Value": cluster}]

    def _steady(namespace, metric, dimensions, since):
        return [d for d in _series(cw, namespace, metric, dimensions, cluster_created)
                if d["Timestamp"] >= since]

    mem_dp = _poll_until(lambda: _steady("AWS/ECS", "MemoryReservation", cluster_dims, steady_from),
                         lambda d: len(d) >= 1, timeout_s=_METRIC_BUDGET_S, interval_s=20.0,
                         description=f"an AWS/ECS MemoryReservation datapoint for {cluster} at/after "
                                     f"{steady_from.isoformat()}")[0]
    cpu_dp = _poll_until(lambda: _steady("AWS/ECS", "CPUReservation", cluster_dims, steady_from),
                         lambda d: len(d) >= 1, timeout_s=_METRIC_BUDGET_S, interval_s=20.0,
                         description=f"an AWS/ECS CPUReservation datapoint for {cluster} at/after "
                                     f"{steady_from.isoformat()}")[0]
    for name, dp, want in (("MemoryReservation", mem_dp, want_mem), ("CPUReservation", cpu_dp, want_cpu)):
        for stat in ("Minimum", "Maximum"):
            assert abs(dp[stat] - want) <= _TOLERANCE_PP, (
                f"{name} {stat} at {dp['Timestamp'].isoformat()} is {dp[stat]!r}, expected {want:.3f} "
                f"(task reserves {_TASK_A_MEM if name.startswith('Memory') else _TASK_A_CPU} of "
                f"registered {reg_mem if name.startswith('Memory') else reg_cpu}); datapoint {dp!r}"
            )
        assert dp.get("Unit") == "Percent", f"{name} Unit is {dp.get('Unit')!r}"

    # Control: one instance, one task that fits -> M == N -> exactly 100.
    cpr_steady = _poll_until(lambda: _steady("AWS/ECS/ManagedScaling", "CapacityProviderReservation",
                                             cpr_dims, steady_from),
                             lambda d: len(d) >= 1, timeout_s=_METRIC_BUDGET_S, interval_s=20.0,
                             description=f"a CapacityProviderReservation datapoint for {cp_name} at/after "
                                         f"{steady_from.isoformat()}")[0]
    assert cpr_steady["Minimum"] == 100.0 and cpr_steady["Maximum"] == 100.0, (
        f"with one instance hosting the only task, CapacityProviderReservation should read exactly "
        f"100; datapoint {cpr_steady!r}"
    )

    # --- Pressure: a task that fits an EMPTY instance of this kind but not beside task A.
    b_mem = reg_mem - 128
    assert b_mem > reg_mem - _TASK_A_MEM, (b_mem, reg_mem)
    td_b = _register_task_def(ctx, ecs, "b", cpu=_TASK_A_CPU, memory=b_mem)
    b_submitted = datetime.now(timezone.utc)
    task_b = _run_task(ecs, cluster, cp_name, td_b)
    tasks.append(task_b)

    pressure_from = _minute_floor(b_submitted)
    pressured = _poll_until(
        lambda: [d for d in _steady("AWS/ECS/ManagedScaling", "CapacityProviderReservation",
                                    cpr_dims, pressure_from) if d["Maximum"] > 100.0],
        lambda d: len(d) >= 1, timeout_s=_METRIC_BUDGET_S, interval_s=20.0,
        description=(f"CapacityProviderReservation for {cp_name} exceeding 100 after the unplaceable "
                     f"task was submitted at {b_submitted.isoformat()}"),
    )[0]
    # M/N * 100 with N=1 instance and M=2 needed (A's instance plus an empty one for B).
    assert pressured["Maximum"] == 200.0, (
        f"one unplaceable task beside one full instance should read M/N*100 = 2/1*100 = 200; "
        f"datapoint {pressured!r}"
    )

    # Invariants at the moment of pressure: B is still unplaced, A is untouched, the ASG is capped.
    both = {t["taskArn"]: t for t in ecs.describe_tasks(cluster=cluster, tasks=[task_a, task_b])["tasks"]}
    assert both[task_b]["lastStatus"] == "PROVISIONING", (
        f"the unplaceable task is {both[task_b]['lastStatus']!r}, expected PROVISIONING"
    )
    assert not both[task_b].get("containerInstanceArn"), both[task_b].get("containerInstanceArn")
    assert both[task_a]["lastStatus"] == "RUNNING", f"task A is {both[task_a]['lastStatus']!r}"
    group = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
    assert group["MaxSize"] == 1 and len(group["Instances"]) == 1, (
        f"ASG MaxSize={group['MaxSize']!r} instances={[i['InstanceId'] for i in group['Instances']]!r}"
    )

    # Reservations never counted the PROVISIONING task: no minute exceeds task A's share.
    for name, metric, want in (("MemoryReservation", "MemoryReservation", want_mem),
                               ("CPUReservation", "CPUReservation", want_cpu)):
        peak = max(d["Maximum"] for d in _series(cw, "AWS/ECS", metric, cluster_dims, cluster_created))
        assert peak <= want + _TOLERANCE_PP, (
            f"{name} peaked at {peak!r} although only task A ({want:.3f}%) was ever placed"
        )

    # In-body teardown of the slow part, so the bounded cleanup chain only has fast deletes left.
    _stop_tasks(ecs, cluster, tasks)
    _disassociate(ecs, cluster)
    _delete_asg(asg, asg_name)
    _deregister_instances(ecs, cluster)


# ===== helpers =====
def _minute_floor(ts: datetime) -> datetime:
    return ts.replace(second=0, microsecond=0)


def _series(cw, namespace, metric, dimensions, since) -> list[dict]:
    now = datetime.now(timezone.utc)
    dps = cw.get_metric_statistics(
        Namespace=namespace, MetricName=metric, Dimensions=dimensions,
        StartTime=_minute_floor(since) - timedelta(minutes=1), EndTime=now + timedelta(minutes=1),
        Period=60, Statistics=["Minimum", "Maximum", "Average"],
    )["Datapoints"]
    return sorted(dps, key=lambda d: d["Timestamp"])


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


def _swallow(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown
        pass


def _tags(name: str) -> list[dict]:
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "Name", "Value": name}]


def _retry_dependency(fn, budget_s: float = 120.0) -> None:
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(5.0)


def _public_network(ctx, ec2) -> tuple[str, str]:
    """A VPC of our own with an IGW and an auto-public-IP subnet, so the container instance can
    reach the ECS endpoint and pull the public image. No default VPC, no NAT, nothing billable."""
    name = ctx.unique_name("sim2real-xsvc-obs3-net-")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert zones, f"no available AZ in {ctx.region} offers {_INSTANCE_TYPE}; offered {sorted(offered)!r}"
    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags(name)}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc)))
    igw = ec2.create_internet_gateway(TagSpecifications=[
        {"ResourceType": "internet-gateway", "Tags": _tags(name)}])["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_dependency(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))
    main_rt = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc]},
        {"Name": "association.main", "Values": ["true"]}])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=main_rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=zones[0],
                               TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags(name)}]
                               )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet)))
    ec2.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={"Value": True})
    sg = ec2.create_security_group(GroupName=name, Description="sim2real obs-ecs-3, egress only",
                                   VpcId=vpc, TagSpecifications=[
                                       {"ResourceType": "security-group", "Tags": _tags(name)}])["GroupId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_security_group(GroupId=sg)))
    return subnet, sg


_INSTANCE_STATEMENTS = [{
    "Effect": "Allow",
    "Action": ["ecs:DeregisterContainerInstance", "ecs:RegisterContainerInstance", "ecs:Submit*",
               "ecs:DiscoverPollEndpoint", "ecs:Poll", "ecs:StartTelemetrySession",
               "ecs:UpdateContainerInstancesState", "ecs:TagResource",
               "ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability",
               "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage",
               "logs:CreateLogStream", "logs:PutLogEvents"],
    "Resource": "*",
}]


def _instance_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-obs3-inst-")
    iam.create_role(
        RoleName=name, Path="/sim2real/", Tags=[{"Key": "sim2real", "Value": CHECK}],
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
    )

    def _drop():
        _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_drop)
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": _INSTANCE_STATEMENTS}))
    return name


def _instance_profile(ctx, role_name: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-obs3-ip-")
    iam.create_instance_profile(InstanceProfileName=name, Path="/sim2real/",
                                Tags=[{"Key": "sim2real", "Value": CHECK}])

    def _drop():
        _swallow(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=name,
                                                               RoleName=role_name))
        iam.delete_instance_profile(InstanceProfileName=name)

    ctx.on_cleanup(_drop)
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=role_name)
    return name


def _launch_template(ctx, ec2, ami, cluster, profile, sg) -> str:
    name = ctx.unique_name("sim2real-xsvc-obs3-lt-")
    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster} >> /etc/ecs/ecs.config\n"
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami, "InstanceType": _INSTANCE_TYPE,
            "IamInstanceProfile": {"Name": profile}, "SecurityGroupIds": [sg],
            "UserData": base64.b64encode(user_data.encode()).decode(),
            "TagSpecifications": [{"ResourceType": "instance", "Tags": _tags(name)},
                                  {"ResourceType": "volume", "Tags": _tags(name)}],
        },
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags(name)}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _create_asg(ctx, asg, lt_name, subnet) -> tuple[str, str]:
    """min 0 / max 1 / desired 0: ECS must be what moves it, and MaxSize 1 is what keeps the
    second task unplaceable. CreateAutoScalingGroup is where the new instance profile's IAM
    propagation is observable (ValidationError naming the profile), so that one rejection is
    retried on a deadline."""
    name = ctx.unique_name("sim2real-xsvc-obs3-asg-")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            asg.create_auto_scaling_group(
                AutoScalingGroupName=name, MinSize=0, MaxSize=1, DesiredCapacity=0,
                LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
                VPCZoneIdentifier=subnet,
                Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
            )
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "ValidationError" and "Instance Profile" in err.get("Message", "")
                    and time.monotonic() < deadline):
                raise
            time.sleep(10.0)
    ctx.on_cleanup(lambda: _delete_asg(asg, name))
    arn = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0][
        "AutoScalingGroupARN"]
    return name, arn


def _delete_asg(asg, name) -> None:
    """Force-delete and WAIT until the group is gone. The delete is refused while a scaling
    activity is mid-flight (an ECS-driven launch), so exactly that refusal is retried every 2 s;
    any other error, or a group still present after 600 s, raises."""
    deadline = time.monotonic() + 600.0
    issued = False
    while time.monotonic() < deadline:
        if not asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]:
            return
        if not issued:
            try:
                asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
                issued = True
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("ScalingActivityInProgress", "ResourceInUse"):
                    raise
        time.sleep(2.0)
    raise RuntimeError(f"auto scaling group {name} still present after 600s")


def _ensure_ecs_slr(ctx) -> None:
    """Capacity providers need AWSServiceRoleForECS; create it if absent (never deleted --
    it is account-wide and other runs rely on it)."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise


def _associate(ecs, cluster, cp_name) -> None:
    deadline = time.monotonic() + 120.0
    while True:
        try:
            ecs.put_cluster_capacity_providers(
                cluster=cluster, capacityProviders=[cp_name],
                defaultCapacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}])
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "UpdateInProgressException" or time.monotonic() > deadline:
                raise
            time.sleep(5.0)


def _disassociate(ecs, cluster) -> None:
    deadline = time.monotonic() + 180.0
    while True:
        try:
            ecs.put_cluster_capacity_providers(cluster=cluster, capacityProviders=[],
                                               defaultCapacityProviderStrategy=[])
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code not in ("UpdateInProgressException", "ResourceInUseException") or \
                    time.monotonic() > deadline:
                raise
            time.sleep(10.0)


def _delete_capacity_provider(ecs, cp_name) -> None:
    deadline = time.monotonic() + 180.0
    while True:
        try:
            ecs.delete_capacity_provider(capacityProvider=cp_name)
            return
        except ClientError as exc:
            if time.monotonic() > deadline:
                raise RuntimeError(f"capacity provider {cp_name}: {exc}") from exc
            time.sleep(10.0)


def _register_task_def(ctx, ecs, suffix, *, cpu, memory) -> str:
    arn = ecs.register_task_definition(
        family=ctx.unique_name(f"sim2real-xsvc-obs3-td-{suffix}-"),
        requiresCompatibilities=["EC2"], networkMode="bridge", cpu=str(cpu), memory=str(memory),
        containerDefinitions=[{"name": "app", "image": _IMAGE, "essential": True,
                               "cpu": cpu, "memory": memory, "command": ["sh", "-c", "sleep 3600"]}],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _run_task(ecs, cluster, cp_name, td) -> str:
    resp = ecs.run_task(cluster=cluster, taskDefinition=td, count=1,
                        capacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}])
    assert not resp.get("failures"), f"RunTask failures: {resp['failures']!r}"
    assert len(resp["tasks"]) == 1, f"RunTask returned {len(resp['tasks'])} tasks"
    return resp["tasks"][0]["taskArn"]


def _stop_tasks(ecs, cluster, tasks) -> None:
    for arn in tasks:
        _swallow(lambda a=arn: ecs.stop_task(cluster=cluster, task=a, reason="sim2real teardown"))


def _deregister_instances(ecs, cluster) -> None:
    for arn in ecs.list_container_instances(cluster=cluster)["containerInstanceArns"]:
        _swallow(lambda a=arn: ecs.deregister_container_instance(cluster=cluster, containerInstance=a,
                                                                 force=True))


def _delete_cluster(ecs, cluster) -> None:
    _deregister_instances(ecs, cluster)
    deadline = time.monotonic() + 180.0
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ClusterNotFoundException":
                return
            if time.monotonic() > deadline:
                raise RuntimeError(f"cluster {cluster}: {exc}") from exc
            time.sleep(10.0)


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
