"""container-workdir-user-and-ulimit-apply-inside-the-running-container."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "container-workdir-user-and-ulimit-apply-inside-the-running-container"
GROUP = "container-runtime"
SERVICES = ["ecs"]

_VPC_CIDR = "10.99.0.0/16"
_SUBNET_CIDR = "10.99.1.0/24"
_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_WORKDIR = "/tmp"
_UID = "1234"
_NOFILE_SOFT = 4321
_NOFILE_HARD = 8192
# The container reports which settings were NOT applied as a bitmask added to this base, so a
# wrong exit code names the exact setting that was ignored.
_BASE = 40
_PROBE = (
    "c=0; "
    f'[ "$(pwd)" = "{_WORKDIR}" ] || c=$((c+1)); '
    f'[ "$(id -u)" = "{_UID}" ] || c=$((c+2)); '
    f'[ "$(ulimit -n)" = "{_NOFILE_SOFT}" ] || c=$((c+4)); '
    f'[ "$(ulimit -Hn)" = "{_NOFILE_HARD}" ] || c=$((c+8)); '
    f"exit $((c+{_BASE}))"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Fargate container runs in its workingDirectory, as its user, with its nofile ulimits: an
    in-container probe encodes any unapplied setting as a bit in its exit code, which must be 40,
    while a control container without the settings must report the workdir and uid bits."""
    ec2 = ctx.client("ec2")
    ecs = ctx.client("ecs")

    _ensure_ecs_slr(ctx)
    subnet, sg = _public_network(ctx, ec2)
    cluster = ctx.unique_name("sim2real-behav-ecs-rt-")
    ecs.create_cluster(clusterName=cluster, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))

    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-rt-td-"), networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"], cpu="256", memory="512",
        containerDefinitions=[
            {"name": "probe", "image": _IMAGE, "essential": True,
             "workingDirectory": _WORKDIR, "user": _UID,
             "ulimits": [{"name": "nofile", "softLimit": _NOFILE_SOFT, "hardLimit": _NOFILE_HARD}],
             "command": ["sh", "-c", _PROBE],
             # Wait for the control so the essential container's exit cannot stop it first.
             "dependsOn": [{"containerName": "control", "condition": "COMPLETE"}]},
            {"name": "control", "image": _IMAGE, "essential": False,
             "command": ["sh", "-c", _PROBE]},
        ],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))
    stored = {c["name"]: c for c in td["containerDefinitions"]}["probe"]
    assert stored.get("workingDirectory") == _WORKDIR and stored.get("user") == _UID, stored

    resp = ecs.run_task(
        cluster=cluster, taskDefinition=td_arn, launchType="FARGATE", count=1,
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": [subnet], "securityGroups": [sg], "assignPublicIp": "ENABLED"}},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    assert not resp.get("failures"), f"RunTask failures: {resp['failures']!r}"
    task_arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _stop_and_wait(ec2, ecs, cluster, task_arn, subnet))

    stopped = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0],
        lambda t: t.get("lastStatus") == "STOPPED", timeout_s=600.0, interval_s=10.0,
        description=f"task {task_arn} running its probe to completion",
    )
    containers = {c["name"]: c for c in stopped["containers"]}
    probe, control = containers["probe"], containers["control"]
    assert stopped.get("stopCode") == "EssentialContainerExited", (
        f"task stopped with stopCode={stopped.get('stopCode')!r} reason={stopped.get('stoppedReason')!r}"
    )
    assert probe.get("exitCode") == _BASE, (
        f"probe container exited {probe.get('exitCode')!r}, expected {_BASE} (all four settings "
        f"applied); bits over {_BASE}: 1=workingDirectory 2=user 4=soft nofile 8=hard nofile. "
        f"reason={probe.get('reason')!r}"
    )
    # Control: the same probe without the settings fails the workdir and uid tests (bits 1 and
    # 2). Its ulimit bits depend on the platform default, so only those two bits are asserted.
    ctl = control.get("exitCode")
    assert isinstance(ctl, int) and ctl >= _BASE and (ctl - _BASE) & 3 == 3, (
        f"control container exited {ctl!r}; without workingDirectory/user it must report both "
        f"bits 1 and 2 over {_BASE}, otherwise the probe is satisfied by image defaults"
    )

    _stop_and_wait(ec2, ecs, cluster, task_arn, subnet)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


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
    """A VPC of our own with an IGW, so Fargate can pull the public image. No default VPC."""
    name = ctx.unique_name("sim2real-behav-ecs-rt-net-")
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert zones, f"no available availability zone in {ctx.region}"
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
    sg = ec2.create_security_group(GroupName=name, Description="sim2real ecs runtime probe, egress only",
                                   VpcId=vpc, TagSpecifications=[
                                       {"ResourceType": "security-group", "Tags": _tags(name)}])["GroupId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_security_group(GroupId=sg)))
    return subnet, sg


def _ensure_ecs_slr(ctx) -> None:
    """Fargate RunTask needs AWSServiceRoleForECS; create it if absent (never deleted --
    it is account-wide and other runs rely on it)."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise


def _stop_and_wait(ec2, ecs, cluster, task_arn, subnet) -> None:
    """Stop the task (idempotent) and wait for its ENI to leave the subnet, so the network
    teardown that follows does not race a DependencyViolation."""
    try:
        ecs.stop_task(cluster=cluster, task=task_arn, reason="sim2real teardown")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet]}])["NetworkInterfaces"]
        if not enis:
            return
        time.sleep(2.0)
    raise AssertionError(f"task {task_arn} ENI still in subnet {subnet} after 300s")


def _delete_cluster(ecs, cluster) -> None:
    deadline = time.monotonic() + 120.0
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code not in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "UpdateInProgressException",
            ) or time.monotonic() > deadline:
                raise
            time.sleep(2.0)


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
