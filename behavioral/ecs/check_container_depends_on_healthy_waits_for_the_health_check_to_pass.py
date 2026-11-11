"""container-depends-on-healthy-waits-for-the-health-check-to-pass."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "container-depends-on-healthy-waits-for-the-health-check-to-pass"
GROUP = "task-lifecycle"
SERVICES = ["ecs"]

# `db` becomes healthy only this many seconds after it starts. Everything asserted below is derived
# from this one number, which this check chooses — no AWS constant is pinned.
_READY_DELAY_S = 15
_HEALTH_INTERVAL_S = 5
_NO_START_FILE = 248
_NEGATIVE_DELTA = 249
_DELTA_CAP = 240
_TASK_TIMEOUT_S = 900.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """dependsOn condition HEALTHY holds the dependent container until the depended-on container's
    healthCheck passes, not merely until it starts: app's measured wait is >= _READY_DELAY_S while an
    identical START control measures less, so a target ignoring the health result fails."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx, ecs)
    subnet_id, sg_id = _public_network(ctx)

    subject_td = _register(ctx, ecs, "HEALTHY")
    control_td = _register(ctx, ecs, "START")

    net = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    subject_arn = _run(ctx, ecs, cluster, subject_td, net)
    control_arn = _run(ctx, ecs, cluster, control_td, net)

    subject = _await_stopped(ecs, cluster, subject_arn, "subject (HEALTHY)")
    control = _await_stopped(ecs, cluster, control_arn, "control (START)")

    subject_delta = _delta(subject, "subject (HEALTHY)")
    control_delta = _delta(control, "control (START)")

    # The barrier first: a small control delta is what proves the probe can measure a short wait on
    # this wiring, so that the subject's long wait is attributable to the condition.
    assert control_delta < _READY_DELAY_S, (
        f"the control task gates on condition START, so app must begin as soon as db begins and the "
        f"measured wait must be well under the {_READY_DELAY_S}s it takes db to become healthy; the "
        f"control measured {control_delta}s. A control this slow means every container is being "
        f"delayed regardless of condition, so the subject's wait below is not evidence"
    )
    assert subject_delta >= _READY_DELAY_S, (
        f"condition HEALTHY must hold app until db's healthCheck passes, which cannot happen before "
        f"db has slept {_READY_DELAY_S}s and created /shared/ready; app started only "
        f"{subject_delta}s after db (the identically-built START control measured {control_delta}s), "
        f"which is what a target that treats HEALTHY as START looks like"
    )
    assert subject_delta > control_delta, (
        f"HEALTHY must delay app strictly longer than START does, but the subject measured "
        f"{subject_delta}s and the control {control_delta}s"
    )

    # An independent read at the destination: the health result that opened the gate must also
    # be what DescribeTasks reports for db, read through a different operation than RunTask.
    db = _container(subject, "db")
    assert db.get("healthStatus") == "HEALTHY", (
        f"db must be reported HEALTHY in the subject task, since that is the condition that released "
        f"app; got healthStatus={db.get('healthStatus')!r}"
    )
    app = _container(subject, "app")
    assert app.get("exitCode") == subject_delta, (
        f"the app container's exit code IS the measurement, so it must match: got "
        f"{app.get('exitCode')!r} vs {subject_delta}"
    )


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_MOUNT = "/shared"

# db: stamp the clock, wait, then become probe-passing, then stay up.
_DB_SCRIPT = (
    f"date +%s > {_MOUNT}/db_start; "
    f"sleep {_READY_DELAY_S}; "
    f"touch {_MOUNT}/ready; "
    "sleep 600"
)
# app: read db's stamp and exit with the elapsed seconds. The bounded wait covers the control case,
# where app may start in the same instant as db and race its first write.
_APP_SCRIPT = (
    f"i=0; while [ ! -f {_MOUNT}/db_start ] && [ $i -lt 15 ]; do sleep 1; i=$((i+1)); done; "
    f"[ -f {_MOUNT}/db_start ] || exit {_NO_START_FILE}; "
    f"s=$(cat {_MOUNT}/db_start); n=$(date +%s); d=$((n-s)); "
    f"[ $d -lt 0 ] && exit {_NEGATIVE_DELTA}; "
    f"[ $d -gt {_DELTA_CAP} ] && exit {_DELTA_CAP}; "
    "exit $d"
)


def _ecs_tags() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _ec2_tags() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn) -> None:
    """Run a teardown call: an already-gone resource is fine, any other failure raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("ClusterNotFoundException", "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound")
            and not (err["Code"] == "ClientException" and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted")))
        ):
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


def _container(task, name) -> dict:
    """The named container's record. Hard lookup — a missing container fails loudly."""
    for c in task["containers"]:
        if c["name"] == name:
            return c
    raise AssertionError(
        f"task {task['taskArn']} has no container named {name!r}; got "
        f"{[c['name'] for c in task['containers']]!r}"
    )


def _delta(task, label) -> int:
    """The seconds app waited for db, decoded from app's exit code."""
    app = _container(task, "app")
    code = app.get("exitCode")
    assert code != _NO_START_FILE, (
        f"the {label} app container never saw db's timestamp file, so no wait was measured — db "
        f"either never started or never wrote it: db={_container(task, 'db')!r}"
    )
    assert code != _NEGATIVE_DELTA, (
        f"the {label} app container measured a NEGATIVE wait, so the two containers disagree about "
        f"the clock: {app!r}"
    )
    assert code != _DELTA_CAP, (
        f"the {label} app container's wait exceeded the {_DELTA_CAP}s the exit code can carry, so the "
        f"measurement is saturated and cannot be compared: {app!r}"
    )
    assert isinstance(code, int) and 0 <= code < _DELTA_CAP, (
        f"the {label} app container must report its wait in seconds as its exit code, got {code!r} "
        f"(reason={app.get('reason')!r}, stoppedReason={task.get('stoppedReason')!r})"
    )
    return code


def _register(ctx, ecs, condition) -> str:
    """A db+app Fargate task definition sharing one volume, app gating on db with `condition`."""
    volume = "shared"
    mount = [{"sourceVolume": volume, "containerPath": _MOUNT, "readOnly": False}]
    arn = ecs.register_task_definition(
        family=ctx.unique_name(f"sim2real-behav-ecs-hc-{condition.lower()}-"),
        volumes=[{"name": volume}],
        containerDefinitions=[
            {
                "name": "db",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                # Non-essential so that app's exit is what stops the task, keeping the stopCode
                # attributable to app rather than to db's own lifetime.
                "essential": False,
                "command": ["sh", "-c", _DB_SCRIPT],
                "mountPoints": mount,
                "healthCheck": {
                    "command": ["CMD-SHELL", f"test -f {_MOUNT}/ready"],
                    "interval": _HEALTH_INTERVAL_S,
                    "timeout": 2,
                    "retries": 3,
                    # The probe deliberately fails for the first _READY_DELAY_S seconds; the grace
                    # period keeps those failures from counting toward `retries`.
                    "startPeriod": _READY_DELAY_S + 60,
                },
            },
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", _APP_SCRIPT],
                "mountPoints": mount,
                "dependsOn": [{"containerName": "db", "condition": condition}],
            },
        ],
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        tags=_ecs_tags(),
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.delete_task_definitions(taskDefinitions=[arn])))
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.deregister_task_definition(taskDefinition=arn)))

    described = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    app = next(c for c in described["containerDefinitions"] if c["name"] == "app")
    assert app["dependsOn"][0]["condition"] == condition, (
        f"the {condition} task definition must round-trip its dependsOn condition, got "
        f"{app.get('dependsOn')!r}"
    )
    return arn


def _create_cluster(ctx, ecs) -> str:
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=_ecs_tags())
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.delete_cluster(cluster=name)))
    return name


def _run(ctx, ecs, cluster, td_arn, net) -> str:
    resp = ecs.run_task(
        cluster=cluster,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration=net,
        tags=_ecs_tags(),
    )
    assert not resp.get("failures"), f"RunTask reported failures: {resp.get('failures')!r}"
    arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: ecs.stop_task(cluster=cluster, task=arn, reason="behavioral-cleanup")
        )
    )
    return arn


def _await_stopped(ecs, cluster, arn, label) -> dict:
    task = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster, tasks=[arn])["tasks"][0],
        lambda t: t["lastStatus"] == "STOPPED",
        timeout_s=_TASK_TIMEOUT_S,
        interval_s=2,
        description=f"the {label} task reaches STOPPED",
    )
    assert task.get("stopCode") != "TaskFailedToStart", (
        f"the {label} task never started, so nothing about the dependsOn gate was measured: "
        f"stoppedReason={task.get('stoppedReason')!r} containers={task.get('containers')!r}"
    )
    return task


def _public_network(ctx):
    """A dedicated VPC with one public subnet, an IGW and a default route.

    An account may have no default VPC, so the check creates its own. The public route is
    load-bearing: both containers pull busybox from public ECR.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.193.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags()}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.193.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _ec2_tags()}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _ec2_tags()}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
            "SecurityGroups"
        ]
        if sg["GroupName"] == "default"
    )

    def _teardown_network():
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if not ec2.describe_network_interfaces(
                Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
            ).get("NetworkInterfaces", []):
                break
            time.sleep(2)
        while time.monotonic() < deadline:
            try:
                ec2.delete_subnet(SubnetId=subnet_id)
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidSubnetID.NotFound":
                    break
                time.sleep(2)
        _swallow(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
        _swallow(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
        while time.monotonic() < deadline:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidVpcID.NotFound":
                    return
                time.sleep(2)
        raise RuntimeError(
            f"vpc {vpc_id} / subnet {subnet_id} not deleted within the teardown deadline"
        )

    ctx.on_cleanup(_teardown_network)
    return subnet_id, sg_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
