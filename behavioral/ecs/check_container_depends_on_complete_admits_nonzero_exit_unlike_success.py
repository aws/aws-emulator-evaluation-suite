"""container-depends-on-complete-admits-nonzero-exit-unlike-success."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "container-depends-on-complete-admits-nonzero-exit-unlike-success"
GROUP = "task-lifecycle"
SERVICES = ["ecs"]

_INIT_EXIT = 1
_APP_EXIT = 42
_TASK_TIMEOUT_S = 600.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """dependsOn condition COMPLETE starts the dependent after a non-zero exit; SUCCESS does not.
    Under COMPLETE `app` exits 42 (EssentialContainerExited); under SUCCESS it has no exitCode.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDependency.html
    """
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx, ecs)
    subnet_id, sg_id = _public_network(ctx)

    subject_td = _register(ctx, ecs, "COMPLETE")
    control_td = _register(ctx, ecs, "SUCCESS")

    # Representation leg: the condition must survive the round trip distinctly, or the data-plane
    # legs below would be measuring two identical task definitions.
    conditions = {}
    for label, arn in (("subject", subject_td), ("control", control_td)):
        described = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
        app = next(c for c in described["containerDefinitions"] if c["name"] == "app")
        depends = app["dependsOn"]
        assert len(depends) == 1, (
            f"the {label} task definition's app container must carry exactly one dependsOn entry, "
            f"got {depends!r}"
        )
        conditions[label] = depends[0]["condition"]
    assert conditions == {"subject": "COMPLETE", "control": "SUCCESS"}, (
        f"the two conditions must round-trip distinctly, got {conditions!r}"
    )

    net = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    subject_arn = _run(ctx, ecs, cluster, subject_td, net)
    control_arn = _run(ctx, ecs, cluster, control_td, net)

    subject = _await_stopped(ecs, cluster, subject_arn, "subject (COMPLETE)")
    control = _await_stopped(
        ecs, cluster, control_arn, "control (SUCCESS)", expect_task_failed_to_start=True
    )

    # Both tasks must have really run their init container, or neither leg says anything about the
    # gate — this is the shared precondition, asserted rather than assumed.
    for label, task in (("subject (COMPLETE)", subject), ("control (SUCCESS)", control)):
        init_exit = _container(task, "init").get("exitCode")
        assert init_exit == _INIT_EXIT, (
            f"the {label} task's init container must have run and exited {_INIT_EXIT} for the "
            f"dependsOn condition to be under test at all, got exitCode={init_exit!r} "
            f"(reason={_container(task, 'init').get('reason')!r})"
        )

    subject_app = _container(subject, "app")
    assert subject_app.get("exitCode") == _APP_EXIT, (
        f"condition COMPLETE must admit init's non-zero exit and let app run, so app must report "
        f"exitCode={_APP_EXIT}; got {subject_app.get('exitCode')!r} "
        f"(reason={subject_app.get('reason')!r}, stoppedReason={subject.get('stoppedReason')!r}) — "
        f"an absent exitCode here means the target is applying SUCCESS semantics to COMPLETE"
    )
    assert subject.get("stopCode") == "EssentialContainerExited", (
        f"the subject task must stop because its essential app container exited, got "
        f"stopCode={subject.get('stopCode')!r} stoppedReason={subject.get('stoppedReason')!r}"
    )

    control_app = _container(control, "app")
    assert control_app.get("exitCode") is None, (
        f"condition SUCCESS must withhold app after init exits {_INIT_EXIT}, so app must have NO "
        f"exitCode — its command never ran; got exitCode={control_app.get('exitCode')!r} "
        f"(lastStatus={control_app.get('lastStatus')!r}, reason={control_app.get('reason')!r}). An "
        f"exitCode of {_APP_EXIT} here means the target is applying COMPLETE semantics to SUCCESS"
    )
    # An essential container withheld by an unsatisfied dependsOn condition stops the task with
    # TaskFailedToStart (the same code as a genuine launch failure), even though init ran.
    assert control.get("stopCode") == "TaskFailedToStart", (
        f"condition SUCCESS withholding app must surface as the task's own stopCode="
        f"'TaskFailedToStart' on real ECS — the essential container never started, so the task "
        f"cannot stop with EssentialContainerExited; got stopCode={control.get('stopCode')!r} "
        f"stoppedReason={control.get('stoppedReason')!r}"
    )
    # The two legs must genuinely disagree; if they ever match, one of the assertions above is
    # passing for the wrong reason.
    assert subject_app.get("exitCode") != control_app.get("exitCode"), (
        f"COMPLETE and SUCCESS must produce different outcomes for app, but both reported "
        f"exitCode={subject_app.get('exitCode')!r}"
    )



_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _ecs_tags() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _ec2_tags() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn) -> None:
    """Run fn(), swallowing any exception. Teardown ONLY — never on an assertion path."""
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


def _register(ctx, ecs, condition) -> str:
    """A two-container Fargate task definition whose app container gates on init with `condition`."""
    arn = ecs.register_task_definition(
        family=ctx.unique_name(f"sim2real-behav-ecs-dep-{condition.lower()}-"),
        containerDefinitions=[
            {
                "name": "init",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                # Non-essential: its non-zero exit must not tear the task down before the gate is
                # evaluated, or the check would measure EssentialContainerExited instead.
                "essential": False,
                "command": ["sh", "-c", f"exit {_INIT_EXIT}"],
            },
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", f"exit {_APP_EXIT}"],
                "dependsOn": [{"containerName": "init", "condition": condition}],
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


def _await_stopped(ecs, cluster, arn, label, *, expect_task_failed_to_start=False) -> dict:
    """Poll to STOPPED. TaskFailedToStart means either a launch failure or an essential container
    withheld by dependsOn, so the caller states which one it expects."""
    task = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster, tasks=[arn])["tasks"][0],
        lambda t: t["lastStatus"] == "STOPPED",
        timeout_s=_TASK_TIMEOUT_S,
        interval_s=10,
        description=f"the {label} task reaches STOPPED",
    )
    if not expect_task_failed_to_start:
        assert task.get("stopCode") != "TaskFailedToStart", (
            f"the {label} task never started, so nothing about the dependsOn gate was measured: "
            f"stoppedReason={task.get('stoppedReason')!r} containers={task.get('containers')!r}"
        )
    return task


def _public_network(ctx):
    """A dedicated VPC with one public subnet, an IGW and a default route.

    A default VPC may be absent or misconfigured; the public route lets both containers pull busybox
    from public ECR."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.194.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags()}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.194.0.0/25",
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
            time.sleep(10)
        while time.monotonic() < deadline:
            try:
                ec2.delete_subnet(SubnetId=subnet_id)
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidSubnetID.NotFound":
                    break
                time.sleep(10)
        _swallow(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
        _swallow(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
        while time.monotonic() < deadline:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidVpcID.NotFound":
                    return
                time.sleep(10)
        raise RuntimeError(
            f"vpc {vpc_id} / subnet {subnet_id} not deleted within the teardown deadline"
        )

    ctx.on_cleanup(_teardown_network)
    return subnet_id, sg_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
