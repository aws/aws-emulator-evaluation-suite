"""ephemeral-storage-request-is-provisioned-inside-the-container."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ephemeral-storage-request-is-provisioned-inside-the-container"
GROUP = "data-plane"
SERVICES = ["ecs"]

_REQUESTED_GIB = 50
_MIN_SUPPORTED_GIB = 21  # fixed, non-adjustable API constant — see the Smithy model's own docs
_BELOW_MINIMUM_GIB = 20
_DELIVERY_FRACTION = 0.8
_DF_FAILED = 250
_TASK_TIMEOUT_S = 600.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A task-level ephemeralStorage request is provisioned: a container in a 50 GiB task measures
    a larger filesystem than its default-storage twin and at least _DELIVERY_FRACTION of the request,
    and the documented 21 GiB floor rejects 20 while accepting 21."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx, ecs)
    subnet_id, sg_id = _public_network(ctx)

    # --- leg 3 first (cheap, control plane): the fixed 21 GiB floor -----------------------------
    family = ctx.unique_name("sim2real-behav-ecs-ephem-")
    accepted = ecs.register_task_definition(
        **_taskdef_kwargs(family, ephemeral_gib=_MIN_SUPPORTED_GIB)
    )["taskDefinition"]
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: ecs.delete_task_definitions(
                taskDefinitions=[accepted["taskDefinitionArn"]]
            )
        )
    )
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: ecs.deregister_task_definition(taskDefinition=accepted["taskDefinitionArn"])
        )
    )
    assert accepted["ephemeralStorage"]["sizeInGiB"] == _MIN_SUPPORTED_GIB, (
        f"the positive control must be accepted at the documented minimum: expected sizeInGiB="
        f"{_MIN_SUPPORTED_GIB}, got {accepted.get('ephemeralStorage')!r}"
    )
    err = _client_error(
        lambda: ecs.register_task_definition(
            **_taskdef_kwargs(family, ephemeral_gib=_BELOW_MINIMUM_GIB)
        )
    )
    assert err.get("Code") == "ClientException", (
        f"ephemeralStorage.sizeInGiB={_BELOW_MINIMUM_GIB} is one below the fixed minimum of "
        f"{_MIN_SUPPORTED_GIB} and must be refused with ClientException, got "
        f"{err.get('Code')!r}: {err.get('Message')!r}"
    )
    assert err.get("Message") == f"EphemeralStorage size should be at least {_MIN_SUPPORTED_GIB}", f"unexpected message: {err.get('Message')!r}"
    # Effect absent, via an independent read: no revision was created for the refused request.
    revisions = ecs.list_task_definitions(familyPrefix=family, status="ACTIVE")[
        "taskDefinitionArns"
    ]
    assert revisions == [accepted["taskDefinitionArn"]], (
        f"the refused registration must not have created a revision: expected only "
        f"{accepted['taskDefinitionArn']!r} in family {family}, got {revisions!r}"
    )

    # --- legs 1+2: the twin, measured inside the containers -------------------------------------
    control_td = ecs.register_task_definition(
        **_taskdef_kwargs(ctx.unique_name("sim2real-behav-ecs-ephem-default-"), ephemeral_gib=None)
    )["taskDefinition"]
    subject_td = ecs.register_task_definition(
        **_taskdef_kwargs(ctx.unique_name("sim2real-behav-ecs-ephem-big-"), ephemeral_gib=_REQUESTED_GIB)
    )["taskDefinition"]
    for td in (control_td, subject_td):
        arn = td["taskDefinitionArn"]
        ctx.on_cleanup(lambda a=arn: _swallow(lambda: ecs.delete_task_definitions(taskDefinitions=[a])))
        ctx.on_cleanup(lambda a=arn: _swallow(lambda: ecs.deregister_task_definition(taskDefinition=a)))

    assert subject_td["ephemeralStorage"]["sizeInGiB"] == _REQUESTED_GIB, (
        f"the subject task definition must carry sizeInGiB={_REQUESTED_GIB}, got "
        f"{subject_td.get('ephemeralStorage')!r}"
    )
    assert control_td.get("ephemeralStorage", {}).get("sizeInGiB") != _REQUESTED_GIB, (
        f"the control task definition must NOT carry the subject's request, got "
        f"{control_td.get('ephemeralStorage')!r}"
    )

    net = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    control_arn = _run(ctx, ecs, cluster, control_td["taskDefinitionArn"], net)
    subject_arn = _run(ctx, ecs, cluster, subject_td["taskDefinitionArn"], net)

    control_task = _await_stopped(ecs, cluster, control_arn)
    subject_task = _await_stopped(ecs, cluster, subject_arn)
    control_gib = _measured_gib(control_task, "control (no ephemeralStorage)")
    subject_gib = _measured_gib(subject_task, f"subject (sizeInGiB={_REQUESTED_GIB})")

    assert subject_gib > control_gib, (
        f"the task that asked for {_REQUESTED_GIB} GiB of ephemeral storage must see a bigger "
        f"filesystem than the identical task that asked for none: subject measured {subject_gib} GiB, "
        f"control measured {control_gib} GiB — equal sizes mean the request had no effect on the "
        f"container at all"
    )
    floor = int(_REQUESTED_GIB * _DELIVERY_FRACTION)
    assert subject_gib >= floor, (
        f"a request for {_REQUESTED_GIB} GiB must deliver at least {floor} GiB of usable filesystem "
        f"({_DELIVERY_FRACTION:.0%} of the request, allowing for filesystem overhead), but the "
        f"container measured only {subject_gib} GiB"
    )

    # An independent read at the destination, through DescribeTasks rather than RunTask's own
    # response — the running task must also report the size it was launched with.
    assert subject_task["ephemeralStorage"]["sizeInGiB"] == _REQUESTED_GIB, (
        f"DescribeTasks must report the subject task's ephemeral storage as {_REQUESTED_GIB} GiB, got "
        f"{subject_task.get('ephemeralStorage')!r}"
    )


# ===== helpers =====

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

# Report the writable filesystem's total size in GiB through the exit code — the only channel a
# stopped Fargate task has. 1K blocks / 1048576 = GiB. A df/awk failure is a distinct code so it
# cannot be misread as a small disk.
_PROBE = (
    "g=$(df -k / | awk 'NR==2{print int($2/1048576)}') || exit " + str(_DF_FAILED) + "; "
    '[ -n "$g" ] || exit ' + str(_DF_FAILED) + "; "
    "exit $g"
)


def _ecs_tags() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _ec2_tags() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn) -> None:
    """Run one teardown call; return only on the not-found codes below, raise anything else."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("ClusterNotFoundException", "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound")
            and not (err["Code"] == "ClientException" and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted")))
        ):
            raise


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    accepting input AWS refuses must fail as an unexpected success, not as an error-code
    mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


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


def _taskdef_kwargs(family, ephemeral_gib):
    kwargs = dict(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", _PROBE],
            }
        ],
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        tags=_ecs_tags(),
    )
    if ephemeral_gib is not None:
        kwargs["ephemeralStorage"] = {"sizeInGiB": ephemeral_gib}
    return kwargs


def _measured_gib(task, label) -> int:
    container = next(c for c in task["containers"] if c["name"] == "app")
    code = container.get("exitCode")
    assert code != _DF_FAILED, (
        f"the {label} probe could not measure its filesystem (df/awk failed inside the container), "
        f"so no size was observed: reason={container.get('reason')!r}"
    )
    assert isinstance(code, int) and 0 < code < _DF_FAILED, (
        f"the {label} probe must report its filesystem size in GiB as its exit code, got {code!r} "
        f"(reason={container.get('reason')!r}, stoppedReason={task.get('stoppedReason')!r})"
    )
    return code


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


def _await_stopped(ecs, cluster, arn) -> dict:
    task = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster, tasks=[arn])["tasks"][0],
        lambda t: t["lastStatus"] == "STOPPED",
        timeout_s=_TASK_TIMEOUT_S,
        interval_s=10,
        description=f"probe task {arn} measures its filesystem and exits",
    )
    assert task.get("stopCode") != "TaskFailedToStart", (
        f"task {arn} never started, so its filesystem was never measured: "
        f"stoppedReason={task.get('stoppedReason')!r} containers={task.get('containers')!r}"
    )
    return task


def _public_network(ctx):
    """A dedicated VPC with one public subnet, an IGW and a default route.

    Created unconditionally rather than adopting an ambient default VPC: a freshly provisioned
    account may not have one. The public route is
    load-bearing — the probe pulls busybox from public ECR.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.195.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags()}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.195.0.0/25",
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
