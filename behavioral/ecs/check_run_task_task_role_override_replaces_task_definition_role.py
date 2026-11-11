"""run-task-task-role-override-replaces-task-definition-role."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-task-task-role-override-replaces-task-definition-role"
GROUP = "task-execution"
SERVICES = ["ecs"]

_RUN_RETRY_S = 180.0
_TASK_TIMEOUT_S = 600.0

# What the probe container's exit code means. One script serves BOTH tasks, so neither leg can be
# satisfied by a target that hard-codes one answer.
_SAW_TASKDEF_ROLE = 3
_SAW_OVERRIDE_ROLE = 4
_SAW_EXECUTION_ROLE = 5
_SAW_SOMETHING_ELSE = 8
_SAW_NOTHING = 9
_MEANING = {
    _SAW_TASKDEF_ROLE: "the credentials endpoint served the TASK DEFINITION's taskRoleArn",
    _SAW_OVERRIDE_ROLE: "the credentials endpoint served the RunTask OVERRIDE taskRoleArn",
    _SAW_EXECUTION_ROLE: "the credentials endpoint served the EXECUTION role",
    _SAW_SOMETHING_ELSE: "the credentials endpoint served credentials for none of the three roles",
    _SAW_NOTHING: "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI was unset or 169.254.170.2 served nothing",
}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """RunTask's overrides.taskRoleArn replaces the task definition's taskRoleArn at the container-
    credentials endpoint: from one task definition, the control task sees the definition's role (exit 3)
    and the overridden task sees the override role (exit 4)."""
    ecs = ctx.client("ecs")
    iam = ctx.client("iam")

    td_role, td_role_arn = _task_role(ctx, iam, "sim2real-behav-ecs-tdrole-")
    ov_role, ov_role_arn = _task_role(ctx, iam, "sim2real-behav-ecs-ovrole-")
    ex_role, ex_role_arn = _execution_role(ctx, iam)
    names = {td_role, ov_role, ex_role}
    assert len(names) == 3, (
        f"the three roles must be distinguishable by name for the probe to discriminate, got {names!r}"
    )

    cluster = _create_cluster(ctx, ecs)
    subnet_id, sg_id = _public_network(ctx)

    # busybox `wget` against the link-local credentials endpoint; the answer is the exit code.
    script = (
        'u="http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}"; '
        f'[ -n "${{AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}}" ] || exit {_SAW_NOTHING}; '
        f'c=$(wget -q -O - "$u") || exit {_SAW_NOTHING}; '
        f'[ -n "$c" ] || exit {_SAW_NOTHING}; '
        f'case "$c" in *{ex_role}*) exit {_SAW_EXECUTION_ROLE};; esac; '
        f'case "$c" in *{ov_role}*) exit {_SAW_OVERRIDE_ROLE};; esac; '
        f'case "$c" in *{td_role}*) exit {_SAW_TASKDEF_ROLE};; esac; '
        f'exit {_SAW_SOMETHING_ELSE}'
    )
    td_arn = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-roleoverride-"),
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", script],
            }
        ],
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        taskRoleArn=td_role_arn,
        executionRoleArn=ex_role_arn,
        tags=_ecs_tags(),
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn])))
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.deregister_task_definition(taskDefinition=td_arn)))

    round_tripped = ecs.describe_task_definition(taskDefinition=td_arn)["taskDefinition"]
    assert round_tripped.get("taskRoleArn") == td_role_arn, (
        f"the task definition must carry {td_role_arn!r} as its taskRoleArn, got "
        f"{round_tripped.get('taskRoleArn')!r}"
    )

    net = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    control_arn = _run(ctx, ecs, cluster, td_arn, net, overrides=None)
    subject_arn = _run(ctx, ecs, cluster, td_arn, net, overrides={"taskRoleArn": ov_role_arn})
    assert control_arn != subject_arn, "the two probe tasks must be distinct"

    control = _await_stopped(ecs, cluster, control_arn)
    subject = _await_stopped(ecs, cluster, subject_arn)

    # The control is the barrier: if the endpoint serves nothing at all, or always serves the
    # override, this leg fails and the subject leg below is not evidence of anything.
    _assert_exit(control, _SAW_TASKDEF_ROLE, "control (no overrides.taskRoleArn)", td_role)
    _assert_exit(subject, _SAW_OVERRIDE_ROLE, "subject (overrides.taskRoleArn set)", ov_role)

    # An independent read at the destination, through DescribeTasks rather than RunTask's own
    # response — the override must also be recorded on the task, and must NOT leak onto the control.
    assert subject["overrides"]["taskRoleArn"] == ov_role_arn, (
        f"DescribeTasks must report the override role on the subject task: expected {ov_role_arn!r}, "
        f"got {subject['overrides'].get('taskRoleArn')!r}"
    )
    assert control["overrides"].get("taskRoleArn") != ov_role_arn, (
        f"the override role {ov_role_arn!r} must not appear on the control task, whose overrides are "
        f"{control['overrides']!r}"
    )
    for label, task in (("control", control), ("subject", subject)):
        assert task.get("stopCode") == "EssentialContainerExited", (
            f"the {label} task must have stopped because its probe container exited, got "
            f"stopCode={task.get('stopCode')!r} stoppedReason={task.get('stoppedReason')!r}"
        )


# ===== helpers =====

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_ECS_TASKS_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"


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
            err["Code"] not in ("ClusterNotFoundException", "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound", "NoSuchEntity")
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


def _assert_exit(task, expected, label, expected_role) -> None:
    container = next(c for c in task["containers"] if c["name"] == "app")
    got = container.get("exitCode")
    assert got == expected, (
        f"the {label} probe must report the credentials endpoint serving role {expected_role!r} "
        f"(exit {expected}), but it exited {got!r}: {_MEANING.get(got, 'unrecognised exit code')} "
        f"(reason={container.get('reason')!r}, stoppedReason={task.get('stoppedReason')!r})"
    )


def _task_role(ctx, iam, prefix):
    """A role trusted by ecs-tasks with one harmless permission. Returns (name, arn)."""
    name = ctx.unique_name(prefix)[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST),
        Tags=_ec2_tags(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=name)))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "ecs:DescribeClusters", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    )
    return name, arn


def _execution_role(ctx, iam):
    name = ctx.unique_name("sim2real-behav-ecs-execrole-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST),
        Tags=_ec2_tags(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=name)))
    iam.attach_role_policy(RoleName=name, PolicyArn=_EXEC_POLICY)
    ctx.on_cleanup(
        lambda: _swallow(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_EXEC_POLICY))
    )
    return name, arn


def _create_cluster(ctx, ecs) -> str:
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=_ecs_tags())
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.delete_cluster(cluster=name)))
    return name


def _run(ctx, ecs, cluster, td_arn, net, overrides) -> str:
    """RunTask once, retrying only while the freshly created roles are still propagating."""
    kwargs = dict(
        cluster=cluster,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration=net,
        tags=_ecs_tags(),
    )
    if overrides is not None:
        kwargs["overrides"] = overrides

    def _attempt():
        try:
            return ecs.run_task(**kwargs)
        except ClientError as exc:
            return exc

    resp = _poll_until(
        _attempt,
        lambda r: not isinstance(r, ClientError),
        timeout_s=_RUN_RETRY_S,
        interval_s=10,
        description="the freshly created roles propagate enough for ECS to assume them",
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
        description=f"probe task {arn} runs to completion",
    )
    assert task.get("stopCode") != "TaskFailedToStart", (
        f"task {arn} never started, so the credentials endpoint was never probed: "
        f"stoppedReason={task.get('stoppedReason')!r} containers={task.get('containers')!r}"
    )
    return task


def _public_network(ctx):
    """A dedicated VPC with one public subnet, an IGW and a default route.

    Created unconditionally rather than adopting an ambient default VPC: a freshly provisioned
    account may not have one, and on real AWS the default VPC in some accounts carries a
    dangling DHCP option set that makes every Fargate task fail at launch. The public route is
    load-bearing — the probe pulls busybox from public ECR.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.196.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags()}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.196.0.0/25",
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
