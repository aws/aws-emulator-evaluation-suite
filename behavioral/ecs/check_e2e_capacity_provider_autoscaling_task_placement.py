"""e2e-capacity-provider-autoscaling-task-placement."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-capacity-provider-autoscaling-task-placement"
GROUP = "e2e"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A capacity provider backed by a real Auto Scaling group actually
    registers an EC2 container instance with the cluster, and RunTask using
    that capacity provider strategy is genuinely placed on that instance."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    state: dict = {}
    # `_teardown` is registered as a fallback for the exception path only. The happy path tears
    # down explicitly at the end of this function instead, because ctx.on_cleanup's own budget
    # (DEFAULT_CLEANUP_TIMEOUT_S) is far shorter than an ASG force-delete with a live EC2 instance
    # can take to actually settle -- confirming it needs the body's much larger budget, not the
    # cleanup callback's.
    ctx.on_cleanup(lambda: _teardown(ecs, ec2, autoscaling, iam, state, confirm=False))

    subnet_id = _public_subnet(ec2, state)

    cluster_name = ctx.unique_name("sim2real-ecs-cpcluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])
    state["cluster_name"] = cluster_name

    # IAM role + instance profile that lets the ECS agent register the instance.
    role_name = ctx.unique_name("sim2real-ecs-instrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    state["role_name"] = role_name
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
    )
    profile_name = role_name
    iam.create_instance_profile(InstanceProfileName=profile_name)
    state["profile_name"] = profile_name
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)

    ami_id = json.loads(
        ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2/recommended")["Parameter"]["Value"]
    )["image_id"]

    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config\n"
    lt_name = ctx.unique_name("sim2real-ecs-lt-")
    # IAM role/instance-profile visibility to EC2 can lag briefly; retry launch
    # template + ASG creation instead of a bare sleep.
    _poll_until(
        lambda: _try_create_launch_template(ec2, lt_name, ami_id, profile_name, user_data, ctx),
        lambda ok: ok is True,
        timeout_s=90,
        interval_s=10,
    )
    state["lt_name"] = lt_name

    asg_name = ctx.unique_name("sim2real-ecs-asg-")
    # The launch template's own IAM instance profile can still be invisible to the
    # AutoScaling control plane even after CreateLaunchTemplate itself succeeded (observed on
    # real AWS: CreateAutoScalingGroup rejected an already-valid launch template with
    # "Invalid IAM Instance Profile name") -- so this needs the same bounded retry as launch
    # template creation above, not just a comment claiming it already had one.
    _poll_until(
        lambda: _try_create_asg(autoscaling, asg_name, lt_name, subnet_id),
        lambda ok: ok is True,
        timeout_s=120,
        interval_s=10,
    )
    state["asg_name"] = asg_name
    asg_arn = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0][
        "AutoScalingGroupARN"
    ]

    cp_name = ctx.unique_name("sim2real-ecs-cp-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {"status": "DISABLED"},
            "managedTerminationProtection": "DISABLED",
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )
    state["cp_name"] = cp_name

    ecs.put_cluster_capacity_providers(
        cluster=cluster_name,
        capacityProviders=[cp_name],
        defaultCapacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}],
    )
    state["cp_associated"] = True

    container_instance_arns = _poll_until(
        lambda: ecs.list_container_instances(cluster=cluster_name, status="ACTIVE")["containerInstanceArns"],
        lambda arns: len(arns) >= 1,
        timeout_s=600,
        interval_s=20,
    )
    # An independent read (describe_container_instances, not list_) confirming the ECS agent on
    # the ASG-launched instance is actually connected -- "registered" and "usable" are different
    # claims, and only the latter proves the capacity provider's instance can run a task.
    ci_detail = ecs.describe_container_instances(
        cluster=cluster_name, containerInstances=container_instance_arns
    )["containerInstances"][0]
    assert ci_detail["agentConnected"] is True, f"ECS agent not connected: {ci_detail}"

    family = ctx.unique_name("sim2real-ecs-daemonlike-taskdef-")
    td_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["EC2"],
        cpu="128",
        memory="128",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "cpu": 128,
                "memory": 128,
                "essential": True,
                "command": ["sleep", "600"],
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    run_resp = ecs.run_task(
        cluster=cluster_name,
        taskDefinition=td_arn,
        count=1,
        capacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}],
    )
    assert not run_resp["failures"], f"RunTask failures: {run_resp['failures']}"
    task_arn = run_resp["tasks"][0]["taskArn"]
    state["task_arn"] = task_arn

    task = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])["tasks"][0],
        lambda t: t["lastStatus"] in ("RUNNING", "STOPPED"),
        timeout_s=180,
        interval_s=10,
    )
    assert task["lastStatus"] == "RUNNING", f"task did not reach RUNNING: {task.get('stoppedReason')}"
    assert task.get("containerInstanceArn") in container_instance_arns

    # Tear down here, inside the check's own (much larger) body budget, rather than leaving it to
    # ctx.on_cleanup: an ASG force-delete with a live EC2 instance routinely needs minutes to
    # actually settle, which the cleanup callback's own budget cannot reliably cover. See the
    # on_cleanup registration above.
    _teardown(ecs, ec2, autoscaling, iam, state, confirm=True)


# ===== helpers =====
def _try_create_launch_template(ec2, lt_name, ami_id, profile_name, user_data, ctx):
    try:
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={
                "ImageId": ami_id,
                "InstanceType": "t3.micro",
                "IamInstanceProfile": {"Name": profile_name},
                "UserData": base64.b64encode(user_data.encode()).decode(),
                "TagSpecifications": [
                    {
                        "ResourceType": "instance",
                        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ecs-instance-")}],
                    }
                ],
            },
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] in ("InvalidParameterValue", "ValidationError"):
            return False
        raise


def _try_create_asg(autoscaling, asg_name, lt_name, subnet_id):
    try:
        autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
            MinSize=1,
            MaxSize=1,
            DesiredCapacity=1,
            VPCZoneIdentifier=subnet_id,
            NewInstancesProtectedFromScaleIn=False,
            Tags=[
                {"Key": "sim2real", "Value": "true", "ResourceType": "auto-scaling-group", "ResourceId": asg_name}
            ],
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ValidationError" and "Instance Profile" in e.response["Error"].get(
            "Message", ""
        ):
            return False
        raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _safe(fn, *gone, retry=(), deadline=0.0):
    """Run one teardown call: return on the given not-found codes, retry the ``retry`` codes (a
    dependency still being released) every 2 s until ``deadline``, raise anything else."""
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone:
                return
            if code not in retry or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _teardown(ecs, ec2, autoscaling, iam, state, *, confirm):
    """Delete everything this check created.

    ``confirm=True`` (called from the happy path, inside the check's own large body budget) waits
    for the ASG to actually disappear before moving on. ``confirm=False`` (the ``ctx.on_cleanup``
    fallback for the exception path, bound to the much smaller cleanup budget) fires every delete
    without waiting, so a slow ASG teardown cannot starve the cluster/launch-template/IAM deletes
    that follow it. Idempotent either way: each resource leaves ``state`` once deleted, so a second
    pass skips it.
    """
    deadline = time.monotonic() + (300 if confirm else 120)
    in_use = ("ResourceInUseException", "UpdateInProgressException", "ClusterContainsTasksException",
              "ClusterContainsContainerInstancesException")
    cluster_name = state.get("cluster_name")

    if state.get("task_arn"):
        _safe(lambda: ecs.stop_task(cluster=cluster_name, task=state["task_arn"]), "ClusterNotFoundException")
        state.pop("task_arn")

    if cluster_name:
        try:
            ci_arns = ecs.list_container_instances(cluster=cluster_name)["containerInstanceArns"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
            ci_arns = []
        for ci_arn in ci_arns:
            _safe(lambda a=ci_arn: ecs.deregister_container_instance(cluster=cluster_name, containerInstance=a, force=True),
                  "ClusterNotFoundException")

    if state.get("cp_associated") and cluster_name:
        _safe(
            lambda: ecs.put_cluster_capacity_providers(
                cluster=cluster_name, capacityProviders=[], defaultCapacityProviderStrategy=[]
            ),
            "ClusterNotFoundException", retry=in_use, deadline=deadline,
        )
        state.pop("cp_associated")

    if state.get("asg_name"):
        _safe(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=state["asg_name"], ForceDelete=True),
              retry=("ResourceInUse", "ScalingActivityInProgress"), deadline=deadline)
        if confirm:
            _poll_until(
                lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[state["asg_name"]])[
                    "AutoScalingGroups"
                ],
                lambda groups: len(groups) == 0,
                timeout_s=300,
                interval_s=2,
            )
            # The ASG wait above must not use up the in-use retries of the deletes below.
            deadline = time.monotonic() + 300
        state.pop("asg_name")

    if state.get("lt_name"):
        _safe(lambda: ec2.delete_launch_template(LaunchTemplateName=state["lt_name"]),
              "InvalidLaunchTemplateName.NotFoundException")
        state.pop("lt_name")

    if state.get("cp_name"):
        _safe(lambda: ecs.delete_capacity_provider(capacityProvider=state["cp_name"]),
              retry=in_use, deadline=deadline)
        state.pop("cp_name")

    if cluster_name:
        _safe(lambda: ecs.delete_cluster(cluster=cluster_name), "ClusterNotFoundException",
              retry=in_use, deadline=deadline)
        state.pop("cluster_name")

    if state.get("profile_name") and state.get("role_name"):
        _safe(
            lambda: iam.remove_role_from_instance_profile(
                InstanceProfileName=state["profile_name"], RoleName=state["role_name"]
            ),
            "NoSuchEntity",
        )
        _safe(lambda: iam.delete_instance_profile(InstanceProfileName=state["profile_name"]), "NoSuchEntity")
        state.pop("profile_name")
    if state.get("role_name"):
        _safe(
            lambda: iam.detach_role_policy(
                RoleName=state["role_name"],
                PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
            ),
            "NoSuchEntity",
        )
        _safe(lambda: iam.delete_role(RoleName=state["role_name"]), "NoSuchEntity")
        state.pop("role_name")

    _teardown_network(ec2, state, wait_s=300 if confirm else 120)


_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _public_subnet(ec2, state):
    """A public subnet in a VPC this check creates, so the container instance's ECS agent
    can reach the ECS endpoint. Ids land in ``state`` for ``_teardown_network``."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.197.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    state["vpc_id"] = vpc_id
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.197.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
    )["Subnet"]["SubnetId"]
    state["subnet_id"] = subnet_id
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _NET_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    state["igw_id"] = igw_id
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"][0][
        "RouteTableId"
    ]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    return subnet_id


def _teardown_network(ec2, state, *, wait_s):
    """Delete the subnet, internet gateway and VPC once the terminated instance's ENI is gone."""
    vpc_id = state.get("vpc_id")
    if not vpc_id:
        return
    deadline = time.monotonic() + wait_s
    subnet_id = state.get("subnet_id")
    while subnet_id:
        try:
            ec2.delete_subnet(SubnetId=subnet_id)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidSubnetID.NotFound":
                break
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    igw_id = state.get("igw_id")
    if igw_id:
        _safe(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
              "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound")
        _safe(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id), "InvalidInternetGatewayID.NotFound")
    try:
        ec2.delete_vpc(VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise
    state.pop("vpc_id", None)


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
