"""e2e-capacity-provider-driven-scaling-flow."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-capacity-provider-driven-scaling-flow"
GROUP = "e2e"
SERVICES = ["ecs"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-ecs-e2e"}
_IN_USE = ("ResourceInUseException", "UpdateInProgressException", "ClusterContainsTasksException",
           "ClusterContainsContainerInstancesException", "ClusterContainsServicesException")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _TAGS.items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _TAGS.items()]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ASG-backed capacity provider drives EC2 container-instance registration and task
    placement as a capacity-provider-strategy service scales 1->0, then every created
    resource (service, capacity provider, ASG, launch template, IAM role, cluster) tears down."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    deleted: set[str] = set()  # resources the happy path below deletes itself; their cleanups skip

    subnet_ids, sg_id = _default_networking(ctx)
    subnet_id = subnet_ids[0]

    role_name, profile_name = _ensure_ecs_instance_profile(ctx, iam)
    ami_id = _ecs_optimized_ami(ssm)

    cluster_name = ctx.unique_name("sim2real-ecs-e2e-cp-")
    ecs.create_cluster(clusterName=cluster_name, tags=_ecs_tags_kv())
    ctx.on_cleanup(lambda: "cluster" in deleted or _safe(
        lambda: ecs.delete_cluster(cluster=cluster_name), "ClusterNotFoundException", retry=_IN_USE))

    lt_name = ctx.unique_name("sim2real-ecs-e2e-lt-")
    user_data = base64.b64encode(
        f"#!/bin/bash\necho ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config\n".encode()
    ).decode()
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": "t3.micro",
            "IamInstanceProfile": {"Name": profile_name},
            "SecurityGroupIds": [sg_id],
            "UserData": user_data,
            "TagSpecifications": [
                {"ResourceType": "instance", "Tags": _tags_kv()},
                {"ResourceType": "volume", "Tags": _tags_kv()},
            ],
        },
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
    )
    ctx.on_cleanup(lambda: "lt" in deleted or _safe(
        lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name), "InvalidLaunchTemplateName.NotFoundException"))

    asg_name = ctx.unique_name("sim2real-ecs-e2e-asg-")
    _create_asg_retrying_iam_propagation(
        autoscaling,
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        NewInstancesProtectedFromScaleIn=False,
        Tags=[{"Key": k, "Value": v, "PropagateAtLaunch": True} for k, v in _TAGS.items()],
    )
    ctx.on_cleanup(
        lambda: "asg" in deleted or _safe(
            lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True),
            retry=("ResourceInUse", "ScalingActivityInProgress"))
    )
    asg_arn = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]["AutoScalingGroupARN"]

    cp_name = ctx.unique_name("sim2real-ecs-e2e-cp-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {"status": "DISABLED"},
            "managedTerminationProtection": "DISABLED",
        },
        tags=_ecs_tags_kv(),
    )

    def _detach_cp_from_cluster():
        _safe(
            lambda: ecs.put_cluster_capacity_providers(
                cluster=cluster_name, capacityProviders=[], defaultCapacityProviderStrategy=[]
            ),
            "ClusterNotFoundException", retry=_IN_USE,
        )

    ctx.on_cleanup(lambda: "cp" in deleted or _safe(
        lambda: ecs.delete_capacity_provider(capacityProvider=cp_name), retry=_IN_USE))
    ctx.on_cleanup(lambda: "cp" in deleted or _detach_cp_from_cluster())

    ecs.put_cluster_capacity_providers(
        cluster=cluster_name,
        capacityProviders=[cp_name],
        defaultCapacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1, "base": 0}],
    )

    # managedScaling is DISABLED, so we drive the ASG ourselves: scale up and wait for the
    # resulting EC2 instance to boot, run the ECS agent, and self-register with the cluster.
    autoscaling.update_auto_scaling_group(AutoScalingGroupName=asg_name, DesiredCapacity=1, MinSize=0)

    def _registered_instances():
        return ecs.list_container_instances(cluster=cluster_name, status="ACTIVE")["containerInstanceArns"]

    instances = _poll_until(_registered_instances, lambda arns: len(arns) >= 1, timeout_s=480.0, interval_s=15.0)
    assert len(instances) >= 1, (
        f"expected >=1 ACTIVE container instance registered to {cluster_name} via the ASG-backed "
        f"capacity provider, got {instances!r}"
    )

    family = ctx.unique_name("sim2real-ecs-e2e-cp-td-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "worker",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", "sleep 3600"],
                "memory": 64,
            }
        ],
        tags=_ecs_tags_kv(),
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    service_name = ctx.unique_name("sim2real-ecs-e2e-cp-svc-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=td_arn,
        desiredCount=1,
        capacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1, "base": 0}],
        tags=_ecs_tags_kv(),
    )
    ctx.on_cleanup(
        lambda: "service" in deleted or _safe(
            lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True),
            "ServiceNotFoundException", "ServiceNotActiveException")
    )

    def _describe_service():
        return ecs.describe_services(cluster=cluster_name, services=[service_name])["services"][0]

    steady = _poll_until(_describe_service, lambda s: s["runningCount"] == 1, timeout_s=300.0, interval_s=10.0)
    assert steady["runningCount"] == 1, (
        f"expected service {service_name} to reach runningCount==1 on the capacity-provider-backed "
        f"instance, got {steady['runningCount']!r} (status={steady.get('status')!r})"
    )

    def _container_instance_running_count():
        arns = ecs.list_container_instances(cluster=cluster_name, status="ACTIVE")["containerInstanceArns"]
        if not arns:
            return 0
        details = ecs.describe_container_instances(cluster=cluster_name, containerInstances=arns)[
            "containerInstances"
        ]
        return sum(ci["runningTasksCount"] for ci in details)

    _poll_until(_container_instance_running_count, lambda n: n >= 1, timeout_s=60.0, interval_s=5.0)

    # Scale back to zero and tear everything down.
    ecs.update_service(cluster=cluster_name, service=service_name, desiredCount=0)
    _poll_until(_describe_service, lambda s: s["runningCount"] == 0, timeout_s=180.0, interval_s=10.0)

    ecs.delete_service(cluster=cluster_name, service=service_name, force=True)
    deleted.add("service")
    _poll_until(
        lambda: ecs.describe_services(cluster=cluster_name, services=[service_name])["services"],
        lambda svcs: not svcs or svcs[0]["status"] == "INACTIVE",
        timeout_s=120.0,
        interval_s=10.0,
    )

    autoscaling.update_auto_scaling_group(AutoScalingGroupName=asg_name, DesiredCapacity=0, MinSize=0)
    _poll_until(_registered_instances, lambda arns: len(arns) == 0, timeout_s=420.0, interval_s=15.0)

    _detach_cp_from_cluster()
    ecs.delete_capacity_provider(capacityProvider=cp_name)
    deleted.add("cp")
    autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    deleted.add("asg")
    ec2.delete_launch_template(LaunchTemplateName=lt_name)
    deleted.add("lt")

    def _cluster_counts():
        return ecs.describe_clusters(clusters=[cluster_name], include=["ATTACHMENTS"])["clusters"][0]

    _poll_until(
        _cluster_counts,
        lambda c: (
            c["runningTasksCount"] == 0
            and c["activeServicesCount"] == 0
            and c["registeredContainerInstancesCount"] == 0
            # DeleteCluster raises UpdateInProgressException while attachments settle; the counts
            # can read zero while attachmentsStatus is still UPDATE_IN_PROGRESS.
            and c.get("attachmentsStatus") in ("UPDATE_COMPLETE", None)
        ),
        timeout_s=180.0,
        interval_s=10.0,
    )

    delete_resp = ecs.delete_cluster(cluster=cluster_name)["cluster"]
    deleted.add("cluster")
    assert delete_resp["status"] in ("INACTIVE", "DEPROVISIONING"), (
        f"expected DeleteCluster's own response status to be INACTIVE/DEPROVISIONING, "
        f"got {delete_resp['status']!r}"
    )

    # Assert on a later DescribeClusters/ListClusters read, not DeleteCluster's own response.
    final_status = _poll_until(
        lambda: (ecs.describe_clusters(clusters=[cluster_name])["clusters"] or [{}])[0].get("status"),
        lambda s: s == "INACTIVE",
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert final_status == "INACTIVE", (
        f"cluster {cluster_name} never settled at INACTIVE via an independent DescribeClusters "
        f"read; last={final_status!r}"
    )

    listed = ecs.list_clusters()["clusterArns"]
    assert not any(cluster_name in arn for arn in listed), (
        f"deleted cluster {cluster_name} still appears in ListClusters: {listed}"
    )



def _safe(fn, *gone, retry=(), wait_s=240.0):
    """Run one teardown call: return on the given not-found codes, retry the ``retry`` codes (a
    dependency still being released) every 2 s for up to ``wait_s``, raise anything else."""
    deadline = time.monotonic() + wait_s
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


def _create_asg_retrying_iam_propagation(autoscaling, *, timeout_s=90.0, interval_s=10.0, **kwargs):
    """Create the ASG, retrying only ValidationError('Invalid IAM Instance Profile name'):
    Auto Scaling's view of IAM lags IAM's own by some seconds. Other errors raise."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            autoscaling.create_auto_scaling_group(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            if (
                code != "ValidationError"
                or "Instance Profile" not in message
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _default_networking(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region; required to place the capacity provider's "
            "EC2 instance and the ECS cluster's default security group"
        )
    vpc = vpcs[0]
    vpc_id = vpc["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return subnet_ids, sg_id


def _ensure_ecs_instance_profile(ctx, iam):
    """Create a throwaway ecsInstanceRole-equivalent role + instance profile for EC2 instances
    that will register themselves as ECS container instances. Cleanups are registered in
    creation order so LIFO teardown unwinds them (role-detach) -> (profile) -> (policy) -> (role)."""
    role_name = ctx.unique_name("sim2real-ecs-e2e-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy, Tags=_tags_kv())
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn), "NoSuchEntity"))

    profile_name = role_name
    iam.create_instance_profile(InstanceProfileName=profile_name, Tags=_tags_kv())
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name), "NoSuchEntity"))

    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name),
                      "NoSuchEntity")
    )

    _poll_until(
        lambda: iam.get_instance_profile(InstanceProfileName=profile_name),
        lambda resp: bool(resp["InstanceProfile"]["Roles"]),
        timeout_s=60.0,
        interval_s=3.0,
    )
    return role_name, profile_name


def _ecs_optimized_ami(ssm):
    resp = ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2/recommended")
    data = json.loads(resp["Parameter"]["Value"])
    return data["image_id"]


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
