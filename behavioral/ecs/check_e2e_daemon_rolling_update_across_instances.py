"""e2e-daemon-rolling-update-across-instances."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError, WaiterError

CHECK = "e2e-daemon-rolling-update-across-instances"
GROUP = "e2e"
SERVICES = ["ecs"]

_INFRA_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"
_INSTANCE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Updating a daemon's task definition starts a new-revision task on the daemon's Managed
    Instances container instance and stops the old-revision task there, not just a version bump;
    Daemon services accept only MANAGED_INSTANCES capacity providers."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    state: dict = {}
    ctx.on_cleanup(lambda: _teardown(ecs, ec2, iam, state))

    subnet_ids, sg_id = _default_network(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-daemoncluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    state["cluster_name"] = cluster_name

    infra_role_arn = _create_infra_role(ctx, iam, state)
    instance_profile_arn = _create_instance_profile(ctx, iam, state, infra_role_arn)

    # ECS can try the just-created infrastructure role before IAM has propagated it; the provider
    # then ends INACTIVE with updateStatus CREATE_FAILED ("Caught ServiceAccessDeniedException
    # for ECSInfrastructureRole"). That one outcome is retried with a fresh provider.
    for attempt in range(4):
        cp_name = ctx.unique_name("sim2real-ecs-daemon-cp-")
        cp_arn = _poll_until(
            lambda: _try_create_managed_instances_capacity_provider(
                ecs, cp_name, cluster_name, infra_role_arn, instance_profile_arn, subnet_ids, sg_id
            ),
            lambda result: result is not None,
            timeout_s=120,
            interval_s=10,
        )
        state.setdefault("cp_arns", []).append(cp_arn)

        # Positive control, via an independent read: the Managed Instances capacity provider must
        # actually converge on ACTIVE before anything daemon-specific is attempted on top of it.
        cp_state = _poll_until(
            lambda: ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"][0],
            lambda cp: cp["status"] != "PROVISIONING",
            timeout_s=600,
            interval_s=15,
        )
        left = ctx.time_left()
        if ("ServiceAccessDeniedException" not in (cp_state.get("updateStatusReason") or "")
                or attempt == 3 or (left is not None and left < 60)):
            break
        # The failed provider (and any instance it launched before failing) goes before the retry.
        _delete_capacity_provider_and_wait(ecs, cp_arn)
        _terminate_tagged_instances(ec2, cluster_name)
        time.sleep(2)
    state["cp_name"] = cp_name
    assert cp_state["status"] == "ACTIVE", (
        f"managed-instances capacity provider never reached ACTIVE: {cp_state}"
    )

    ecs.put_cluster_capacity_providers(
        cluster=cluster_name,
        capacityProviders=[cp_name],
        defaultCapacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}],
    )
    state["cp_associated"] = True

    family = ctx.unique_name("sim2real-ecs-daemon-taskdef-")
    td_v1_arn = ecs.register_daemon_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "cpu": 128,
                "memory": 128,
                "essential": True,
                "command": ["sleep", "3600"],
            }
        ],
        cpu="128",
        memory="128",
    )["daemonTaskDefinitionArn"]
    state["td_v1_arn"] = td_v1_arn

    daemon_name = ctx.unique_name("sim2real-ecs-daemon-")
    try:
        create_resp = ecs.create_daemon(
            daemonName=daemon_name,
            clusterArn=cluster_arn,
            daemonTaskDefinitionArn=td_v1_arn,
            capacityProviderArns=[cp_arn],
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "UnsupportedFeatureException":
            raise AssertionError("ECS daemon feature is not enabled for this account/region") from e
        raise
    daemon_arn = create_resp["daemonArn"]
    state["daemon_arn"] = daemon_arn
    deployment_arn_v1 = create_resp["deploymentArn"]

    # Daemons do not launch instances: a Managed Instances provider provisions one only for an
    # application task (docs: "Amazon ECS Managed Daemons"). A one-task service on the provider
    # creates that demand, and keeps it through the rolling update's instance replacement.
    _start_demand_service(ctx, ecs, cluster_name, cp_name, subnet_ids, sg_id)
    _poll_until(
        lambda: ecs.list_container_instances(cluster=cluster_name, status="ACTIVE")["containerInstanceArns"],
        lambda arns: len(arns) >= 1,
        timeout_s=900,
        interval_s=20,
    )

    _poll_until(
        lambda: ecs.describe_daemon_deployments(daemonDeploymentArns=[deployment_arn_v1])["daemonDeployments"][0][
            "status"
        ],
        lambda status: status == "SUCCESSFUL",
        timeout_s=600,
        interval_s=15,
    )

    v1_task_arns = _poll_until(
        lambda: ecs.list_tasks(cluster=cluster_name, daemonName=daemon_name, desiredStatus="RUNNING")["taskArns"],
        lambda arns: len(arns) >= 1,
        timeout_s=180,
        interval_s=10,
    )
    v1_task = ecs.describe_tasks(cluster=cluster_name, tasks=v1_task_arns)["tasks"][0]
    assert v1_task["taskDefinitionArn"] == td_v1_arn, (
        f"expected the daemon's first task to run td_v1 {td_v1_arn!r}, got {v1_task['taskDefinitionArn']!r}"
    )
    old_task_arn = v1_task["taskArn"]

    td_v2_arn = ecs.register_daemon_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "cpu": 128,
                "memory": 128,
                "essential": True,
                "command": ["sleep", "3601"],
            }
        ],
        cpu="128",
        memory="128",
    )["daemonTaskDefinitionArn"]
    state["td_v2_arn"] = td_v2_arn
    assert td_v2_arn != td_v1_arn, f"RegisterDaemonTaskDefinition must mint a new revision arn, got the same {td_v2_arn!r}"

    update_resp = ecs.update_daemon(
        daemonArn=daemon_arn, daemonTaskDefinitionArn=td_v2_arn, capacityProviderArns=[cp_arn]
    )
    deployment_arn_v2 = update_resp["deploymentArn"]

    _poll_until(
        lambda: ecs.describe_daemon_deployments(daemonDeploymentArns=[deployment_arn_v2])["daemonDeployments"][0][
            "status"
        ],
        lambda status: status == "SUCCESSFUL",
        timeout_s=600,
        interval_s=15,
    )

    v2_task_arns = _poll_until(
        lambda: ecs.list_tasks(cluster=cluster_name, daemonName=daemon_name, desiredStatus="RUNNING")["taskArns"],
        lambda arns: len(arns) >= 1 and arns != [old_task_arn],
        timeout_s=180,
        interval_s=10,
    )
    v2_task = ecs.describe_tasks(cluster=cluster_name, tasks=v2_task_arns)["tasks"][0]
    assert v2_task["taskDefinitionArn"] == td_v2_arn, (
        f"expected the replacement task to run td_v2 {td_v2_arn!r}, got {v2_task['taskDefinitionArn']!r}"
    )

    old_task_after = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_name, tasks=[old_task_arn])["tasks"][0],
        lambda t: t["lastStatus"] == "STOPPED",
        timeout_s=120,
        interval_s=10,
    )
    assert old_task_after["lastStatus"] == "STOPPED", (
        f"expected the old-revision task to have been stopped by the rolling update, "
        f"got lastStatus={old_task_after['lastStatus']!r}"
    )


# ===== helpers =====
def _start_demand_service(ctx, ecs, cluster_name, cp_name, subnet_ids, sg_id):
    family = ctx.unique_name("sim2real-ecs-daemon-app-")
    td_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["MANAGED_INSTANCES"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[{
            "name": "app",
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "essential": True,
            "command": ["sleep", "3600"],
        }],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))
    service = ctx.unique_name("sim2real-ecs-daemon-app-svc-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=service,
        taskDefinition=td_arn,
        desiredCount=1,
        capacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}],
        networkConfiguration={"awsvpcConfiguration": {"subnets": subnet_ids[:1], "securityGroups": [sg_id]}},
    )

    def _delete_service():
        try:
            ecs.delete_service(cluster=cluster_name, service=service, force=True)
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("ServiceNotFoundException", "ServiceNotActiveException"):
                raise
        ecs.get_waiter("services_inactive").wait(
            cluster=cluster_name, services=[service], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    ctx.on_cleanup(_delete_service)
    return service


def _try_create_managed_instances_capacity_provider(
    ecs, cp_name, cluster_name, infra_role_arn, instance_profile_arn, subnet_ids, sg_id
):
    try:
        return ecs.create_capacity_provider(
            name=cp_name,
            cluster=cluster_name,
            managedInstancesProvider={
                "infrastructureRoleArn": infra_role_arn,
                "instanceLaunchTemplate": {
                    "ec2InstanceProfileArn": instance_profile_arn,
                    "networkConfiguration": {"subnets": subnet_ids[:1], "securityGroups": [sg_id]},
                    "monitoring": "basic",
                },
            },
        )["capacityProvider"]["capacityProviderArn"]
    except ClientError as e:
        # The infra/instance IAM roles just created can still be invisible to ECS's own
        # IAM cache for a few seconds after IAM itself reports them as created.
        if e.response["Error"]["Code"] in ("ClientException", "InvalidParameterException"):
            return None
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


def _already_gone(e) -> bool:
    """ECS answers a delete of a resource that is already gone or INACTIVE with the broad
    ClientException; only that meaning, read from its message, counts as gone."""
    message = e.response["Error"].get("Message", "").lower()
    return e.response["Error"]["Code"] == "ClientException" and any(
        word in message for word in ("inactive", "not found", "does not exist", "not exist")
    )


def _delete_capacity_provider_and_wait(ecs, cp_arn, timeout_s=300.0):
    try:
        ecs.delete_capacity_provider(capacityProvider=cp_arn)
    except ClientError as e:
        # An INACTIVE (failed) or already-deleted provider is gone for delete purposes.
        if not _already_gone(e):
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        found = ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"]
        if not found or found[0]["status"] == "INACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"capacity provider {cp_arn} still not INACTIVE {timeout_s}s after DeleteCapacityProvider")


def _terminate_tagged_instances(ec2, cluster_name):
    reservations = ec2.describe_instances(
        Filters=[
            {"Name": "tag:aws:ecs:clusterName", "Values": [cluster_name]},
            {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped", "shutting-down"]},
        ]
    )["Reservations"]
    instance_ids = [i["InstanceId"] for r in reservations for i in r["Instances"]]
    if instance_ids:
        ec2.terminate_instances(InstanceIds=instance_ids)
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=instance_ids, WaiterConfig={"Delay": 2, "MaxAttempts": 200}
        )


def _deregister_container_instances(ecs, cluster_name):
    for ci_arn in ecs.list_container_instances(cluster=cluster_name)["containerInstanceArns"]:
        ecs.deregister_container_instance(cluster=cluster_name, containerInstance=ci_arn, force=True)


def _delete_cluster_retrying(ecs, cluster_arn, timeout_s=180.0):
    """DeleteCluster, retried while the cluster still drains tasks, instances or providers."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in (
                "ClusterContainsContainerInstancesException", "ClusterContainsTasksException",
                "ClusterContainsServicesException", "ClusterContainsCapacityProviderException",
                "UpdateInProgressException",
            ) or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


def _teardown(ecs, ec2, iam, state):
    """Every step runs even if an earlier one fails; only an already-absent resource is fine.
    Raises at the end naming each step that failed."""
    steps = []

    def step(label, fn, ok_codes=()):
        steps.append((label, fn, ok_codes))

    cluster_name = state.get("cluster_name")
    gone = ("ResourceNotFoundException", "ClusterNotFoundException")
    if state.get("daemon_arn"):
        step("delete daemon", lambda: ecs.delete_daemon(daemonArn=state["daemon_arn"]), gone)
    for key in ("td_v1_arn", "td_v2_arn"):
        if state.get(key):
            step(key, lambda k=key: ecs.delete_daemon_task_definition(daemonTaskDefinition=state[k]), gone)
    if state.get("cp_associated") and cluster_name:
        step("disassociate capacity providers", lambda: ecs.put_cluster_capacity_providers(
            cluster=cluster_name, capacityProviders=[], defaultCapacityProviderStrategy=[]
        ), gone)
    for cp_arn in state.get("cp_arns", []):
        step(f"delete {cp_arn}", lambda a=cp_arn: _delete_capacity_provider_and_wait(ecs, a), gone)
    # A Managed Instances provider can launch an instance that never registers as a container
    # instance; anything EC2 tags with THIS check's cluster is terminated and waited out.
    if cluster_name:
        step("terminate cluster instances", lambda: _terminate_tagged_instances(ec2, cluster_name))
        step("deregister container instances", lambda: _deregister_container_instances(ecs, cluster_name), gone)
        step("delete cluster", lambda: _delete_cluster_retrying(ecs, cluster_name), gone)
    if state.get("instance_profile_name") and state.get("instance_role_name"):
        step("remove role from instance profile", lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=state["instance_profile_name"], RoleName=state["instance_role_name"]
        ), ("NoSuchEntity",))
        step("delete instance profile", lambda: iam.delete_instance_profile(
            InstanceProfileName=state["instance_profile_name"]), ("NoSuchEntity",))
    if state.get("instance_role_name"):
        step("detach instance role policy", lambda: iam.detach_role_policy(
            RoleName=state["instance_role_name"], PolicyArn=_INSTANCE_POLICY_ARN), ("NoSuchEntity",))
        step("delete instance role", lambda: iam.delete_role(RoleName=state["instance_role_name"]), ("NoSuchEntity",))
    if state.get("infra_role_name"):
        step("detach infra role policy", lambda: iam.detach_role_policy(
            RoleName=state["infra_role_name"], PolicyArn=_INFRA_POLICY_ARN), ("NoSuchEntity",))
        step("delete infra inline policy", lambda: iam.delete_role_policy(
            RoleName=state["infra_role_name"], PolicyName="pass-instance-role"), ("NoSuchEntity",))
        step("delete infra role", lambda: iam.delete_role(RoleName=state["infra_role_name"]), ("NoSuchEntity",))
    errors = []
    for label, fn, ok_codes in steps:
        try:
            fn()
        except (ClientError, WaiterError, AssertionError) as e:
            # A waiter or bounded wait that gives up is recorded like a failed call, so every
            # later step still runs; all of them are raised together below.
            if not (isinstance(e, ClientError) and (e.response["Error"]["Code"] in ok_codes or _already_gone(e))):
                errors.append(f"{label}: {e}")
    if errors:
        raise RuntimeError(f"{len(errors)} teardown step(s) failed: " + "; ".join(errors))


def _create_infra_role(ctx, iam, state) -> str:
    role_name = ctx.unique_name("sim2real-ecs-daemon-infra-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    state["infra_role_name"] = role_name
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_INFRA_POLICY_ARN)
    return role_arn


def _create_instance_profile(ctx, iam, state, infra_role_arn) -> str:
    role_name = ctx.unique_name("sim2real-ecs-daemon-instrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    instance_role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    state["instance_role_name"] = role_name
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_INSTANCE_POLICY_ARN)

    profile_name = role_name
    profile_arn = iam.create_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Arn"]
    state["instance_profile_name"] = profile_name
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)

    infra_role_name = state["infra_role_name"]
    iam.put_role_policy(
        RoleName=infra_role_name,
        PolicyName="pass-instance-role",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": instance_role_arn}],
            }
        ),
    )

    _poll_until(
        lambda: iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Roles"],
        lambda roles: len(roles) >= 1,
        timeout_s=30.0,
        interval_s=2.0,
    )
    return profile_arn


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region for launching EC2 container instances")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    subnet_ids = [s["SubnetId"] for s in subnets]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group available")
    sg_id = sgs[0]["GroupId"]
    return subnet_ids, sg_id


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
