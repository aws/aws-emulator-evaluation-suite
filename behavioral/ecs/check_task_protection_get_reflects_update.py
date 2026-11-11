"""task-protection-get-reflects-update."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "task-protection-get-reflects-update"
GROUP = "state-machine"
SERVICES = ["ecs"]


# When the ECS service scheduler's first task-placement attempt fails (an execution role or
# service-linked role still propagating, Fargate capacity held by the standalone task, an ENI
# still detaching), it backs off its next attempt for far longer than the cause takes to clear.
# So the check issues CreateService only after the execution role is proven assumable and the
# standalone task is STOPPED with its ENI detached. The service may still need a fresh placement
# attempt: poll each service up to _SERVICE_PLACEMENT_ATTEMPT_BUDGET_S, recreate it under a new
# name if no task was placed, and keep the whole check under the runner's per-check limit by
# tracking elapsed time against _TOTAL_BUDGET_S.
_TOTAL_BUDGET_S = 285.0
_STANDALONE_ROLE_RETRY_BUDGET_S = 30.0
_STANDALONE_STOP_POLL_BUDGET_S = 25.0
_SERVICE_PLACEMENT_ATTEMPT_BUDGET_S = 90.0
_MIN_REMAINING_TO_RETRY_SERVICE_S = 30.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTaskProtection reflects the protection status most recently set by UpdateTaskProtection."""

    start_time = time.monotonic()

    # Unlike a standalone RunTask, the ECS service scheduler depends on the account's
    # `AWSServiceRoleForECS` service-linked role to place tasks. ECS creates that role lazily on
    # first use in an account/region, and a just-created role can still be propagating when the
    # scheduler makes its first placement attempt. Create it first, so its IAM propagation
    # overlaps the rest of the setup below.
    _ensure_ecs_service_linked_role(ctx)

    env = _setup_fargate_env(ctx)
    ecs = ctx.client("ecs")
    cluster_name = env["cluster_name"]

    # Boundary: UpdateTaskProtection on a standalone (non-service) RunTask task is rejected. Do
    # this FIRST (role-propagation retry included) so it also proves the freshly-created
    # execution role is actually assumable by ECS *before* the service ever attempts its own
    # task placement -- see the module-level comment above for why letting CreateService's first
    # placement attempt race the role's propagation delay leads the ECS service scheduler to back
    # off its next attempt for far longer than this bounded retry loop ever takes.
    standalone = _run_task_with_role_retry(
        ecs,
        timeout_s=_STANDALONE_ROLE_RETRY_BUDGET_S,
        cluster=cluster_name,
        taskDefinition=env["task_def_arn"],
        launchType="FARGATE",
        networkConfiguration=env["network_configuration"],
        count=1,
    )
    assert not standalone.get("failures"), f"RunTask failed: {standalone.get('failures')}"
    standalone_task_arn = standalone["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _stop_task_best_effort(ecs, cluster_name, standalone_task_arn))

    # Boundary assertions: a task that doesn't belong to a service can't be protected.
    boundary = ecs.update_task_protection(cluster=cluster_name, tasks=[standalone_task_arn], protectionEnabled=True)

    assert boundary["protectedTasks"] == [], f"expected no protected tasks for a standalone task, got {boundary['protectedTasks']}"
    assert len(boundary["failures"]) == 1, f"expected exactly one failure entry, got {boundary['failures']}"
    # Real AWS doesn't always echo back the identical ARN string you passed in the "arn" field
    # of a Failure record (e.g. it can normalize container-instance-style path segments); the
    # meaningful invariant is that the failure names the same task, i.e. the same task ID.
    failure_arn = boundary["failures"][0]["arn"]
    assert failure_arn.rsplit("/", 1)[-1] == standalone_task_arn.rsplit("/", 1)[-1], (
        f"expected the failure to reference the standalone task {standalone_task_arn}, got {failure_arn}"
    )
    assert boundary["failures"][0]["reason"] == "TASK_NOT_VALID", (
        f"expected TASK_NOT_VALID for a standalone task, got {boundary['failures'][0]['reason']}"
    )

    # The standalone task has served its purpose (proving both the role is assumable and the
    # TASK_NOT_VALID boundary) -- stop it and wait for it to actually reach STOPPED (freeing its
    # Fargate capacity in this cluster/subnets) *before* CreateService's first task-placement
    # attempt ever fires. See the module-level comment above for why racing CreateService against a
    # still-running standalone task in the same capacity pool reproduces the exact same
    # first-attempt-fails-then-long-backoff pathology as the role-propagation race, just for
    # capacity instead of IAM.
    _stop_task_best_effort(ecs, cluster_name, standalone_task_arn)

    # Wait for both the task record to flip to STOPPED AND its awsvpc ENI attachment to be
    # released, not just the former. On real AWS, a STOPPED task's ENI detachment (which is
    # what actually frees the subnet capacity/IP the next placement attempt needs) measurably
    # lags the task's own lastStatus flipping to STOPPED -- a service creation that races that
    # lag can still lose its very first placement attempt to the still-attaching/detaching ENI,
    # reproducing the same first-attempt-fails-then-long-scheduler-backoff pathology described
    # in the module-level comment above.
    def _standalone_capacity_released():
        d = ecs.describe_tasks(cluster=cluster_name, tasks=[standalone_task_arn])["tasks"]
        if not d:
            return True
        task = d[0]
        if task["lastStatus"] != "STOPPED":
            return False
        attachments = task.get("attachments") or []
        if not attachments:
            return True
        return all(a.get("status") in ("DELETED", "DETACHED") for a in attachments)

    _poll_until(
        _standalone_capacity_released,
        lambda released: released,
        timeout_s=_STANDALONE_STOP_POLL_BUDGET_S,
        interval_s=3.0,
    )

    # Now that the standalone task is confirmed stopped (its capacity freed) and the execution
    # role has already been proven assumable, kick off the SERVICE: its very first
    # task-placement attempt races neither IAM propagation nor capacity contention with the
    # standalone task.
    def _create_fresh_service():
        name = ctx.unique_name("sim2real-tp-svc-")
        # Retry CreateService itself while ECS reports it still can't use the (possibly
        # just-created, still-propagating) service-linked role -- the synchronous counterpart to
        # the asynchronous "scheduler backs off after its first placement attempt" pathology
        # described above: on real AWS, a not-yet-ready service-linked role can also surface as
        # an immediate ClientError on CreateService itself rather than only as a silently-stalled
        # scheduler.
        _create_service_with_role_retry(
            ecs,
            timeout_s=_STANDALONE_ROLE_RETRY_BUDGET_S,
            cluster=cluster_name,
            serviceName=name,
            taskDefinition=env["task_def_arn"],
            desiredCount=1,
            launchType="FARGATE",
            networkConfiguration=env["network_configuration"],
        )
        ctx.on_cleanup(lambda: _delete_service_best_effort(ecs, cluster_name, name))
        return name

    # Poll for a task belonging to the given service, re-querying the service's live tasks each
    # attempt rather than sticking to the first ARN observed: on real AWS the very first task can
    # fail fast and get replaced by a fresh ARN, so pinning to the initial ARN can spin forever
    # watching a task that is (and will remain) STOPPED. Distinguish three outcomes rather than
    # collapsing them all to a single None:
    #   - "running": a task is actually RUNNING -- done.
    #   - "pending": the service HAS placed a task (desiredStatus RUNNING) that just hasn't
    #     reached RUNNING yet (e.g. still pulling its image / attaching its ENI). This is normal,
    #     bounded Fargate startup latency, not a stuck scheduler -- it must NOT be treated the
    #     same as a placement failure, or a genuinely-in-progress task gets thrown away and its
    #     progress reset right as it might have been about to reach RUNNING.
    #   - "empty": the service has placed NO task at all. This is the actual signature of the
    #     scheduler-backoff pathology described in the module-level comment above (first placement
    #     attempt rejected, next one backed off far longer than this sub-window) -- only THIS
    #     outcome warrants deleting the service and trying a fresh one.
    def _service_task_status(name):
        arns = ecs.list_tasks(cluster=cluster_name, serviceName=name, desiredStatus="RUNNING")["taskArns"]
        if not arns:
            return "empty", None
        statuses = ecs.describe_tasks(cluster=cluster_name, tasks=arns)["tasks"]
        for t in statuses:
            if t["lastStatus"] == "RUNNING":
                return "running", t["taskArn"]
        # Not RUNNING yet -- return the (still-pending) task's own ARN, not None, so the caller
        # can actually tell "the same task is still pending" apart from "a different task
        # replaced it" (both previously collapsed to the same `None`, which made the
        # same-task-pending-too-long stuck detection below unable to track anything).
        if statuses:
            return "pending", statuses[0]["taskArn"]
        return "pending", None

    # A longer poll on a single service does not get past a scheduler backoff after a failed
    # first attempt. Bound each individual service's
    # placement attempt to a modest sub-window; if that window elapses with the service having
    # placed NO task whatsoever ("empty" the whole time), delete it and create a fresh one (a new
    # scheduler queue entry, unaffected by whatever backoff the previous attempt triggered) and
    # try again. But if the service DID manage to place a task that's merely still starting up
    # ("pending" at least once), keep polling that same service/task instead of discarding
    # in-progress startup progress -- only the shared total budget tracked from the top of this
    # check bounds that continued wait.
    # A task that is merely slow to start and one permanently stuck in PENDING/PROVISIONING
    # (e.g. an AZ out of capacity for this placement) both read as "pending". Track how long the
    # SAME task ARN has been seen "pending"; the nginx image normally reaches RUNNING within
    # ~90s, so a task still "pending" well past that is treated as stuck and gets a fresh
    # service, like the "placed nothing at all" case handled below.
    _MAX_SINGLE_TASK_PENDING_S = 170.0

    service_name = _create_fresh_service()
    task_arn = None
    pending_arn = None
    pending_since = None
    while task_arn is None:
        remaining_s = _TOTAL_BUDGET_S - (time.monotonic() - start_time)
        if remaining_s <= 0:
            raise AssertionError(
                "no RUNNING service task observed within the shared total check budget "
                f"({_TOTAL_BUDGET_S}s), even after recreating the service to dodge scheduler backoff"
            )
        attempt_budget_s = min(_SERVICE_PLACEMENT_ATTEMPT_BUDGET_S, remaining_s)
        attempt_deadline = time.monotonic() + attempt_budget_s
        saw_placement = False
        stuck = False
        while time.monotonic() < attempt_deadline:
            status, arn = _service_task_status(service_name)
            if status == "running":
                task_arn = arn
                break
            if status == "pending":
                saw_placement = True
                if arn != pending_arn or pending_since is None:
                    pending_arn = arn
                    pending_since = time.monotonic()
                elif time.monotonic() - pending_since > _MAX_SINGLE_TASK_PENDING_S:
                    # The SAME task has been merely "pending" for far longer than genuine
                    # (if slow) Fargate startup ever takes -- it's stuck, not progressing.
                    stuck = True
                    break
            else:
                # "empty": whatever was pending before is gone (replaced/failed); forget it so a
                # freshly-placed task under the SAME service gets its own fresh pending clock.
                pending_arn = None
                pending_since = None
            time.sleep(5.0)
        if task_arn is not None:
            break
        remaining_after_attempt_s = _TOTAL_BUDGET_S - (time.monotonic() - start_time)
        if remaining_after_attempt_s <= 0:
            raise AssertionError(
                "no RUNNING service task observed within the shared total check budget "
                f"({_TOTAL_BUDGET_S}s)"
            )
        if (saw_placement and not stuck) or remaining_after_attempt_s < _MIN_REMAINING_TO_RETRY_SERVICE_S:
            # Either the service is making real (if slow) progress on an already-placed task that
            # hasn't yet exceeded the stuck bound, or there isn't enough budget left to usefully
            # recreate the service -- either way, keep polling the SAME service/task rather than
            # discarding it.
            continue
        _delete_service_best_effort(ecs, cluster_name, service_name)
        service_name = _create_fresh_service()
        pending_arn = None
        pending_since = None

    enable_resp = ecs.update_task_protection(
        cluster=cluster_name, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=5
    )
    assert not enable_resp["failures"], enable_resp["failures"]
    # Real AWS doesn't always echo back the identical ARN string you passed in (observed: the
    # UpdateTaskProtection response's taskArn omits the cluster-name path segment that
    # ListTasks/DescribeTasks include) -- the meaningful invariant is the task ID, not the ARN
    # shape. Same normalization already used for the standalone-task failure ARN above.
    enabled_task_arn = enable_resp["protectedTasks"][0]["taskArn"]
    assert enabled_task_arn.rsplit("/", 1)[-1] == task_arn.rsplit("/", 1)[-1], (
        f"expected the protected task to be {task_arn}, got {enabled_task_arn}"
    )
    assert enable_resp["protectedTasks"][0]["protectionEnabled"] is True, (
        f"expected protectionEnabled True right after enabling it, got {enable_resp['protectedTasks'][0]['protectionEnabled']}"
    )

    got_enabled = ecs.get_task_protection(cluster=cluster_name, tasks=[task_arn])
    assert got_enabled["protectedTasks"][0]["protectionEnabled"] is True, (
        f"expected GetTaskProtection to report protectionEnabled True, got {got_enabled['protectedTasks'][0]['protectionEnabled']}"
    )
    assert "expirationDate" in got_enabled["protectedTasks"][0], (
        f"expected an expirationDate on an enabled protection, got {got_enabled['protectedTasks'][0]}"
    )

    disable_resp = ecs.update_task_protection(cluster=cluster_name, tasks=[task_arn], protectionEnabled=False)
    assert not disable_resp["failures"], disable_resp["failures"]
    assert disable_resp["protectedTasks"][0]["protectionEnabled"] is False, (
        f"expected protectionEnabled False right after disabling it, got {disable_resp['protectedTasks'][0]['protectionEnabled']}"
    )

    got_disabled = ecs.get_task_protection(cluster=cluster_name, tasks=[task_arn])
    assert got_disabled["protectedTasks"][0]["protectionEnabled"] is False, (
        "GetTaskProtection must reflect the most recent UpdateTaskProtection call, not a stale enabled state"
    )


# ===== helpers =====

def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _run_task_with_role_retry(ecs, timeout_s=60.0, **kwargs):
    """IAM roles are eventually consistent; retry RunTask while ECS can't yet assume the
    execution role we just created/attached ("ECS was unable to assume the role ...")."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ecs.run_task(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = str(err)
            last_err = err
            if code == "ClientException" and "ssume" in msg.lower():
                time.sleep(5)
                continue
            raise
    raise last_err if last_err is not None else RuntimeError("RunTask never succeeded")


def _ensure_ecs_service_linked_role(ctx):
    """Proactively create ECS's service-linked role (AWSServiceRoleForECS) if it doesn't already
    exist in this account/region. Unlike a standalone RunTask (which needs no service-linked
    role at all), the ECS SERVICE scheduler depends on it to place tasks; if it's freshly
    auto-created on first use it can still be propagating when CreateService's scheduler makes
    its first placement attempt. Calling this as the very first thing this check does lets that
    propagation race in parallel with all the other independent setup that happens before
    CreateService is ever issued, at no extra wall-clock cost."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as err:
        # InvalidInput: the role already exists in this account -- nothing to propagate.
        if err.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_service_with_role_retry(ecs, timeout_s=30.0, **kwargs):
    """Retry CreateService while ECS reports it still can't use the (possibly just-created,
    still-propagating) service-linked role -- the synchronous counterpart to
    `_ensure_ecs_service_linked_role`'s asynchronous propagation wait."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ecs.create_service(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = str(err)
            last_err = err
            if code in ("ClientException", "InvalidParameterException") and (
                "ssume" in msg.lower() or "service-linked role" in msg.lower() or "service linked role" in msg.lower()
            ):
                time.sleep(5)
                continue
            raise
    raise last_err if last_err is not None else RuntimeError("CreateService never succeeded")


def _stop_task_best_effort(ecs, cluster_name, task_arn):
    from botocore.exceptions import ClientError

    try:
        ecs.stop_task(cluster=cluster_name, task=task_arn, reason="sim2real cleanup")
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ClusterNotFoundException":
            return
        if err["Code"] == "InvalidParameterException" and "not found" in err.get("Message", "").lower():
            return
        raise


def _delete_service_best_effort(ecs, cluster_name, service_name):
    from botocore.exceptions import ClientError

    try:
        ecs.delete_service(cluster=cluster_name, service=service_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException", "ServiceNotFoundException", "ServiceNotActiveException",
        ):
            raise


_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _own_network(ctx):
    """Create a dedicated VPC with one public subnet (internet gateway + default route,
    so a Fargate task can pull a public-ECR image) and return
    {"vpc_id", "subnet_ids", "sg_id"} using that VPC's own default security group.

    One cleanup tears the stack down; it is registered before any ECS resource, so it
    runs last and first waits out the Fargate ENIs that linger after tasks stop."""
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.198.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    state = {"subnet_id": None, "igw_id": None}

    def _teardown_network():
        deadline = time.monotonic() + 540
        subnet_id, igw_id = state["subnet_id"], state["igw_id"]
        if subnet_id:
            while time.monotonic() < deadline:
                enis = ec2.describe_network_interfaces(
                    Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
                ).get("NetworkInterfaces", [])
                if not enis:
                    break
                time.sleep(10)
            while True:
                try:
                    ec2.delete_subnet(SubnetId=subnet_id)
                    break
                except ClientError as exc:
                    if exc.response["Error"]["Code"] == "InvalidSubnetID.NotFound":
                        break
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(10)
        if igw_id:
            ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
            ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        while True:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "InvalidVpcID.NotFound":
                    break
                if time.monotonic() >= deadline:
                    raise
                time.sleep(10)

    ctx.on_cleanup(_teardown_network)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.198.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
    )["Subnet"]["SubnetId"]
    state["subnet_id"] = subnet_id
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _NET_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    state["igw_id"] = igw_id
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"][0]["GroupId"]
    return {"vpc_id": vpc_id, "subnet_ids": [subnet_id], "sg_id": sg_id}


def _delete_cluster(ecs, cluster_name):
    """Delete the cluster, waiting out ClusterContainsTasksException while stopped tasks drain."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 300
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterContainsTasksException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _setup_fargate_env(ctx):
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    ecs = ctx.client("ecs")

    exec_role_name = ctx.unique_name("sim2real-ecs-exec-")
    exec_trust = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    )
    exec_policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    try:
        exec_role_arn = iam.create_role(RoleName=exec_role_name, AssumeRolePolicyDocument=exec_trust)["Role"]["Arn"]
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_role_name))
        iam.attach_role_policy(RoleName=exec_role_name, PolicyArn=exec_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=exec_role_name, PolicyArn=exec_policy_arn))
    except ClientError as err:
        raise AssertionError(f"unreachable: cannot provision the ECS task execution role ({err.response['Error']['Code']})")

    # A dedicated VPC: the check never depends on the account's default VPC or subnets.
    net = _own_network(ctx)
    subnet_ids, sg_id = net["subnet_ids"], net["sg_id"]

    cluster_name = ctx.unique_name("sim2real-tp-cluster-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster_name))

    family = ctx.unique_name("sim2real-tp-td-")
    # nginx's default entrypoint keeps a Fargate task RUNNING with no command override, and this check
    # needs a genuinely RUNNING task.
    td_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/nginx/nginx:1.27",
                "essential": True,
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    network_configuration = {
        "awsvpcConfiguration": {"subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED"}
    }
    return {
        "cluster_name": cluster_name,
        "task_def_arn": td_arn,
        "network_configuration": network_configuration,
    }


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
