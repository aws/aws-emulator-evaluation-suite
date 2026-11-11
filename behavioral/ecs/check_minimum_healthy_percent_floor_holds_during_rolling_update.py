"""minimum-healthy-percent-floor-holds-during-rolling-update."""
from __future__ import annotations

import math
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "minimum-healthy-percent-floor-holds-during-rolling-update"
GROUP = "task-lifecycle"
SERVICES = ["ecs"]

_DESIRED = 2
_SUBJECT_MIN_PCT = 100
_SUBJECT_MAX_PCT = 200
_CONTROL_MIN_PCT = 0
_CONTROL_MAX_PCT = 100
_POLL_S = 2.0
_STEADY_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 1200.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """During a rolling update a min=100/max=200 service never drops below its floor and overshoots
    desiredCount, while an identically updated min=0/max=100 control is seen to dip below it.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-type-ecs.html
    """
    ecs = ctx.client("ecs")
    _ensure_ecs_service_linked_role(ctx)
    subnet_id, sg_id = _public_network(ctx)
    cluster = _create_cluster(ctx, ecs)

    family = ctx.unique_name("sim2real-behav-ecs-mhp-")
    rev1 = _register(ecs, ctx, family, "sleep 3600")
    rev2 = _register(ecs, ctx, family, "sleep 3601")
    assert rev1 != rev2, (
        f"the two task-definition revisions must be distinct for the update to be a real "
        f"deployment, got {rev1!r} twice"
    )

    net = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    subject = _create_service(ctx, ecs, cluster, rev1, net, _SUBJECT_MIN_PCT, _SUBJECT_MAX_PCT)
    control = _create_service(ctx, ecs, cluster, rev1, net, _CONTROL_MIN_PCT, _CONTROL_MAX_PCT)
    both = [subject, control]

    # Both services must be genuinely steady on rev1 before the swap, or a dip observed afterwards
    # would just be the initial ramp-up.
    _poll_until(
        lambda: _describe(ecs, cluster, both),
        lambda st: all(
            s["runningCount"] == _DESIRED and s["rolloutState"] == "COMPLETED" for s in st.values()
        ),
        timeout_s=_STEADY_TIMEOUT_S,
        interval_s=10,
        description=f"both services reach {_DESIRED} running tasks with a COMPLETED rollout on rev1",
    )
    for name in both:
        cfg = _describe(ecs, cluster, both)[name]["deploymentConfiguration"]
        assert cfg["minimumHealthyPercent"] == (
            _SUBJECT_MIN_PCT if name == subject else _CONTROL_MIN_PCT
        ), (
            f"service {name} must carry the minimumHealthyPercent it was created with, got "
            f"{cfg.get('minimumHealthyPercent')!r}"
        )

    # One fan-out, back to back, so the two deployments overlap in time.
    for name in both:
        ecs.update_service(cluster=cluster, service=name, taskDefinition=rev2)

    # Observe BOTH services in a SINGLE DescribeServices call per tick, so every comparison between
    # subject and control is made on the same instant's data.
    seen: dict[str, list[int]] = {subject: [], control: []}
    started: set[str] = set()

    def _tick():
        state = _describe(ecs, cluster, both)
        for name in both:
            seen[name].append(state[name]["runningCount"])
            if (
                state[name]["taskDefinition"] == rev2
                and state[name]["rolloutState"] == "IN_PROGRESS"
            ):
                started.add(name)
        return state

    # Sample from the moment each deployment is genuinely IN_PROGRESS. Without this leg the completion
    # poll below could be satisfied by its very FIRST tick — for a moment after UpdateService returns,
    # the previous rollout still reads COMPLETED and runningCount is still at desiredCount — and the
    # check would then grade a deployment it never actually watched.
    _poll_until(
        _tick,
        lambda _state: started == set(both),
        timeout_s=300,
        interval_s=_POLL_S,
        description="both services report an IN_PROGRESS rollout of rev2, so the samples span the "
        "actual deployment rather than the steady state that preceded it",
    )
    _poll_until(
        _tick,
        lambda st: all(
            s["taskDefinition"] == rev2
            and s["rolloutState"] == "COMPLETED"
            and s["runningCount"] == _DESIRED
            for s in st.values()
        ),
        timeout_s=_DEPLOY_TIMEOUT_S,
        interval_s=_POLL_S,
        description="both rolling deployments land on rev2 and return to a COMPLETED rollout",
    )

    floor = math.ceil(_DESIRED * _SUBJECT_MIN_PCT / 100)
    subject_min = min(seen[subject])
    subject_max = max(seen[subject])
    control_min = min(seen[control])

    # Without a control that dipped, a subject that never dipped is not evidence of enforcement.
    assert control_min < floor, (
        f"the control service (minimumHealthyPercent={_CONTROL_MIN_PCT}, "
        f"maximumPercent={_CONTROL_MAX_PCT}, so it CANNOT exceed {_DESIRED} running and must stop "
        f"an old task before starting a new one) was never observed below {floor} running tasks: "
        f"min={control_min}, samples={seen[control]!r}. Either the deployment did not really replace "
        f"any task, or the poll never saw the window — in both cases the subject's floor below is "
        f"not evidence of enforcement"
    )

    assert subject_min >= floor, (
        f"minimumHealthyPercent={_SUBJECT_MIN_PCT} on desiredCount={_DESIRED} means at least "
        f"{floor} tasks must stay RUNNING throughout the deployment, but runningCount fell to "
        f"{subject_min} (samples={seen[subject]!r}) while the identically-updated control dipped to "
        f"{control_min} as configured"
    )
    assert subject_max > _DESIRED, (
        f"maximumPercent={_SUBJECT_MAX_PCT} with minimumHealthyPercent={_SUBJECT_MIN_PCT} requires "
        f"the scheduler to start replacements before retiring the old tasks, so runningCount must be "
        f"seen ABOVE desiredCount={_DESIRED} at some point; the maximum observed was {subject_max} "
        f"(samples={seen[subject]!r}), which is what an in-place swap that ignores the "
        f"configuration looks like"
    )

    final = _describe(ecs, cluster, both)
    for name in both:
        assert final[name]["taskDefinition"] == rev2, (
            f"service {name} must end the deployment on {rev2!r}, got "
            f"{final[name]['taskDefinition']!r}"
        )
        arns = ecs.list_tasks(cluster=cluster, serviceName=name, desiredStatus="RUNNING")[
            "taskArns"
        ]
        assert len(arns) == _DESIRED, (
            f"service {name} must have exactly {_DESIRED} running tasks after the deployment, got "
            f"{len(arns)}: {arns!r}"
        )
        revs = {
            t["taskDefinitionArn"]
            for t in ecs.describe_tasks(cluster=cluster, tasks=arns)["tasks"]
        }
        assert revs == {rev2}, (
            f"every running task of service {name} must be on the new revision {rev2!r}, got {revs!r}"
        )


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _ecs_tags() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _ec2_tags() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn) -> None:
    """Run fn(), swallowing any exception; for teardown only."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("ClusterNotFoundException", "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound", "NamespaceNotFoundException", "ServiceNotActiveException", "ServiceNotFoundException")
            and not (err["Code"] == "ClientException" and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted")))
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll until predicate holds; raise on timeout."""
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


def _describe(ecs, cluster, names) -> dict:
    """One DescribeServices call covering every service, flattened to the fields under assertion."""
    resp = ecs.describe_services(cluster=cluster, services=list(names))
    assert not resp.get("failures"), (
        f"DescribeServices could not read {names!r}: {resp.get('failures')!r}"
    )
    out = {}
    for svc in resp["services"]:
        primary = [d for d in svc["deployments"] if d["status"] == "PRIMARY"]
        assert len(primary) == 1, (
            f"service {svc['serviceName']} must have exactly one PRIMARY deployment, got "
            f"{[d['status'] for d in svc['deployments']]!r}"
        )
        out[svc["serviceName"]] = {
            "runningCount": svc["runningCount"],
            "desiredCount": svc["desiredCount"],
            "taskDefinition": svc["taskDefinition"],
            "rolloutState": primary[0].get("rolloutState"),
            "deploymentConfiguration": svc["deploymentConfiguration"],
        }
    assert set(out) == set(names), f"expected {sorted(names)!r} back, got {sorted(out)!r}"
    return out


def _ensure_ecs_service_linked_role(ctx) -> None:
    """Create-or-adopt the ECS service-linked role, which CreateService requires."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("InvalidInput", "InvalidInputException", "EntityAlreadyExists"):
            raise
    # Not torn down: the service-linked role is account-global and shared.


def _register(ecs, ctx, family, command) -> str:
    """Register one revision of a minimal Fargate task definition; return its ARN."""
    arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", command],
            }
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
    ctx.on_cleanup(lambda: _delete_cluster(ecs, name))
    return name


def _delete_cluster(ecs, name, timeout_s=300) -> None:
    """A force-deleted service's tasks keep stopping for a while after DeleteService returns, and
    DeleteCluster refuses until they are gone: retry on exactly that refusal, raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _swallow(lambda: ecs.delete_cluster(cluster=name))
            return
        except ClientError as exc:
            if (exc.response["Error"]["Code"] not in ("ClusterContainsTasksException",
                                                      "ClusterContainsServicesException")
                    or time.monotonic() >= deadline):
                raise
        time.sleep(2)


def _create_service(ctx, ecs, cluster, td_arn, net, min_pct, max_pct) -> str:
    name = ctx.unique_name("sim2real-behav-ecs-svc-")
    ecs.create_service(
        cluster=cluster,
        serviceName=name,
        taskDefinition=td_arn,
        desiredCount=_DESIRED,
        launchType="FARGATE",
        networkConfiguration=net,
        deploymentConfiguration={
            "minimumHealthyPercent": min_pct,
            "maximumPercent": max_pct,
        },
        tags=_ecs_tags(),
    )

    def _drop():
        _swallow(lambda: ecs.update_service(cluster=cluster, service=name, desiredCount=0))
        _swallow(lambda: ecs.delete_service(cluster=cluster, service=name, force=True))

    ctx.on_cleanup(_drop)
    return name


def _public_network(ctx):
    """A dedicated VPC with one public subnet, an IGW and a default route.

    An account need not have a default VPC; the public route lets tasks pull from public ECR.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.197.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags()}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.197.0.0/25",
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
        # Fargate ENIs linger briefly after the services drain and block subnet deletion.
        deadline = time.monotonic() + 900
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
