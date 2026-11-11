"""deep-ecs-3-deploy-fail-maximum-percent-ceiling-never-exceeded-during-rollout."""
from __future__ import annotations

import math
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-ecs-3-deploy-fail-maximum-percent-ceiling-never-exceeded-during-rollout"
GROUP = "service-deployment"
SERVICES = ["ecs"]

_DESIRED = 2
_SUBJECT_MIN_PCT = 50
_SUBJECT_MAX_PCT = 100
_CONTROL_MIN_PCT = 100
_CONTROL_MAX_PCT = 200
_POLL_S = 2.0
_STEADY_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 1200.0
# The task states maximumPercent caps, per the ECS API reference: "an upper limit on the number of
# your service's tasks that are allowed in the RUNNING or PENDING state during a deployment".
_CAPPED_STATES = ("PENDING", "RUNNING")
_LIVE_STATES = ("PROVISIONING", "PENDING", "ACTIVATING", "RUNNING")


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """During a rolling update, maximumPercent=100 on desiredCount=2 keeps at most 2 tasks PENDING or
    RUNNING and forces a stop-first dip; a 200% control service is seen to exceed 2.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DeploymentConfiguration.html
    """
    ecs = ctx.client("ecs")
    own: list = []  # every teardown, in registration order, for _teardown_inline
    _ensure_ecs_service_linked_role(ctx)
    subnets, sg_id = _public_network(ctx, own)
    cluster = _create_cluster(ctx, ecs, own)

    family = ctx.unique_name("sim2real-behav-ecs-maxpct-")
    rev1 = _register(ecs, ctx, family, "sleep 3600", own)
    rev2 = _register(ecs, ctx, family, "sleep 3601", own)
    assert rev1 != rev2, f"the two task-definition revisions must be distinct, got {rev1!r} twice"

    net = {
        "awsvpcConfiguration": {
            "subnets": subnets,
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    subject = _create_service(ctx, ecs, cluster, rev1, net, _SUBJECT_MIN_PCT, _SUBJECT_MAX_PCT, own)
    control = _create_service(ctx, ecs, cluster, rev1, net, _CONTROL_MIN_PCT, _CONTROL_MAX_PCT, own)
    both = [subject, control]

    steady = _poll_until(
        lambda: _services(ecs, cluster, both),
        lambda st: all(
            s["runningCount"] == _DESIRED
            and len(s["deployments"]) == 1
            and _primary(s).get("rolloutState") == "COMPLETED"
            for s in st.values()
        ),
        timeout_s=_STEADY_TIMEOUT_S,
        interval_s=10,
        description=f"both services reach {_DESIRED} running tasks in a single COMPLETED rev1 deployment",
    )
    cfg = steady[subject]["deploymentConfiguration"]
    assert (cfg.get("minimumHealthyPercent"), cfg.get("maximumPercent")) == (_SUBJECT_MIN_PCT, _SUBJECT_MAX_PCT), (
        f"the subject must carry minimumHealthyPercent/maximumPercent "
        f"{_SUBJECT_MIN_PCT}/{_SUBJECT_MAX_PCT}, got {cfg!r}"
    )
    ceiling = math.floor(steady[subject]["desiredCount"] * cfg["maximumPercent"] / 100)
    assert ceiling == _DESIRED, f"derived ceiling must be {_DESIRED}, got {ceiling!r} from {cfg!r}"

    # Both services are sampled in the same loop so no propagation delta exists between them.
    for name in both:
        ecs.update_service(cluster=cluster, service=name, taskDefinition=rev2)

    samples: dict[str, list[dict]] = {subject: [], control: []}
    started: set[str] = set()

    def _tick():
        state = _services(ecs, cluster, both)
        for name in both:
            tasks = _service_tasks(ecs, cluster, name)
            samples[name].append(
                {
                    "capped": sum(1 for t in tasks if t["lastStatus"] in _CAPPED_STATES),
                    "scheduled": sum(
                        1 for t in tasks if t["desiredStatus"] == "RUNNING" and t["lastStatus"] in _LIVE_STATES
                    ),
                    "counts": state[name]["runningCount"] + state[name]["pendingCount"],
                }
            )
            if _primary(state[name]).get("taskDefinition") == rev2 and _primary(state[name]).get(
                "rolloutState"
            ) == "IN_PROGRESS":
                started.add(name)
        return state

    # Start counting only once each rev2 rollout is genuinely IN_PROGRESS, so the samples span the
    # replacement window rather than the steady state that preceded it.
    _poll_until(
        _tick,
        lambda _st: started == set(both),
        timeout_s=300,
        interval_s=_POLL_S,
        description="both services report an IN_PROGRESS rollout of rev2",
    )
    final = _poll_until(
        _tick,
        lambda st: all(
            len(s["deployments"]) == 1
            and _primary(s).get("taskDefinition") == rev2
            and _primary(s).get("rolloutState") == "COMPLETED"
            and s["runningCount"] == _DESIRED
            for s in st.values()
        ),
        timeout_s=_DEPLOY_TIMEOUT_S,
        interval_s=_POLL_S,
        description="both rolling deployments land on rev2 with a single COMPLETED deployment",
    )

    def _peak(name, key):
        return max(s[key] for s in samples[name])

    # Barrier first: the sampler must be able to see overshoot when overshoot is allowed.
    assert _peak(control, "capped") > _DESIRED, (
        f"the control (maximumPercent={_CONTROL_MAX_PCT}, minimumHealthyPercent={_CONTROL_MIN_PCT}) must "
        f"start replacements before stopping old tasks, so more than {_DESIRED} PENDING/RUNNING tasks "
        f"must be sampled at some point; peak was {_peak(control, 'capped')} over "
        f"{len(samples[control])} samples -- without this the subject's ceiling below is not evidence"
    )

    for key, label in (
        ("capped", "tasks in PENDING or RUNNING (any desiredStatus)"),
        ("scheduled", "tasks with desiredStatus RUNNING"),
        ("counts", "runningCount+pendingCount"),
    ):
        peak = _peak(subject, key)
        assert peak <= ceiling, (
            f"maximumPercent={_SUBJECT_MAX_PCT} on desiredCount={_DESIRED} caps the deployment at "
            f"{ceiling} tasks, but {peak} {label} were sampled at once "
            f"(series={[s[key] for s in samples[subject]]!r}); the identically-updated control peaked "
            f"at {_peak(control, 'capped')} as configured"
        )
    dip = min(s["scheduled"] for s in samples[subject])
    assert dip < _DESIRED, (
        f"with a {ceiling}-task ceiling the subject must stop an old task before starting a new one, so "
        f"fewer than {_DESIRED} scheduled-live tasks must be sampled at some point; min was {dip} over "
        f"{len(samples[subject])} samples, which means the replacement window was never observed"
    )

    # Independent terminal read through DescribeTasks: the deployment really replaced every task.
    assert final[subject]["taskDefinition"] == rev2, (
        f"the subject must end the deployment on {rev2!r}, got {final[subject]['taskDefinition']!r}"
    )
    live = [t for t in _service_tasks(ecs, cluster, subject) if t["desiredStatus"] == "RUNNING"]
    assert len(live) == _DESIRED and {t["taskDefinitionArn"] for t in live} == {rev2}, (
        f"the subject must finish with {_DESIRED} live tasks all on rev2 {rev2!r}, got "
        f"{[(t['taskDefinitionArn'], t['lastStatus']) for t in live]!r}"
    )

    _teardown_inline(ecs, cluster, both, own)


# ===== helpers =====


def _teardown_inline(ecs, cluster, services, own) -> None:
    """Run every registered teardown now, inside the check's own budget.

    Registered cleanups are time-bounded, and draining Fargate services plus deleting the VPC takes
    minutes; the same idempotent callables stay registered as the failure-path net.
    """
    for name in services:  # kick every drain first so they overlap rather than queue
        _unless_gone(lambda n=name: ecs.update_service(cluster=cluster, service=n, desiredCount=0),
                     *_SVC_GONE)
        _unless_gone(lambda n=name: ecs.delete_service(cluster=cluster, service=n, force=True),
                     *_SVC_GONE)
    for fn in reversed(own):
        fn()
    own.clear()

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _ecs_tags() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _aws_tags() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


#: Codes UpdateService/DeleteService return once the service or its cluster is already gone.
_SVC_GONE = ("ServiceNotFoundException", "ServiceNotActiveException", "ClusterNotFoundException")


def _unless_gone(fn, *codes) -> None:
    """Run a teardown step; return only on the given not-found codes, raise any other error."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _net(ctx, own, fn) -> None:
    """Register fn with ctx.on_cleanup (the failure-path net) AND record it for _teardown_inline.

    The step runs at most once to completion, so the net is a no-op after a clean inline teardown.
    """
    done = []

    def _once():
        if not done:
            fn()
            done.append(True)

    ctx.on_cleanup(_once)
    own.append(_once)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last observed {last!r}")


def _primary(svc: dict) -> dict:
    prim = [d for d in svc.get("deployments", []) if d.get("status") == "PRIMARY"]
    return prim[0] if len(prim) == 1 else {}


def _services(ecs, cluster, names) -> dict:
    resp = ecs.describe_services(cluster=cluster, services=list(names))
    assert not resp.get("failures"), f"DescribeServices could not read {names!r}: {resp.get('failures')!r}"
    out = {s["serviceName"]: s for s in resp["services"]}
    assert set(out) == set(names), f"expected {sorted(names)!r} back, got {sorted(out)!r}"
    return out


def _service_tasks(ecs, cluster, service) -> list[dict]:
    """Every task of the service still known to ECS: desired RUNNING and recently desired STOPPED.

    The STOPPED listing is what makes a draining old task visible -- its desiredStatus is already
    STOPPED while its lastStatus can still read RUNNING, and the ceiling covers it.
    """
    arns: list[str] = []
    for desired in ("RUNNING", "STOPPED"):
        for page in ecs.get_paginator("list_tasks").paginate(
            cluster=cluster, serviceName=service, desiredStatus=desired
        ):
            arns.extend(page["taskArns"])
    tasks: list[dict] = []
    for i in range(0, len(arns), 100):
        tasks.extend(ecs.describe_tasks(cluster=cluster, tasks=arns[i : i + 100])["tasks"])
    return tasks


def _ensure_ecs_service_linked_role(ctx) -> None:
    """Create-or-adopt the ECS service-linked role, which CreateService requires."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("InvalidInput", "InvalidInputException", "EntityAlreadyExists"):
            raise
    # Deliberately NOT torn down: the service-linked role is account-global and shared.


def _register(ecs, ctx, family, command, own) -> str:
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
    def _drop() -> None:
        ecs.deregister_task_definition(taskDefinition=arn)
        failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
        if failures:
            raise RuntimeError(f"task definition {arn} teardown failed: {failures}")

    _net(ctx, own, _drop)
    return arn


def _create_cluster(ctx, ecs, own) -> str:
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=_ecs_tags())

    def _drop_cluster():
        # Services registered LATER are deleted FIRST (LIFO); DeleteCluster refuses a cluster that
        # still holds a DRAINING service, so retry on a bounded deadline.
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            try:
                ecs.delete_cluster(cluster=name)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ClusterNotFoundException":
                    return
                if code not in ("ClusterContainsServicesException", "ClusterContainsTasksException",
                                "UpdateInProgressException"):
                    raise
                time.sleep(2)
        raise RuntimeError(f"ecs cluster {name} not deleted within the teardown deadline")

    _net(ctx, own, _drop_cluster)
    return name


def _create_service(ctx, ecs, cluster, td_arn, net, min_pct, max_pct, own) -> str:
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
        _unless_gone(lambda: ecs.update_service(cluster=cluster, service=name, desiredCount=0),
                     *_SVC_GONE)
        _unless_gone(lambda: ecs.delete_service(cluster=cluster, service=name, force=True),
                     *_SVC_GONE)
        deadline = time.monotonic() + 420
        while time.monotonic() < deadline:
            try:
                found = ecs.describe_services(cluster=cluster, services=[name]).get("services") or [{}]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ClusterNotFoundException":
                    return
                raise
            if found[0].get("status", "INACTIVE") == "INACTIVE":
                return
            time.sleep(2)
        raise RuntimeError(f"ecs service {name} in {cluster} not INACTIVE within the teardown deadline")

    _net(ctx, own, _drop)
    return name


def _public_network(ctx, own):
    """A dedicated VPC with public subnets in two AZs, an IGW and a default route.

    Created rather than adopting a default VPC, which an account may lack or have misconfigured.
    The public route is load-bearing: the tasks pull from public ECR.
    """
    ec2 = ctx.client("ec2")
    azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )
    assert len(azs) >= 2, f"need two available AZs for the Fargate subnets, got {azs!r}"
    vpc_id = ec2.create_vpc(
        CidrBlock="10.194.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _aws_tags()}],
    )["Vpc"]["VpcId"]
    subnet_ids: list[str] = []
    igw_id: list[str] = []

    def _teardown_network():
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            if not ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get(
                "NetworkInterfaces", []
            ):
                break
            time.sleep(2)
        for sid in subnet_ids:
            while time.monotonic() < deadline:
                try:
                    ec2.delete_subnet(SubnetId=sid)
                    break
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") == "InvalidSubnetID.NotFound":
                        break
                    time.sleep(2)
        for gw in igw_id:
            _unless_gone(lambda: ec2.detach_internet_gateway(InternetGatewayId=gw, VpcId=vpc_id),
                         "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound")
            _unless_gone(lambda: ec2.delete_internet_gateway(InternetGatewayId=gw),
                         "InvalidInternetGatewayID.NotFound")
        while time.monotonic() < deadline:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidVpcID.NotFound":
                    return
                time.sleep(2)
        raise RuntimeError(
            f"vpc {vpc_id} / subnets {subnet_ids} / igw {igw_id} not deleted within the teardown deadline"
        )

    _net(ctx, own, _teardown_network)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    for i, az in enumerate(azs[:2]):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.194.0.{i * 128}/25",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _aws_tags()}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
    igw_id.append(
        ec2.create_internet_gateway(
            TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _aws_tags()}]
        )["InternetGateway"]["InternetGatewayId"]
    )
    ec2.attach_internet_gateway(InternetGatewayId=igw_id[0], VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"][0][
        "RouteTableId"
    ]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id[0])
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
        if sg["GroupName"] == "default"
    )
    return subnet_ids, sg_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
