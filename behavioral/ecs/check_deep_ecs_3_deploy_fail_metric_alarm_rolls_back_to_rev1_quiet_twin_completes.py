"""deep-ecs-3-deploy-fail-metric-alarm-rolls-back-to-rev1-quiet-twin-completes."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-ecs-3-deploy-fail-metric-alarm-rolls-back-to-rev1-quiet-twin-completes"
GROUP = "service-deployment"
SERVICES = ["ecs"]

_STEADY_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 1500.0
_PUT_EVERY_S = 20.0
_METRIC_NS = "Sim2Real/Behavioral/EcsDeployAlarm"
_METRIC_NAME = "DeployErrors"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-alarm-failure.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:metrics",
    "concern:negative-classes",
    "plane:control",
    "timing:real-time",
)
def run(ctx) -> None:
    """An OK->ALARM transition of a deployment alarm makes ECS fail the rev2 rollout and roll back to rev1.

    A twin service whose alarm stays OK completes rev2 with no rollback, as a positive control.
    """
    ecs = ctx.client("ecs")
    own: list = []
    cw = ctx.client("cloudwatch")
    _ensure_ecs_service_linked_role(ctx)
    subnets, sg_id = _public_network(ctx, own)
    cluster = _create_cluster(ctx, ecs, own)

    family = ctx.unique_name("sim2real-behav-ecs-alarmrb-")
    rev1 = _register(ecs, ctx, family, "sleep 3600", own)
    rev2 = _register(ecs, ctx, family, "sleep 3601", own)
    assert rev1 != rev2, f"the two task-definition revisions must be distinct, got {rev1!r} twice"

    run_id = ctx.unique_name("sim2real-run-")
    subject_alarm = _create_alarm(ctx, cw, ctx.unique_name("sim2real-ecs-alarmrb-subject-"), run_id, "subject", own)
    twin_alarm = _create_alarm(ctx, cw, ctx.unique_name("sim2real-ecs-alarmrb-twin-"), run_id, "twin", own)

    net = {
        "awsvpcConfiguration": {
            "subnets": subnets,
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    subject = _create_service(ctx, ecs, cluster, rev1, net, subject_alarm, own)
    twin = _create_service(ctx, ecs, cluster, rev1, net, twin_alarm, own)
    both = [subject, twin]

    for name, alarm in ((subject, subject_alarm), (twin, twin_alarm)):
        cfg = _services(ecs, cluster, both)[name]["deploymentConfiguration"].get("alarms") or {}
        assert cfg.get("alarmNames") == [alarm] and cfg.get("enable") is True and cfg.get("rollback") is True, (
            f"service {name} must carry the alarm configuration it was created with "
            f"(alarmNames=[{alarm!r}], enable=True, rollback=True), got {cfg!r}"
        )

    _poll_until(
        lambda: _services(ecs, cluster, both),
        lambda st: all(
            s["runningCount"] == 1
            and len(s["deployments"]) == 1
            and _primary(s).get("rolloutState") == "COMPLETED"
            and _primary(s).get("taskDefinition") == rev1
            for s in st.values()
        ),
        timeout_s=_STEADY_TIMEOUT_S,
        interval_s=10,
        description="both services reach a single COMPLETED deployment of rev1 with 1 running task",
    )

    # Both alarms must read OK before the deployment: ECS does not react to an
    # INSUFFICIENT_DATA -> ALARM transition mid-deployment, only to OK -> ALARM.
    _poll_until(
        lambda: {
            a["AlarmName"]: a["StateValue"]
            for a in cw.describe_alarms(AlarmNames=[subject_alarm, twin_alarm])["MetricAlarms"]
        },
        lambda st: st == {subject_alarm: "OK", twin_alarm: "OK"},
        timeout_s=600,
        interval_s=10,
        description="both deployment alarms complete their first evaluation and read OK",
    )

    for name in both:
        ecs.update_service(cluster=cluster, service=name, taskDefinition=rev2)

    # PutMetricData, not SetAlarmState: ECS's monitor does not trip on an alarm forced via
    # SetAlarmState. The twin's metric is never written, so its notBreaching alarm stays OK.
    last_put = [0.0]

    def _tick():
        now = time.monotonic()
        if now - last_put[0] >= _PUT_EVERY_S:
            cw.put_metric_data(
                Namespace=_METRIC_NS,
                MetricData=[
                    {
                        "MetricName": _METRIC_NAME,
                        "Dimensions": [{"Name": "Run", "Value": run_id}, {"Name": "Leg", "Value": "subject"}],
                        "Timestamp": datetime.datetime.now(datetime.timezone.utc),
                        "Value": 100.0,
                    }
                ],
            )
            last_put[0] = now
        return _services(ecs, cluster, both)

    def _dep_for(svc: dict, td: str) -> dict:
        for dep in svc["deployments"]:
            if dep.get("taskDefinition") == td:
                return dep
        return {}

    failed = _poll_until(
        _tick,
        lambda st: _dep_for(st[subject], rev2).get("rolloutState") == "FAILED",
        timeout_s=_DEPLOY_TIMEOUT_S,
        interval_s=5,
        description="ECS's alarm monitor drives the subject's rev2 deployment to rolloutState FAILED",
    )[subject]
    reason = _dep_for(failed, rev2).get("rolloutStateReason") or ""
    assert "alarm" in reason.lower() and "circuit breaker" not in reason.lower(), (
        "an alarm-tripped rollout must attribute the failure to the alarm, not the circuit breaker, "
        f"got rolloutStateReason={reason!r}"
    )

    settled = _poll_until(
        lambda: _services(ecs, cluster, both),
        lambda st: all(len(s["deployments"]) == 1 and s["runningCount"] == 1 for s in st.values())
        and _primary(st[subject]).get("taskDefinition") == rev1
        and _primary(st[subject]).get("rolloutState") == "COMPLETED"
        and _primary(st[twin]).get("taskDefinition") == rev2
        and _primary(st[twin]).get("rolloutState") == "COMPLETED",
        timeout_s=_DEPLOY_TIMEOUT_S,
        interval_s=10,
        description="the subject rolls back to a COMPLETED rev1 deployment while the twin COMPLETES rev2",
    )
    assert settled[subject]["taskDefinition"] == rev1, (
        f"after the alarm rollback the subject's service taskDefinition must be rev1 {rev1!r}, got "
        f"{settled[subject]['taskDefinition']!r}"
    )
    assert settled[twin]["taskDefinition"] == rev2, (
        f"the twin whose alarm never fired must stay on rev2 {rev2!r}, got {settled[twin]['taskDefinition']!r}"
    )

    subj_hist = _alarm_transitions(cw, subject_alarm)
    assert any(h.endswith("to ALARM") for h in subj_hist), (
        f"the subject alarm {subject_alarm!r} must have transitioned to ALARM from the real metric, "
        f"history was {subj_hist!r}"
    )
    twin_hist = _alarm_transitions(cw, twin_alarm)
    assert not any(h.endswith("to ALARM") for h in twin_hist), (
        f"the twin alarm {twin_alarm!r} was never fed and must never have reached ALARM, history was "
        f"{twin_hist!r}"
    )

    subj_sd = _service_deployment_targeting(ecs, cluster, subject, rev2)
    assert subj_sd.get("status") == "ROLLBACK_SUCCESSFUL", (
        f"the subject's rev2 ServiceDeployment must read ROLLBACK_SUCCESSFUL, got "
        f"status={subj_sd.get('status')!r} statusReason={subj_sd.get('statusReason')!r}"
    )
    mon = subj_sd.get("alarms") or {}
    assert mon.get("status") == "TRIGGERED" and mon.get("triggeredAlarmNames") == [subject_alarm], (
        f"the subject's alarm monitor must be TRIGGERED by exactly [{subject_alarm!r}], got {mon!r}"
    )
    rb = subj_sd.get("rollback") or {}
    rb_rev = rb.get("serviceRevisionArn")
    assert rb_rev and rb.get("startedAt"), f"the subject's ServiceDeployment must carry a rollback record, got {rb!r}"
    sources = [r.get("arn") for r in subj_sd.get("sourceServiceRevisions") or []]
    assert rb_rev in sources, (
        f"the rollback must target the revision the deployment replaced, got rollback={rb_rev!r} "
        f"sources={sources!r}"
    )
    rb_td = ecs.describe_service_revisions(serviceRevisionArns=[rb_rev])["serviceRevisions"][0]["taskDefinition"]
    assert rb_td == rev1, f"the rollback's service revision must run rev1 {rev1!r}, got {rb_td!r}"

    twin_sd = _service_deployment_targeting(ecs, cluster, twin, rev2)
    twin_mon = twin_sd.get("alarms") or {}
    assert twin_sd.get("status") == "SUCCESSFUL", (
        f"the twin's rev2 ServiceDeployment must read SUCCESSFUL, got status={twin_sd.get('status')!r} "
        f"statusReason={twin_sd.get('statusReason')!r}"
    )
    assert twin_mon.get("status") == "MONITORING_COMPLETE" and not twin_mon.get("triggeredAlarmNames"), (
        f"the twin's alarm monitor must complete without triggering, got {twin_mon!r}"
    )
    assert not twin_sd.get("rollback"), f"the twin must have no rollback record, got {twin_sd.get('rollback')!r}"

    for name, want in ((subject, rev1), (twin, rev2)):
        tasks = _live_tasks(ecs, cluster, name)
        assert len(tasks) == 1, (
            f"service {name} must have exactly 1 live task after settling, got "
            f"{[(t['taskArn'], t['lastStatus']) for t in tasks]!r}"
        )
        revs = {t["taskDefinitionArn"] for t in tasks}
        assert revs == {want} and tasks[0]["lastStatus"] == "RUNNING", (
            f"service {name}'s live task must be RUNNING {want!r}, got "
            f"{[(t['taskDefinitionArn'], t['lastStatus']) for t in tasks]!r}"
        )

    _teardown_inline(ecs, cluster, both, own)


def _teardown_inline(ecs, cluster, services, own) -> None:
    """Run every registered teardown inside the check's own budget.

    Draining Fargate services and deleting the VPC takes minutes, longer than the cleanup bound.
    """
    for name in services:  # kick every drain first so they overlap rather than queue
        _swallow(lambda n=name: ecs.update_service(cluster=cluster, service=n, desiredCount=0))
        _swallow(lambda n=name: ecs.delete_service(cluster=cluster, service=n, force=True))
    for fn in reversed(own):
        fn()
    own.clear()

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _ecs_tags() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _aws_tags() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn) -> None:
    """Run fn(), swallowing any exception. Teardown ONLY — never on an assertion path."""
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown step
        pass


def _net(ctx, own, fn) -> None:
    """Register fn with ctx.on_cleanup (the failure-path net) AND record it for _teardown_inline."""
    ctx.on_cleanup(fn)
    own.append(fn)


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


def _live_tasks(ecs, cluster, service) -> list[dict]:
    arns: list[str] = []
    for page in ecs.get_paginator("list_tasks").paginate(
        cluster=cluster, serviceName=service, desiredStatus="RUNNING"
    ):
        arns.extend(page["taskArns"])
    tasks: list[dict] = []
    for i in range(0, len(arns), 100):
        tasks.extend(ecs.describe_tasks(cluster=cluster, tasks=arns[i : i + 100])["tasks"])
    return tasks


def _service_deployment_targeting(ecs, cluster, service, td_arn) -> dict:
    """The one ServiceDeployment whose TARGET revision runs td_arn."""
    arns: list[str] = []
    token = None
    while True:
        kw = {"cluster": cluster, "service": service}
        if token:
            kw["nextToken"] = token
        page = ecs.list_service_deployments(**kw)
        arns.extend(d["serviceDeploymentArn"] for d in page.get("serviceDeployments", []))
        token = page.get("nextToken")
        if not token:
            break
    assert arns, f"ListServiceDeployments returned nothing for {service!r}"
    found = []
    for i in range(0, len(arns), 20):
        for sd in ecs.describe_service_deployments(serviceDeploymentArns=arns[i : i + 20])["serviceDeployments"]:
            target = (sd.get("targetServiceRevision") or {}).get("arn")
            if not target:
                continue
            rev = ecs.describe_service_revisions(serviceRevisionArns=[target])["serviceRevisions"][0]
            if rev.get("taskDefinition") == td_arn:
                found.append(sd)
    assert len(found) == 1, (
        f"exactly one ServiceDeployment of {service!r} must target {td_arn!r}, got "
        f"{[(s.get('serviceDeploymentArn'), s.get('status')) for s in found]!r}"
    )
    return found[0]


def _alarm_transitions(cw, alarm) -> list[str]:
    out: list[str] = []
    for page in cw.get_paginator("describe_alarm_history").paginate(AlarmName=alarm, HistoryItemType="StateUpdate"):
        out.extend(h["HistorySummary"] for h in page["AlarmHistoryItems"])
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
    # Deliberately NOT torn down: the service-linked role is account-global and shared.


def _create_alarm(ctx, cw, name, run_id, leg, own) -> str:
    cw.put_metric_alarm(
        AlarmName=name,
        AlarmDescription="sim2real behavioral: ECS deployment alarm rollback",
        Namespace=_METRIC_NS,
        MetricName=_METRIC_NAME,
        Dimensions=[{"Name": "Run", "Value": run_id}, {"Name": "Leg", "Value": leg}],
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=0.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=_aws_tags(),
    )
    _net(ctx, own, lambda: _swallow(lambda: cw.delete_alarms(AlarmNames=[name])))
    return name


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
    _net(ctx, own, lambda: _swallow(lambda: ecs.delete_task_definitions(taskDefinitions=[arn])))
    _net(ctx, own, lambda: _swallow(lambda: ecs.deregister_task_definition(taskDefinition=arn)))
    return arn


def _create_cluster(ctx, ecs, own) -> str:
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=_ecs_tags())

    def _drop_cluster():
        # Services registered LATER are deleted FIRST (LIFO); wait for them to go INACTIVE, because
        # DeleteCluster refuses a cluster that still holds a DRAINING service.
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            try:
                ecs.delete_cluster(cluster=name)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ClusterNotFoundException":
                    return
                time.sleep(10)
        print(f"ecs cluster {name} not deleted within the teardown deadline")

    _net(ctx, own, _drop_cluster)
    return name


def _create_service(ctx, ecs, cluster, td_arn, net, alarm, own) -> str:
    name = ctx.unique_name("sim2real-behav-ecs-svc-")
    ecs.create_service(
        cluster=cluster,
        serviceName=name,
        taskDefinition=td_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=net,
        deploymentConfiguration={
            "minimumHealthyPercent": 100,
            "maximumPercent": 200,
            "alarms": {"alarmNames": [alarm], "enable": True, "rollback": True},
        },
        tags=_ecs_tags(),
    )

    def _drop():
        _swallow(lambda: ecs.update_service(cluster=cluster, service=name, desiredCount=0))
        _swallow(lambda: ecs.delete_service(cluster=cluster, service=name, force=True))
        deadline = time.monotonic() + 420
        while time.monotonic() < deadline:
            try:
                found = ecs.describe_services(cluster=cluster, services=[name]).get("services") or [{}]
            except ClientError:
                return
            if found[0].get("status", "INACTIVE") == "INACTIVE":
                return
            time.sleep(10)
        print(f"ecs service {name} in {cluster} not INACTIVE within the teardown deadline")

    _net(ctx, own, _drop)
    return name


def _public_network(ctx, own):
    """A dedicated VPC with public subnets in two AZs, an IGW and a default route.

    The account may have no usable default VPC; the public route lets tasks pull from public ECR.
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
        CidrBlock="10.195.0.0/24",
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
            time.sleep(10)
        for sid in subnet_ids:
            while time.monotonic() < deadline:
                try:
                    ec2.delete_subnet(SubnetId=sid)
                    break
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") == "InvalidSubnetID.NotFound":
                        break
                    time.sleep(10)
        for gw in igw_id:
            _swallow(lambda: ec2.detach_internet_gateway(InternetGatewayId=gw, VpcId=vpc_id))
            _swallow(lambda: ec2.delete_internet_gateway(InternetGatewayId=gw))
        while time.monotonic() < deadline:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidVpcID.NotFound":
                    return
                time.sleep(10)
        raise RuntimeError(
            f"vpc {vpc_id} / subnets {subnet_ids} / igw {igw_id} not deleted within the teardown deadline"
        )

    _net(ctx, own, _teardown_network)
    # DescribeVpcs can answer InvalidVpcID.NotFound just after CreateVpc; vpc_exists retries it.
    ec2.get_waiter("vpc_exists").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    for i, az in enumerate(azs[:2]):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.195.0.{i * 128}/25",
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
