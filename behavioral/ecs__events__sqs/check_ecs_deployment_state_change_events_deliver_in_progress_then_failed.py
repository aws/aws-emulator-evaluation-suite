"""ecs-deployment-state-change-events-deliver-in-progress-then-failed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-deployment-state-change-events-deliver-in-progress-then-failed"
GROUP = "service-deployment"
SERVICES = ["ecs", "events", "sqs"]

_DETAIL_TYPE = "ECS Deployment State Change"
_IN_PROGRESS = "SERVICE_DEPLOYMENT_IN_PROGRESS"
_COMPLETED = "SERVICE_DEPLOYMENT_COMPLETED"
_FAILED = "SERVICE_DEPLOYMENT_FAILED"
_BAD_TAG = "sim2real-no-such-tag"

_STEADY_TIMEOUT_S = 900.0
_FAILED_TIMEOUT_S = 1500.0
_ROLLBACK_TIMEOUT_S = 1200.0
_EVENT_TIMEOUT_S = 600.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:e2e", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """A healthy ECS deployment delivers IN_PROGRESS and COMPLETED (INFO) events via EventBridge,
    and a deployment failed by the circuit breaker delivers SERVICE_DEPLOYMENT_FAILED (ERROR)
    naming the failed deploymentId; the healthy leg is the positive control for the same wiring.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs_service_deployment_events.html
    """
    ecs = ctx.client("ecs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_ecs_service_linked_role(ctx)
    subnet_id, sg_id = _public_network(ctx)
    cluster = _create_cluster(ctx, ecs)

    family = ctx.unique_name("sim2real-behav-ecs-depev-")
    good_td = _register(ctx, ecs, family, "busybox:latest")
    bad_td = _register(ctx, ecs, family, f"busybox:{_BAD_TAG}")

    # The rule must exist BEFORE the service does, or the initial deployment's events are emitted
    # into nothing. The service ARN is therefore constructed from values this check chooses, and
    # CreateService's own answer is asserted against it below rather than trusted.
    service = ctx.unique_name("sim2real-behav-ecs-depev-svc-")
    service_arn = f"arn:aws:ecs:{ctx.region}:{account}:service/{cluster}/{service}"
    queue_url = _rule_and_queue(ctx, service_arn)

    net = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    created = ecs.create_service(
        cluster=cluster,
        serviceName=service,
        taskDefinition=good_td,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=net,
        deploymentConfiguration={
            # SERVICE_DEPLOYMENT_FAILED is only emitted for services with the circuit breaker on.
            "deploymentCircuitBreaker": {"enable": True, "rollback": True},
            "minimumHealthyPercent": 100,
            "maximumPercent": 200,
        },
        tags=_ecs_tags(),
    )["service"]

    def _drop_service():
        _unless_gone(lambda: ecs.update_service(cluster=cluster, service=service, desiredCount=0),
                     ("ServiceNotFoundException", "ServiceNotActiveException",
                      "ClusterNotFoundException"))
        _unless_gone(lambda: ecs.delete_service(cluster=cluster, service=service, force=True),
                     ("ServiceNotFoundException", "ServiceNotActiveException",
                      "ClusterNotFoundException"))
        # DeleteService returns before the service drains, and the cluster delete runs next.
        _poll_until(
            lambda: _describe(ecs, cluster, service),
            lambda d: d.get("status") == "INACTIVE" and d.get("runningCount", 0) == 0,
            timeout_s=200,
            interval_s=2,
            description="the deleted service to fully drain to INACTIVE with no running tasks",
        )

    ctx.on_cleanup(_drop_service)
    assert created["serviceArn"] == service_arn, (
        f"the EventBridge rule was scoped to the predicted service ARN {service_arn!r}, but ECS "
        f"created {created['serviceArn']!r}; the pattern would match nothing and every absence below "
        f"would be an artifact of that, not evidence"
    )

    # --- leg 1: the healthy deployment, and the positive control for the wiring ------------------
    steady = _poll_until(
        lambda: _primary(ecs, cluster, service),
        lambda d: d.get("rolloutState") == "COMPLETED",
        timeout_s=_STEADY_TIMEOUT_S,
        interval_s=15,
        description="the initial deployment of the healthy revision reaches a COMPLETED rollout",
    )
    good_deployment_id = steady["id"]

    delivered = _drain_for(ctx, queue_url, {_IN_PROGRESS, _COMPLETED})
    for name in (_IN_PROGRESS, _COMPLETED):
        events = delivered[name]
        assert events, (
            f"the healthy deployment must deliver a {name} event to the queue behind the rule; "
            f"nothing arrived within {_EVENT_TIMEOUT_S}s. With no delivery path proven here, the "
            f"{_FAILED} assertion below could not distinguish 'correctly silent' from 'never sent' "
            f"(delivered so far: { {k: len(v) for k, v in delivered.items()} })"
        )
        assert any(e.get("deploymentId") == good_deployment_id for e in events), (
            f"the delivered {name} events must name the deployment DescribeServices reports as "
            f"PRIMARY ({good_deployment_id!r}); got "
            f"{[e.get('deploymentId') for e in events]!r}"
        )
    assert all(e.get("eventType") == "INFO" for e in delivered[_COMPLETED]), (
        f"a successful deployment is an INFO event, got "
        f"{[e.get('eventType') for e in delivered[_COMPLETED]]!r}"
    )

    # --- leg 2: break exactly one thing — a revision whose image cannot be pulled ----------------
    ecs.update_service(cluster=cluster, service=service, taskDefinition=bad_td)
    bad_deployment_id = _poll_until(
        lambda: _primary(ecs, cluster, service),
        lambda d: d["taskDefinition"] == bad_td,
        timeout_s=300,
        interval_s=10,
        description="the unpullable revision becomes the PRIMARY deployment",
    )["id"]
    assert bad_deployment_id != good_deployment_id, (
        f"the failing deployment must be a NEW deployment, but ECS reported the same id "
        f"{bad_deployment_id!r} for both"
    )
    failed = _poll_until(
        lambda: _deployment_by_id(ecs, cluster, service, bad_deployment_id),
        lambda d: d is not None and d.get("rolloutState") == "FAILED",
        timeout_s=_FAILED_TIMEOUT_S,
        interval_s=20,
        description="ECS's own circuit breaker drives the unpullable deployment to rolloutState "
        "FAILED",
    )
    assert "circuit breaker" in (failed.get("rolloutStateReason") or "").lower(), (
        f"the deployment must have been failed by the circuit breaker, and the reason must say so: "
        f"rolloutStateReason={failed.get('rolloutStateReason')!r}"
    )

    # --- leg 3: the verdict, read at the CONSUMER ------------------------------------------------
    error_events = _drain_for(ctx, queue_url, {_FAILED})[_FAILED]
    assert error_events, (
        f"the circuit breaker failed deployment {bad_deployment_id!r} on the control plane, so a "
        f"{_FAILED} event must be delivered to the consumer; nothing arrived within "
        f"{_EVENT_TIMEOUT_S}s even though the same rule, queue and queue policy demonstrably "
        f"delivered {_IN_PROGRESS} and {_COMPLETED} earlier in this run"
    )
    matching = [e for e in error_events if e.get("deploymentId") == bad_deployment_id]
    assert matching, (
        f"the delivered {_FAILED} events must name the deployment that actually failed "
        f"({bad_deployment_id!r}) and not the one that succeeded ({good_deployment_id!r}); got "
        f"{[e.get('deploymentId') for e in error_events]!r}"
    )
    assert all(e.get("eventType") == "ERROR" for e in matching), (
        f"a failed deployment is an ERROR event, not INFO; got "
        f"{[e.get('eventType') for e in matching]!r}"
    )

    # The rollback is the independent read at the producer that corroborates what the consumer said:
    # the service must be back on the revision that worked.
    rolled_back = _poll_until(
        lambda: _primary(ecs, cluster, service),
        lambda d: d["taskDefinition"] == good_td and d.get("rolloutState") == "COMPLETED",
        timeout_s=_ROLLBACK_TIMEOUT_S,
        interval_s=20,
        description="the rollback returns the service to the last good revision",
    )
    assert rolled_back["taskDefinition"] == good_td, (
        f"after the circuit breaker rolled back, the PRIMARY deployment must be the healthy revision "
        f"{good_td!r}, got {rolled_back['taskDefinition']!r}"
    )


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _ecs_tags() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _ec2_tags() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _unless_gone(fn, gone) -> None:
    """Run a teardown step; only the operation's not-found codes in ``gone`` count as done."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in gone:
            raise


def _retry_in_use(fn, retry, gone, timeout_s=120.0) -> None:
    """Retry a delete refused with a ``retry`` code every 2 s up to ``timeout_s``; raise the
    rest."""
    deadline = time.monotonic() + timeout_s
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


def _describe(ecs, cluster, service) -> dict:
    resp = ecs.describe_services(cluster=cluster, services=[service])
    assert not resp.get("failures"), (
        f"DescribeServices could not read {service!r}: {resp.get('failures')!r}"
    )
    return resp["services"][0]


def _primary(ecs, cluster, service) -> dict:
    svc = _describe(ecs, cluster, service)
    primary = [d for d in svc["deployments"] if d["status"] == "PRIMARY"]
    assert len(primary) == 1, (
        f"service {service} must have exactly one PRIMARY deployment, got "
        f"{[d['status'] for d in svc['deployments']]!r}"
    )
    return primary[0]


def _deployment_by_id(ecs, cluster, service, deployment_id):
    for d in _describe(ecs, cluster, service)["deployments"]:
        if d["id"] == deployment_id:
            return d
    return None


def _ensure_ecs_service_linked_role(ctx) -> None:
    """Create-or-adopt the ECS service-linked role, which CreateService requires."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("InvalidInput", "InvalidInputException", "EntityAlreadyExists"):
            raise
    # Not torn down: the role is account-global and shared with concurrent runs.


def _register(ctx, ecs, family, image_suffix) -> str:
    arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": f"public.ecr.aws/docker/library/{image_suffix}",
                "essential": True,
                "command": ["sh", "-c", "sleep 3600"],
            }
        ],
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        tags=_ecs_tags(),
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=arn))
    return arn


def _create_cluster(ctx, ecs) -> str:
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=_ecs_tags())
    ctx.on_cleanup(lambda: _retry_in_use(
        lambda: ecs.delete_cluster(cluster=name),
        ("ClusterContainsServicesException", "ClusterContainsTasksException",
         "UpdateInProgressException"),
        ("ClusterNotFoundException",),
    ))
    return name


def _rule_and_queue(ctx, service_arn) -> str:
    """An SQS queue behind an EventBridge rule matching this service's deployment events.

    The queue policy is scoped to this rule's ARN, so nothing else in the account can deliver into
    it — which is what makes an empty queue mean "ECS sent nothing" rather than "something else was
    filtered out".
    """
    sqs = ctx.client("sqs")
    events = ctx.client("events")

    q_name = ctx.unique_name("sim2real-behav-ecs-depev-q-")
    q_url = sqs.create_queue(QueueName=q_name, tags=dict(_MANAGED_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: sqs.delete_queue(QueueUrl=q_url),
        ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"),
    ))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    rule = ctx.unique_name("sim2real-behav-ecs-depev-rule-")
    rule_arn = events.put_rule(
        Name=rule,
        State="ENABLED",
        Description="SimParity behavioral: ECS Deployment State Change -> SQS",
        Tags=_ec2_tags(),
        EventPattern=json.dumps(
            {
                "source": ["aws.ecs"],
                "detail-type": [_DETAIL_TYPE],
                "resources": [service_arn],
            }
        ),
    )["RuleArn"]

    def _drop_rule():
        _unless_gone(lambda: events.remove_targets(Rule=rule, Ids=["q"]),
                     ("ResourceNotFoundException",))
        _unless_gone(lambda: events.delete_rule(Name=rule), ("ResourceNotFoundException",))

    ctx.on_cleanup(_drop_rule)
    sqs.set_queue_attributes(
        QueueUrl=q_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowThisRuleOnly",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": q_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                        }
                    ],
                }
            )
        },
    )
    events.put_targets(Rule=rule, Targets=[{"Id": "q", "Arn": q_arn}])

    # A rule created seconds earlier can miss the first IN_PROGRESS event, and there is no API that
    # reports when a rule is live, so hold a bounded settle window before creating the service.
    _settle_rule(events, rule, "q")
    return q_url


def _settle_rule(events, rule: str, target_id: str, *, window_s=90.0, interval_s=10.0) -> None:
    """Hold for `window_s`, re-confirming the target registration stays visible throughout."""
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        targets = events.list_targets_by_rule(Rule=rule)["Targets"]
        assert any(t["Id"] == target_id for t in targets), (
            f"rule {rule!r} lost its target {target_id!r} while settling; the wiring this check "
            f"depends on no longer exists"
        )
        time.sleep(interval_s)


def _drain_for(ctx, queue_url, wanted) -> dict:
    """Long-poll the queue until every wanted eventName has been seen, or the deadline passes.

    Returns eventName -> list of detail dicts. Delivery COUNT is never asserted by the caller:
    EventBridge is at-least-once, so the invariant is what each delivered event SAYS.
    """
    sqs = ctx.client("sqs")
    found: dict[str, list[dict]] = {name: [] for name in wanted}
    deadline = time.monotonic() + _EVENT_TIMEOUT_S
    while time.monotonic() < deadline and not all(found[n] for n in wanted):
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=20
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            assert body.get("detail-type") == _DETAIL_TYPE, (
                f"the rule is scoped to {_DETAIL_TYPE!r} only, so nothing else may be delivered into "
                f"this queue; got detail-type={body.get('detail-type')!r}"
            )
            detail = body["detail"]
            name = detail.get("eventName")
            if name in found:
                found[name].append(detail)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return found


def _public_network(ctx):
    """A dedicated VPC with one public subnet, an IGW and a default route.

    An account's default VPC may be missing or misconfigured, which would fail the healthy deployment.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.191.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags()}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.191.0.0/25",
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
        while ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
        ).get("NetworkInterfaces", []):
            if time.monotonic() >= deadline:
                raise AssertionError(f"subnet {subnet_id} still holds ENIs 600s into its teardown")
            time.sleep(2)
        _retry_in_use(lambda: ec2.delete_subnet(SubnetId=subnet_id), ("DependencyViolation",),
                      ("InvalidSubnetID.NotFound",))
        _unless_gone(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
                     ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"))
        _unless_gone(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id),
                     ("InvalidInternetGatewayID.NotFound",))
        _retry_in_use(lambda: ec2.delete_vpc(VpcId=vpc_id), ("DependencyViolation",),
                      ("InvalidVpcID.NotFound",))

    ctx.on_cleanup(_teardown_network)
    return subnet_id, sg_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
