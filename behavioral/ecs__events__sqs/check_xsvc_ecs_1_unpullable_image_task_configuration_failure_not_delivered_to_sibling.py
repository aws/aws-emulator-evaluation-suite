"""xsvc-ecs-1-unpullable-image-task-configuration-failure-not-delivered-to-sibling."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-ecs-1-unpullable-image-task-configuration-failure-not-delivered-to-sibling"
GROUP = "event-propagation"
SERVICES = ["ecs", "events", "sqs"]

_DETAIL_TYPE = "ECS Service Action"
_FAILURE = "SERVICE_TASK_CONFIGURATION_FAILURE"
_STEADY = "SERVICE_STEADY_STATE"
_BAD_TAG = "sim2real-no-such-tag"

_EVENT_TIMEOUT_S = 300.0
_TEARDOWN_S = 240.0


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:e2e",
    "concern:eventing",
    "plane:control",
)
def run(ctx) -> None:
    """A service whose image cannot be pulled emits SERVICE_TASK_CONFIGURATION_FAILURE (ERROR, reason
    CannotPullContainerError) scoped to its own service ARN, while rules scoped to a healthy sibling
    receive only its SERVICE_STEADY_STATE and never the failure.
    """
    ecs = ctx.client("ecs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_ecs_service_linked_role(ctx)

    # One teardown, registered before the first create and filled in as resources appear. It
    # deletes the quick resources first (rules, queues, task definitions) and only then waits on the
    # slow Fargate drain and ENI release. The happy path also calls it at the end of the body.
    estate = _Estate(ctx)
    ctx.on_cleanup(estate.teardown)

    cluster = ctx.unique_name("sim2real-xsvc-ecs-cluster-")
    ecs.create_cluster(clusterName=cluster, tags=_ecs_tags())
    estate.cluster = cluster
    cluster_arn = f"arn:aws:ecs:{ctx.region}:{account}:cluster/{cluster}"

    # Rules first, before the network and services exist, so they have been live for the whole
    # provisioning window before ECS can emit anything. The ARNs are predicted from names this check
    # chooses and asserted against CreateService's own answer below.
    good_svc = ctx.unique_name("sim2real-xsvc-ecs-tcf-good-")
    bad_svc = ctx.unique_name("sim2real-xsvc-ecs-tcf-bad-")
    good_arn = f"arn:aws:ecs:{ctx.region}:{account}:service/{cluster}/{good_svc}"
    bad_arn = f"arn:aws:ecs:{ctx.region}:{account}:service/{cluster}/{bad_svc}"

    base = {"source": ["aws.ecs"], "detail-type": [_DETAIL_TYPE]}
    q_bad = estate.rule_and_queue("bad", dict(base, resources=[bad_arn]))
    q_good = estate.rule_and_queue("good", dict(base, resources=[good_arn]))
    q_near = estate.rule_and_queue(
        "near", dict(base, resources=[good_arn], detail={"eventName": [_FAILURE, _STEADY]})
    )

    subnet_id, sg_id = estate.public_network()
    family = ctx.unique_name("sim2real-xsvc-ecs-tcf-")
    good_td = estate.register(family, "busybox:latest")
    bad_td = estate.register(family, f"busybox:{_BAD_TAG}")

    net = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    for name, td, expected in ((bad_svc, bad_td, bad_arn), (good_svc, good_td, good_arn)):
        estate.services.append(name)  # before the create: a create that raises may still exist
        created = ecs.create_service(
            cluster=cluster,
            serviceName=name,
            taskDefinition=td,
            desiredCount=1,
            launchType="FARGATE",
            networkConfiguration=net,
            # Off on purpose: with the breaker on, the unpullable deployment would be FAILED and
            # rolled back instead of being left to keep failing task starts.
            deploymentConfiguration={
                "deploymentCircuitBreaker": {"enable": False, "rollback": False},
                "minimumHealthyPercent": 100,
                "maximumPercent": 200,
            },
            tags=_ecs_tags(),
        )["service"]
        assert created["serviceArn"] == expected, (
            f"the rules were scoped to the predicted service ARN {expected!r}, but ECS created "
            f"{created['serviceArn']!r}; every rule would match nothing"
        )

    # --- the barrier: BAD's failure event, and steady state on BOTH good-scoped rules -----------
    got = {"bad": [], "good": [], "near": []}
    queues = {"bad": q_bad, "good": q_good, "near": q_near}

    def _barrier():
        return (
            any(_name(b) == _FAILURE for b in got["bad"])
            and any(_name(b) == _STEADY for b in got["good"])
            and any(_name(b) == _STEADY for b in got["near"])
        )

    deadline = time.monotonic() + _EVENT_TIMEOUT_S
    while time.monotonic() < deadline and not _barrier():
        for key, url in queues.items():
            got[key].extend(_receive(ctx, url, wait_s=5))
    assert _barrier(), (
        f"within {_EVENT_TIMEOUT_S}s the failing service must deliver {_FAILURE} to R_bad, and the "
        f"healthy one {_STEADY} to both R_good and R_near; delivered "
        f"{ {k: [_name(b) for b in v] for k, v in got.items()} !r}; BAD's service events: "
        f"{_service_messages(ecs, cluster, bad_svc)!r}"
    )
    for key, url in queues.items():
        got[key].extend(_drain_until_quiet(ctx, url))

    # --- the failing service's own consumer ------------------------------------------------------
    failures = [b for b in got["bad"] if _name(b) == _FAILURE]
    for body in failures:
        assert body["detail"].get("eventType") == "ERROR", (
            f"{_FAILURE} is an ERROR event; got eventType={body['detail'].get('eventType')!r}"
        )
        assert body.get("resources") == [bad_arn], (
            f"the failure event must name exactly the failing service {bad_arn!r}; got "
            f"resources={body.get('resources')!r}"
        )
        assert body["detail"].get("clusterArn") == cluster_arn, (
            f"the failure event must name the cluster {cluster_arn!r}; got "
            f"{body['detail'].get('clusterArn')!r}"
        )
        reason = body["detail"].get("reason") or ""
        assert reason.startswith("CannotPullContainerError") and _BAD_TAG in reason, (
            f"the failure event's reason must say the image {_BAD_TAG!r} could not be pulled; got "
            f"reason={reason!r}"
        )
    for body in got["bad"]:
        assert body.get("detail-type") == _DETAIL_TYPE and body.get("resources") == [bad_arn], (
            f"R_bad is scoped to {bad_arn!r}; it delivered detail-type={body.get('detail-type')!r} "
            f"resources={body.get('resources')!r}"
        )

    # --- the healthy sibling's own consumer: steady state and nothing else ----------------------
    good_names = [_name(b) for b in got["good"]]
    assert set(good_names) == {_STEADY}, (
        f"the healthy sibling's own rule must deliver {_STEADY} and nothing else; got {good_names!r}"
    )
    for body in got["good"]:
        assert body.get("resources") == [good_arn] and body["detail"].get("eventType") == "INFO", (
            f"R_good is scoped to {good_arn!r} and steady state is INFO; it delivered "
            f"resources={body.get('resources')!r} eventType={body['detail'].get('eventType')!r}"
        )

    # --- the near miss: demonstrably live, and silent on the failure event ---------------------
    near_failure = [b for b in got["near"] if _name(b) == _FAILURE]
    assert near_failure == [], (
        f"R_near asks for {_FAILURE} on the HEALTHY service {good_arn!r}; the failure event names "
        f"only {bad_arn!r}, so none may be delivered — got "
        f"{[(_name(b), b.get('resources')) for b in near_failure]!r}"
    )
    assert all(b.get("resources") == [good_arn] for b in got["near"]), (
        f"R_near is scoped to {good_arn!r}; it delivered "
        f"{[b.get('resources') for b in got['near']]!r}"
    )

    # Teardown inside the check's own budget; the registered net then finds nothing left to do.
    estate.teardown()


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _ecs_tags() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _ec2_tags() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _unless_gone(fn, gone) -> None:
    """Run a teardown step; only the operation's not-found codes in ``gone`` count as done."""
    try:
        fn()
    except ClientError as exc:
        if _code(exc) not in gone:
            raise


def _retry_in_use(fn, retry, gone, deadline) -> None:
    """Retry a delete refused with a ``retry`` code every 2 s up to ``deadline``; raise the rest."""
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) in gone:
                return
            if _code(exc) not in retry or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _name(body) -> str | None:
    return (body.get("detail") or {}).get("eventName")


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _service_messages(ecs, cluster, service) -> list[str]:
    try:
        svc = ecs.describe_services(cluster=cluster, services=[service])["services"][0]
    except Exception as exc:  # noqa: BLE001 - diagnostic only
        return [f"<describe failed: {exc}>"]
    return [e.get("message", "") for e in svc.get("events", [])[:5]]


def _ensure_ecs_service_linked_role(ctx) -> None:
    """Create-or-adopt the ECS service-linked role, which CreateService requires."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        if _code(exc) not in ("InvalidInput", "InvalidInputException", "EntityAlreadyExists"):
            raise
    # Deliberately NOT torn down: account-global and shared with concurrent runs.


def _receive(ctx, queue_url, *, wait_s) -> list[dict]:
    """One long poll; returns parsed EventBridge envelopes and deletes what it read."""
    sqs = ctx.client("sqs")
    out = []
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
    for msg in resp.get("Messages", []):
        out.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _drain_until_quiet(ctx, queue_url, *, quiet_polls=1) -> list[dict]:
    out, quiet = [], 0
    while quiet < quiet_polls:
        batch = _receive(ctx, queue_url, wait_s=10)
        out.extend(batch)
        quiet = 0 if batch else quiet + 1
    return out


class _Estate:
    """Everything this check creates, and the one idempotent teardown that removes it."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.ecs = ctx.client("ecs")
        self.ec2 = ctx.client("ec2")
        self.sqs = ctx.client("sqs")
        self.events = ctx.client("events")
        self.rules: list[str] = []
        self.queues: list[str] = []
        self.task_defs: list[str] = []
        self.services: list[str] = []
        self.cluster: str | None = None
        self.vpc: str | None = None
        self.subnet: str | None = None
        self.igw: str | None = None

    # --- creates --------------------------------------------------------------------------------
    def rule_and_queue(self, label, pattern) -> str:
        """A queue whose policy admits only one rule, and that rule targeting it."""
        q_url = self.sqs.create_queue(
            QueueName=self.ctx.unique_name(f"sim2real-xsvc-ecs-{label}-"), tags=dict(_MANAGED_TAGS)
        )["QueueUrl"]
        self.queues.append(q_url)
        q_arn = self.sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])[
            "Attributes"
        ]["QueueArn"]
        rule = self.ctx.unique_name(f"sim2real-xsvc-ecs-{label}-")
        self.rules.append(rule)
        rule_arn = self.events.put_rule(
            Name=rule,
            State="ENABLED",
            Description=f"SimParity xsvc: {label} rule -> SQS",
            Tags=_ec2_tags(),
            EventPattern=json.dumps(pattern),
        )["RuleArn"]
        self.sqs.set_queue_attributes(
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
        self.events.put_targets(Rule=rule, Targets=[{"Id": "q", "Arn": q_arn}])
        return q_url

    def register(self, family, image_suffix) -> str:
        arn = self.ecs.register_task_definition(
            family=family,
            containerDefinitions=[
                {
                    "name": "app",
                    "image": f"public.ecr.aws/docker/library/{image_suffix}",
                    "essential": True,
                    # Exits on SIGTERM so teardown does not wait out the stop timeout.
                    "command": ["sh", "-c", "trap 'exit 0' TERM; sleep 3600 & wait"],
                    "stopTimeout": 2,
                }
            ],
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory="512",
            tags=_ecs_tags(),
        )["taskDefinition"]["taskDefinitionArn"]
        self.task_defs.append(arn)
        return arn

    def public_network(self):
        """A dedicated VPC with one public subnet, an IGW and a default route (no default VPC)."""
        ec2 = self.ec2
        self.vpc = ec2.create_vpc(
            CidrBlock="10.192.0.0/24",
            TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags()}],
        )["Vpc"]["VpcId"]
        ec2.get_waiter("vpc_available").wait(
            VpcIds=[self.vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
        ec2.modify_vpc_attribute(VpcId=self.vpc, EnableDnsSupport={"Value": True})
        ec2.modify_vpc_attribute(VpcId=self.vpc, EnableDnsHostnames={"Value": True})
        az = sorted(
            z["ZoneName"]
            for z in ec2.describe_availability_zones(
                Filters=[{"Name": "state", "Values": ["available"]}]
            )["AvailabilityZones"]
        )[0]
        self.subnet = ec2.create_subnet(
            VpcId=self.vpc,
            CidrBlock="10.192.0.0/25",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _ec2_tags()}],
        )["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=self.subnet, MapPublicIpOnLaunch={"Value": True})
        self.igw = ec2.create_internet_gateway(
            TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _ec2_tags()}]
        )["InternetGateway"]["InternetGatewayId"]
        ec2.attach_internet_gateway(InternetGatewayId=self.igw, VpcId=self.vpc)
        rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [self.vpc]}])[
            "RouteTables"
        ][0]["RouteTableId"]
        ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=self.igw)
        sg_id = next(
            sg["GroupId"]
            for sg in ec2.describe_security_groups(
                Filters=[{"Name": "vpc-id", "Values": [self.vpc]}]
            )["SecurityGroups"]
            if sg["GroupName"] == "default"
        )
        return self.subnet, sg_id

    # --- the one teardown -----------------------------------------------------------------------
    def teardown(self) -> None:
        """Idempotent; cheap deletes first, then the bounded waits. A leftover raises."""
        ecs, ec2 = self.ecs, self.ec2
        while self.rules:
            rule = self.rules.pop()
            _unless_gone(lambda r=rule: self.events.remove_targets(Rule=r, Ids=["q"]),
                         ("ResourceNotFoundException",))
            _unless_gone(lambda r=rule: self.events.delete_rule(Name=r),
                         ("ResourceNotFoundException",))
        while self.queues:
            q = self.queues.pop()
            _unless_gone(lambda u=q: self.sqs.delete_queue(QueueUrl=u),
                         ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"))
        while self.task_defs:
            arn = self.task_defs.pop()
            ecs.deregister_task_definition(taskDefinition=arn)
            ecs.delete_task_definitions(taskDefinitions=[arn])
        deadline = time.monotonic() + _TEARDOWN_S
        if self.cluster:
            gone = ("ServiceNotFoundException", "ServiceNotActiveException",
                    "ClusterNotFoundException")
            for svc in self.services:
                _unless_gone(lambda s=svc: ecs.update_service(
                    cluster=self.cluster, service=s, desiredCount=0), gone)
                _unless_gone(lambda s=svc: ecs.delete_service(
                    cluster=self.cluster, service=s, force=True), gone)

            def _stop_and_delete():
                for t in ecs.list_tasks(cluster=self.cluster)["taskArns"]:
                    ecs.stop_task(cluster=self.cluster, task=t)
                ecs.delete_cluster(cluster=self.cluster)

            _retry_in_use(_stop_and_delete, ("ClusterContainsTasksException",
                                             "ClusterContainsServicesException",
                                             "UpdateInProgressException"),
                          ("ClusterNotFoundException",), deadline)
            self.cluster = None
        if self.vpc:
            if self.subnet:
                while ec2.describe_network_interfaces(
                    Filters=[{"Name": "subnet-id", "Values": [self.subnet]}]
                ).get("NetworkInterfaces", []):
                    if time.monotonic() >= deadline:
                        raise AssertionError(
                            f"subnet {self.subnet} still holds ENIs after {_TEARDOWN_S}s")
                    time.sleep(2)
                _retry_in_use(lambda: ec2.delete_subnet(SubnetId=self.subnet),
                              ("DependencyViolation",), ("InvalidSubnetID.NotFound",), deadline)
                self.subnet = None
            if self.igw:
                _unless_gone(lambda: ec2.detach_internet_gateway(
                    InternetGatewayId=self.igw, VpcId=self.vpc),
                    ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"))
                _unless_gone(lambda: ec2.delete_internet_gateway(InternetGatewayId=self.igw),
                             ("InvalidInternetGatewayID.NotFound",))
                self.igw = None
            _retry_in_use(lambda: ec2.delete_vpc(VpcId=self.vpc), ("DependencyViolation",),
                          ("InvalidVpcID.NotFound",), deadline)
            self.vpc = None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
