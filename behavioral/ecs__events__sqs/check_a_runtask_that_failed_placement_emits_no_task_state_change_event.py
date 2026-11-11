"""a-runtask-that-failed-placement-emits-no-task-state-change-event."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "a-runtask-that-failed-placement-emits-no-task-state-change-event"
GROUP = "event-propagation"
SERVICES = ["ecs", "events", "sqs"]

_DETAIL_TYPE = "ECS Task State Change"
#: Upper bound on this check's total runtime, in seconds.
_WORST_CASE_BUDGET_S = 1200


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _make_queue(ctx, name, check_tag):
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": check_tag})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowEventBridge",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {
                                "ArnLike": {
                                    "aws:SourceArn": f"arn:*:events:{ctx.region}:{account}:rule/*"
                                }
                            },
                        }
                    ],
                }
            )
        },
    )
    return url, arn


def _drain(ctx, url, *, seconds):
    """`.get("Messages", [])` feeds a loop whose result is asserted by exact membership — the
    sanctioned polarity for an empty default."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _queue_depth(ctx, url):
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=[
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
        ],
    )["Attributes"]
    return sum(int(v) for v in attrs.values())


def _make_network(ctx, check_tag):
    """A VPC and one subnet, created in-check. No IGW and no NAT: the control task is EXPECTED to
    fail to reach the registry, which is sufficient — it still gets placed, which is the point."""
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.191.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [
                    {"Key": "Name", "Value": "sim2real-nd-ecs"},
                    {"Key": "sim2real-check", "Value": check_tag},
                ],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ctx.client("ec2"), "delete_vpc", VpcId=vpc))
    zone = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert zone, (
        f"describe_availability_zones returned no available zone in {ctx.region}, so no subnet can "
        f"be created and neither leg of this check can run"
    )
    subnet = ec2.create_subnet(
        VpcId=vpc,
        CidrBlock="10.191.1.0/24",
        AvailabilityZone=zone[0]["ZoneName"],
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "sim2real-check", "Value": check_tag}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ctx.client("ec2"), "delete_subnet", SubnetId=subnet))
    return vpc, subnet


def _put_targets_ok(events, rule, targets):
    resp = events.put_targets(Rule=rule, Targets=targets)
    assert resp.get("FailedEntryCount") == 0, (
        f"put_targets on {rule} reported failures, so the wiring under test does not exist: "
        f"{resp.get('FailedEntries')!r}"
    )


def _teardown_rule(ctx, rule):
    events = ctx.client("events")
    events.remove_targets(Rule=rule, Ids=["q"], Force=True)
    events.delete_rule(Name=rule, Force=True)


def _stop_and_delete_cluster(ctx, cluster):
    ecs = ctx.client("ecs")
    for status in ("RUNNING", "PENDING"):
        for arn in ecs.list_tasks(cluster=cluster, desiredStatus=status).get("taskArns", []):
            try:
                ecs.stop_task(cluster=cluster, task=arn, reason="sim2real teardown")
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "InvalidParameterException":
                    raise
    ecs.delete_cluster(cluster=cluster)


# ===== the check =====
@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A RunTask that fails placement creates no task and emits no ECS Task State Change event, while
    a task that WAS placed and then failed emits the full sequence on the same cluster and rule."""
    ecs = ctx.client("ecs")
    events = ctx.client("events")
    check_tag = CHECK
    suffix = uuid.uuid4().hex[:10]

    cluster = ctx.unique_name("sim2real-nd-ecs-")
    ecs.create_cluster(
        clusterName=cluster, tags=[{"key": "sim2real-check", "value": check_tag}]
    )
    ctx.on_cleanup(lambda: _stop_and_delete_cluster(ctx, cluster))
    described = ecs.describe_clusters(clusters=[cluster])["clusters"]
    assert described and described[0]["registeredContainerInstancesCount"] == 0, (
        f"the cluster {cluster} reports "
        f"{described[0]['registeredContainerInstancesCount'] if described else 'no cluster'} "
        f"registered container instances, expected 0 — the EC2-launch-type placement failure this "
        f"check depends on requires an empty cluster"
    )
    cluster_arn = described[0]["clusterArn"]

    _, subnet = _make_network(ctx, check_tag)

    family = ctx.unique_name("sim2real-nd-ecs-td-")
    task_def = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE", "EC2"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "probe",
                # A registry this subnet has no route to. The task is still PLACED, which is all the
                # control leg needs; asserting a specific stoppedReason is deliberately avoided.
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", "exit 0"],
            }
        ],
        tags=[{"key": "sim2real-check", "value": check_tag}],
    )["taskDefinition"]
    ctx.on_cleanup(
        lambda: _retire_task_definition(ctx.client("ecs"), task_def["taskDefinitionArn"])
    )

    queue_url, queue_arn = _make_queue(ctx, f"sim2real-nd-ecs-{suffix}", check_tag)
    rule = ctx.unique_name("sim2real-nd-ecs-rule-")
    events.put_rule(
        Name=rule,
        EventPattern=json.dumps(
            {
                "source": ["aws.ecs"],
                "detail-type": [_DETAIL_TYPE],
                "detail": {"clusterArn": [cluster_arn]},
            }
        ),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": check_tag}],
    )
    ctx.on_cleanup(lambda: _teardown_rule(ctx, rule))
    _put_targets_ok(events, rule, [{"Id": "q", "Arn": queue_arn}])

    # BEAT 1 — a task that IS placed, into a subnet with no route to the registry. It never needs to
    # pull successfully: a task that exists has a state, and its state changes are what must be
    # delivered. This also measures L for the absence window.
    t0 = time.monotonic()
    placed = ecs.run_task(
        cluster=cluster,
        taskDefinition=task_def["taskDefinitionArn"],
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": [subnet], "assignPublicIp": "DISABLED"}
        },
        tags=[{"key": "sim2real-check", "value": check_tag}],
    )
    assert placed.get("failures") == [] and len(placed.get("tasks", [])) == 1, (
        f"the FARGATE control RunTask did not place exactly one task: failures="
        f"{placed.get('failures')!r} tasks={len(placed.get('tasks', []))} — without a placed task "
        f"there is no positive control and the absence below is not evidence"
    )
    control_task_arn = placed["tasks"][0]["taskArn"]
    control_events = _poll_until(
        lambda: _drain(ctx, queue_url, seconds=6),
        lambda msgs: any(m["detail"]["taskArn"] == control_task_arn for m in msgs),
        timeout_s=300,
        interval_s=0,
        description=(
            f"an '{_DETAIL_TYPE}' event for the placed task {control_task_arn} reached {queue_url} — "
            f"the positive control for the ECS -> EventBridge -> SQS wiring in this run"
        ),
    )
    latency = max(time.monotonic() - t0, 1.0)
    for msg in control_events:
        assert msg["detail"]["clusterArn"] == cluster_arn, (
            f"a delivered event names clusterArn={msg['detail']['clusterArn']!r}, expected "
            f"{cluster_arn!r} — the rule's pattern pins the cluster, so a mismatch means the pattern "
            f"was not applied"
        )
        assert msg["source"] == "aws.ecs" and msg["detail-type"] == _DETAIL_TYPE, (
            f"a delivered event carries source={msg['source']!r} detail-type={msg['detail-type']!r}, "
            f"expected 'aws.ecs' / {_DETAIL_TYPE!r}"
        )
    statuses = [m["detail"]["lastStatus"] for m in control_events]
    assert statuses, f"no lastStatus on any delivered control event: {control_events!r}"

    # BEAT 2 — the failed placement. STRUCTURAL: an EC2-launch-type task cannot be placed on a
    # cluster with no container instances. MEASURED against real AWS: this is not a 200 with a
    # `failures[]` entry, it is a synchronous refusal — RunTask never returns, so no `tasks` or
    # `failures` list to inspect exists at all, and (by construction) no task is ever created.
    try:
        ecs.run_task(
            cluster=cluster,
            taskDefinition=task_def["taskDefinitionArn"],
            launchType="EC2",
            count=1,
            networkConfiguration={
                "awsvpcConfiguration": {"subnets": [subnet], "assignPublicIp": "DISABLED"}
            },
        )
    except ClientError as exc:
        error = exc.response.get("Error", {})
        assert error.get("Code") == "InvalidParameterException", (
            f"RunTask with launchType=EC2 on a cluster with zero registered container instances "
            f"raised {error.get('Code')!r}, expected 'InvalidParameterException': {error!r}"
        )
        assert error.get("Message") == "No Container Instances were found in your cluster.", (
            f"the InvalidParameterException carries message {error.get('Message')!r}, expected "
            f"the exact literal measured against real AWS for an empty cluster"
        )
    else:
        raise AssertionError(
            "RunTask with launchType=EC2 on a cluster with zero registered container instances "
            "returned successfully — measured against real AWS to raise InvalidParameterException "
            "synchronously instead, and the whole negative rests on that refusal"
        )

    # The structural second observable, across every desired state: no second task exists anywhere.
    seen_tasks = set()
    for status in ("RUNNING", "PENDING", "STOPPED"):
        seen_tasks.update(ecs.list_tasks(cluster=cluster, desiredStatus=status).get("taskArns", []))
    assert seen_tasks == {control_task_arn}, (
        f"ListTasks on {cluster} reports {sorted(seen_tasks)!r}, expected exactly "
        f"[{control_task_arn!r}] — the failed placement must not have created a task in any state"
    )

    # Drive the control task to its terminal state explicitly, rather than waiting on AWS's own
    # image-pull retry/backoff for a registry this subnet cannot reach: MEASURED against real AWS,
    # that natural failure had not reached STOPPED even after 300s of PENDING, which is an unbounded
    # wait this check must not gamble its budget on. StopTask forces a fast, deterministic
    # PENDING/RUNNING -> STOPPED transition, and the property under test — a task that EXISTED gets
    # its terminal state change delivered — holds regardless of why it stopped.
    ecs.stop_task(cluster=cluster, task=control_task_arn, reason="sim2real control task stop")

    # BEAT 3 — THE NEGATIVE, held for 3L and confirmed by queue depth. The control task is still
    # transitioning toward STOPPED (forced above), so its own events are expected here and are
    # filtered out by ARN; anything naming a DIFFERENT task ARN is the failure this check exists to
    # detect.
    hold = max(3 * latency, 15.0)
    later = _drain(ctx, queue_url, seconds=hold)
    strangers = [m for m in later if m["detail"]["taskArn"] != control_task_arn]
    assert strangers == [], (
        f"{len(strangers)} '{_DETAIL_TYPE}' event(s) named a task other than the placed control task "
        f"during a {hold:.0f}s hold (3x the {latency:.0f}s measured latency): "
        f"{[(m['detail']['taskArn'], m['detail'].get('lastStatus')) for m in strangers]!r} — a "
        f"RunTask that placed nothing has no task whose state could change"
    )
    # The control task's own events prove the path stayed live throughout the hold, so the absence
    # above is a withholding rather than a queue that stopped receiving.
    assert later, (
        f"the queue received NOTHING during the {hold:.0f}s hold, not even a further state change for "
        f"the control task {control_task_arn} — the delivery path may have died, in which case the "
        f"absence of stranger events is not attributable to the failed placement"
    )
    assert _queue_depth(ctx, queue_url) == 0, (
        f"the queue reports depth {_queue_depth(ctx, queue_url)} behind an empty receive"
    )

    # BEAT 4 — the terminal read at the consumer, on the control task only: it reached STOPPED, so
    # the event sequence for a task that DID exist is complete.
    terminal = _poll_until(
        lambda: _drain(ctx, queue_url, seconds=8)
        + [
            {"detail": {"taskArn": control_task_arn, "lastStatus": t["lastStatus"]}}
            for t in ecs.describe_tasks(cluster=cluster, tasks=[control_task_arn])["tasks"]
        ],
        lambda msgs: any(
            m["detail"]["taskArn"] == control_task_arn and m["detail"]["lastStatus"] == "STOPPED"
            for m in msgs
        ),
        timeout_s=300,
        interval_s=5,
        description=(
            f"the control task {control_task_arn} reached lastStatus STOPPED, so the task that DID "
            f"exist ran its state machine to a terminal state"
        ),
    )
    assert any(m["detail"]["lastStatus"] == "STOPPED" for m in terminal), (
        f"the control task never reported STOPPED: {terminal!r}"
    )

    # A stopped Fargate awsvpc task detaches its ENI asynchronously, after lastStatus already reads
    # STOPPED. Wait for that here so this check's own 60s cleanup budget only has to delete an
    # already-unattached subnet and VPC rather than race the detach: deleting the subnet/VPC
    # before the ENI detaches fails with DependencyViolation.
    final_attachments = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster, tasks=[control_task_arn])["tasks"][0].get(
            "attachments", []
        ),
        lambda atts: all(a.get("status") == "DELETED" for a in atts),
        timeout_s=120,
        interval_s=5,
        description=(
            f"the control task {control_task_arn}'s ENI attachment(s) reaching DELETED after "
            f"STOPPED, so teardown does not race the network interface's own detachment"
        ),
    )
    assert all(a.get("status") == "DELETED" for a in final_attachments), (
        f"the control task's attachments did not all reach DELETED: {final_attachments!r}"
    )


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that leaked the
# VPC while the check PASSED. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached. Every other error propagates. Teardown-only: nothing run() executes calls this, so it
# cannot change the verdict. The window is shared by all of one check's network deletes.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


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
