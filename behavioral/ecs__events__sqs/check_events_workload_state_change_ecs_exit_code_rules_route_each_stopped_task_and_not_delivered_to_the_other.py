"""events-workload-state-change-ecs-exit-code-rules-route-each-stopped-task-and-not-delivered-to-the-other."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-workload-state-change-ecs-exit-code-rules-route-each-stopped-task-and-not-delivered-to-the-other"
GROUP = "event-propagation"
SERVICES = ["ecs", "events", "sqs"]

_SOURCE = "aws.ecs"
_DETAIL_TYPE = "ECS Task State Change"
_WARMUP_SOURCE = "sim2real.warmup"
_IMAGE = "public.ecr.aws/docker/library/busybox:latest"
_FAIL_CODE = 7
_TASK_STOPPED_S = 420.0
_EVENT_WAIT_S = 180.0
_MIN_SETTLE_S = 30.0


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Of two Fargate tasks exiting 7 and 0, each STOPPED event reaches only the rule matching its
    containers[].exitCode, with exitCode/stopCode/stoppedReason equal to DescribeTasks, and each RUNNING
    event has a lower detail.version and no exitCode.
    """
    ecs = ctx.client("ecs")
    token = ctx.unique_name("w")[-12:]

    net = _network(ctx)
    cluster = _xname(ctx, "cl")[:255]
    cluster_arn = ecs.create_cluster(
        clusterName=cluster, tags=[{"key": k, "value": v} for k, v in _TAGS.items()]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _retry_codes(
        lambda: ecs.delete_cluster(cluster=cluster),
        ("ClusterContainsTasksException", "ClusterContainsServicesException",
         "UpdateInProgressException"),
        ("ClusterNotFoundException",),
    ))

    family = _xname(ctx, "td")[:255]
    td_arn = ecs.register_task_definition(
        family=family, requiresCompatibilities=["FARGATE"], networkMode="awsvpc",
        cpu="256", memory="512",
        containerDefinitions=[{"name": "work", "image": _IMAGE, "essential": True,
                               "command": ["sh", "-c", "sleep 5; exit 0"]}],
        tags=[{"key": k, "value": v} for k, v in _TAGS.items()],
    )["taskDefinition"]["taskDefinitionArn"]

    def _deregister(a=td_arn):
        ecs.deregister_task_definition(taskDefinition=a)
        ecs.delete_task_definitions(taskDefinitions=[a])

    ctx.on_cleanup(_deregister)

    scope = {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE], "detail": {"clusterArn": [cluster_arn]}}
    queues: dict[str, dict] = {}
    for label, extra in (
        ("fail", {"lastStatus": ["STOPPED"], "containers": {"exitCode": [_FAIL_CODE]}}),
        ("ok", {"lastStatus": ["STOPPED"], "containers": {"exitCode": [0]}}),
        ("running", {"lastStatus": ["RUNNING"]}),
    ):
        pattern = json.loads(json.dumps(scope))
        pattern["detail"].update(extra)
        queues[label] = _create_queue(ctx)
        _rule_to_queue(ctx, {"$or": [pattern, {"source": [_WARMUP_SOURCE],
                                                "detail": {"token": [f"{token}-{label}"]}}]},
                       queues[label])
    _warm_up(ctx, {label: q["url"] for label, q in queues.items()}, token)

    tasks: dict[str, str] = {}
    for label, code in (("fail", _FAIL_CODE), ("ok", 0)):
        resp = ecs.run_task(
            cluster=cluster, taskDefinition=td_arn, launchType="FARGATE", count=1,
            networkConfiguration={"awsvpcConfiguration": {
                "subnets": [net["subnet"]], "securityGroups": [net["sg"]], "assignPublicIp": "ENABLED"}},
            overrides={"containerOverrides": [{"name": "work",
                                               "command": ["sh", "-c", f"sleep 5; exit {code}"]}]},
        )
        assert not resp.get("failures") and len(resp.get("tasks", [])) == 1, (
            f"RunTask for the {label} task must place exactly one task, got failures "
            f"{resp.get('failures')!r}"
        )
        arn = resp["tasks"][0]["taskArn"]
        tasks[label] = arn
        ctx.on_cleanup(lambda a=arn: _retry_codes(
            lambda: ecs.stop_task(cluster=cluster, task=a), (), ("ClusterNotFoundException",)))

    t0 = time.monotonic()
    described = {}
    for label, arn in tasks.items():
        described[label] = _poll_until(
            lambda a=arn: ecs.describe_tasks(cluster=cluster, tasks=[a])["tasks"][0],
            lambda t: t["lastStatus"] == "STOPPED",
            timeout_s=_TASK_STOPPED_S, interval_s=5,
            description=f"the {label} task {arn} reaches lastStatus STOPPED",
        )
    run_s = time.monotonic() - t0
    for label, code in (("fail", _FAIL_CODE), ("ok", 0)):
        container = described[label]["containers"][0]
        assert container.get("exitCode") == code, (
            f"DescribeTasks must report the {label} task's real exit code {code}, got "
            f"{container.get('exitCode')!r} (stopCode {described[label].get('stopCode')!r}, reason "
            f"{described[label].get('stoppedReason')!r})"
        )

    sinks: dict[str, list[dict]] = {label: [] for label in queues}

    def _stopped(label: str, task_label: str) -> list[dict]:
        return [b for b in sinks[label] if b["detail"].get("taskArn") == tasks[task_label]]

    def _drain_all():
        for label, q in queues.items():
            _drain_once(ctx, q["url"], sinks[label])
        return sinks

    _poll_until(
        _drain_all,
        lambda _s: (_stopped("fail", "fail") and _stopped("ok", "ok")
                    and _stopped("running", "fail") and _stopped("running", "ok")),
        timeout_s=_EVENT_WAIT_S, interval_s=0.5,
        description="each exit-code rule receives its own task's STOPPED event and the RUNNING "
                    "rule receives both tasks' RUNNING events",
    )
    settle_until = time.monotonic() + max(_MIN_SETTLE_S, 0.5 * run_s)
    while time.monotonic() < settle_until:
        _drain_all()

    assert _stopped("ok", "fail") == [], (
        f"the rule matching containers.exitCode [0] received {len(_stopped('ok', 'fail'))} event(s) "
        f"for the task that exited {_FAIL_CODE}: exit codes "
        f"{[[c.get('exitCode') for c in b['detail'].get('containers', [])] for b in _stopped('ok', 'fail')]!r}"
    )
    assert _stopped("fail", "ok") == [], (
        f"the rule matching containers.exitCode [{_FAIL_CODE}] received an event for the task that "
        f"exited 0"
    )
    for label in ("fail", "ok", "running"):
        foreign = [b["detail"].get("taskArn") for b in sinks[label]
                   if b["detail"].get("taskArn") not in tasks.values()]
        assert foreign == [], f"queue {label!r} received events for tasks this check never ran: {foreign!r}"

    for label, code in (("fail", _FAIL_CODE), ("ok", 0)):
        d = described[label]
        stopped = _stopped(label, label)[-1]
        detail = stopped["detail"]
        assert stopped["resources"] == [tasks[label]], (
            f"{label}: envelope resources must be exactly the task ARN, got {stopped['resources']!r}"
        )
        assert detail["lastStatus"] == "STOPPED", f"{label}: lastStatus {detail['lastStatus']!r}"
        ev_codes = [c.get("exitCode") for c in detail["containers"]]
        assert ev_codes == [c.get("exitCode") for c in d["containers"]] == [code], (
            f"{label}: event containers[].exitCode {ev_codes!r} must equal DescribeTasks "
            f"{[c.get('exitCode') for c in d['containers']]!r} and the real exit status [{code}]"
        )
        assert detail.get("stopCode") == d.get("stopCode") == "EssentialContainerExited", (
            f"{label}: event stopCode {detail.get('stopCode')!r} must equal DescribeTasks "
            f"{d.get('stopCode')!r} (EssentialContainerExited)"
        )
        assert detail.get("stoppedReason") == d.get("stoppedReason"), (
            f"{label}: event stoppedReason {detail.get('stoppedReason')!r} must equal DescribeTasks "
            f"{d.get('stoppedReason')!r}"
        )
        running = _stopped("running", label)
        assert all(b["detail"]["lastStatus"] == "RUNNING" for b in running), (
            f"{label}: the RUNNING rule delivered non-RUNNING events: "
            f"{[b['detail']['lastStatus'] for b in running]!r}"
        )
        run_versions = [b["detail"]["version"] for b in running]
        assert max(run_versions) < detail["version"], (
            f"{label}: every RUNNING event must precede the STOPPED one in the task's version "
            f"sequence; RUNNING versions {run_versions!r}, STOPPED version {detail['version']!r}"
        )
        assert all("exitCode" not in c for b in running for c in b["detail"]["containers"]), (
            f"{label}: a RUNNING event cannot carry an exit code, got "
            f"{[b['detail']['containers'] for b in running]!r}"
        )


_XSVC_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}
_TEARDOWN_S = 240.0


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


_SUCCEEDED = "<call succeeded>"


def _error_code(fn) -> str:
    """The error code `fn` raised, or _SUCCEEDED (a value no AWS error code equals) when it returned."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "<ClientError without a code>"
    return _SUCCEEDED


def _retry_codes(fn, retry, gone) -> None:
    """Run a teardown step: retry a ``retry`` refusal every 2 s to the teardown deadline, accept the
    documented not-found codes in ``gone``, and raise everything else."""
    deadline = time.monotonic() + _TEARDOWN_S
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in gone:
                return
            if code not in retry or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll until predicate holds; RAISE on timeout (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _retry_delete(what: str, fn) -> None:
    """Retry a delete through DependencyViolation (ENIs detaching); raise if it never lands."""
    deadline = time.monotonic() + _TEARDOWN_S
    code = "unattempted"
    while time.monotonic() < deadline:
        code = _error_code(fn)
        if code == _SUCCEEDED or code.endswith("NotFound") or code.endswith(".NotFound"):
            return
        if code != "DependencyViolation":
            break
        time.sleep(2)
    raise RuntimeError(f"could not delete {what}: {code}")


def _ec2_tags(ctx, resource_type: str, kind: str) -> list[dict]:
    tags = [{"Key": "Name", "Value": _xname(ctx, kind)}, {"Key": "sim2real", "Value": CHECK[:200]}]
    tags += [{"Key": k, "Value": v} for k, v in _TAGS.items()]
    return [{"ResourceType": resource_type, "Tags": tags}]


def _network(ctx) -> dict[str, str]:
    """A private VPC with one public subnet in a derived AZ, an IGW route and an egress-only SG.

    Created here rather than borrowed from the account: a fresh account may have no default VPC.
    Every piece is tagged at create time and torn down in reverse order.
    """
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.77.0.0/16",
                         TagSpecifications=_ec2_tags(ctx, "vpc", "vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(f"vpc {vpc}", lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc)))
    ec2.get_waiter("vpc_available").wait(
        VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    igw = ec2.create_internet_gateway(
        TagSpecifications=_ec2_tags(ctx, "internet-gateway", "igw"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(f"igw {igw}", lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        f"igw attachment {igw}", lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw, VpcId=vpc)))

    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert zones, f"region {ctx.region} reports no available availability zone"
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.77.1.0/24", AvailabilityZone=zones[0],
                               TagSpecifications=_ec2_tags(ctx, "subnet", "sn"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(f"subnet {subnet}", lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet)))

    rt = ec2.create_route_table(VpcId=vpc, TagSpecifications=_ec2_tags(ctx, "route-table", "rt"))[
        "RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(f"route table {rt}", lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt)))
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=rt, SubnetId=subnet)["AssociationId"]
    ctx.on_cleanup(lambda: _retry_codes(
        lambda: ec2.disassociate_route_table(AssociationId=assoc), (),
        ("InvalidAssociationID.NotFound",)))

    sg = ec2.create_security_group(
        GroupName=_xname(ctx, "sg")[:255], Description="sim2real-xsvc egress-only task SG", VpcId=vpc,
        TagSpecifications=_ec2_tags(ctx, "security-group", "sg"))["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(f"security group {sg}", lambda: _delete_net(ec2, "delete_security_group", GroupId=sg)))
    return {"vpc": vpc, "subnet": subnet, "sg": sg}


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = _xname(ctx, "q")[:80]
    url = sqs.create_queue(QueueName=name, tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _rule_to_queue(ctx, pattern: dict, queue: dict) -> str:
    """A rule on the DEFAULT bus (where AWS service events land) with this queue as sole target."""
    events = ctx.client("events")
    name = _xname(ctx, "rule")[:64]
    arn = events.put_rule(
        Name=name, EventPattern=json.dumps(pattern),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["RuleArn"]

    def _teardown(n=name):
        _leaks: list = []
        code = _error_code(lambda: events.remove_targets(Rule=n, Ids=["q"], Force=True))
        if code not in (_SUCCEEDED, "ResourceNotFoundException"):
            _leaks.append((f"could not remove target from rule {n}: {code}", None))
        code = _error_code(lambda: events.delete_rule(Name=n, Force=True))
        if code not in (_SUCCEEDED, "ResourceNotFoundException"):
            _leaks.append((f"could not delete rule {n}: {code}", None))
        if _leaks:
            raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
                (e for _, e in _leaks if e is not None), None
            )

    ctx.on_cleanup(_teardown)
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={"Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                           "Action": "sqs:SendMessage", "Resource": queue["arn"],
                           "Condition": {"ArnEquals": {"aws:SourceArn": arn}}}],
        })},
    )
    events.put_targets(Rule=name, Targets=[{"Id": "q", "Arn": queue["arn"]}])
    return arn


def _warm_up(ctx, urls: dict[str, str], token: str) -> None:
    """Prove every rule is live through its own warm-up branch before the workload starts."""
    events = ctx.client("events")
    pending = dict(urls)
    deadline = time.monotonic() + 180
    last_put = 0.0
    while pending and time.monotonic() < deadline:
        if time.monotonic() - last_put > 10:
            resp = events.put_events(Entries=[
                {"Source": _WARMUP_SOURCE, "DetailType": "sim2real warm-up",
                 "Detail": json.dumps({"token": f"{token}-{label}"})} for label in pending])
            assert resp["FailedEntryCount"] == 0, f"warm-up PutEvents was rejected: {resp!r}"
            last_put = time.monotonic()
        for label, url in list(pending.items()):
            sink: list[dict] = []
            _drain_once(ctx, url, sink, keep_warmup=True)
            if any(b.get("detail", {}).get("token") == f"{token}-{label}" for b in sink):
                pending.pop(label)
    assert not pending, f"rules for {sorted(pending)!r} never delivered their warm-up event within 180s"
    for url in urls.values():  # discard duplicate warm-ups so they cannot be read as evidence
        _drain_once(ctx, url, [], keep_warmup=True)


def _drain_once(ctx, url: str, sink: list, keep_warmup: bool = False) -> list:
    """One long-poll receive; matching bodies (the workload's own detail-type) go to sink."""
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        body = json.loads(msg["Body"])
        if keep_warmup and body.get("source") == _WARMUP_SOURCE:
            sink.append(body)
        elif body.get("source") == _SOURCE and body.get("detail-type") == _DETAIL_TYPE:
            sink.append(body)
    return sink


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes asynchronously: its ENIs
# outlive its delete, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry DependencyViolation in the same
# window shared by all of one check's network deletes, then raise naming the ENIs still attached.
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
        _time.sleep(2)
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
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
