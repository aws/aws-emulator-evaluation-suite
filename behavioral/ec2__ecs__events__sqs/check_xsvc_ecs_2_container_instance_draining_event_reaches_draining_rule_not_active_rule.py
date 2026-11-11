"""xsvc-ecs-2-container-instance-draining-event-reaches-draining-rule-not-active-rule."""

from __future__ import annotations

import base64
import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-ecs-2-container-instance-draining-event-reaches-draining-rule-not-active-rule"
GROUP = "event-propagation"
SERVICES = ["ec2", "ecs", "events", "sqs"]

_SOURCE = "aws.ecs"
_DETAIL_TYPE = "ECS Container Instance State Change"
_WARMUP_SOURCE = "sim2real.warmup"
_INSTANCE_TYPE = "t3.micro"
_REGISTER_S = 420.0
_EVENT_WAIT_S = 240.0


@tags(
    "axis:negative-delivery",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """Draining a real agent-registered container instance delivers its state-change event (instance ARN
    in resources) only to the DRAINING + agentConnected true rule, not to the ACTIVE or the DRAINING +
    agentConnected false rule; re-activating it then reaches the ACTIVE rule's queue.
    """
    ecs = ctx.client("ecs")
    token = uuid.uuid4().hex[:12]

    # Decidable preconditions first, before anything bills.
    net = _network(ctx)

    cluster = _xname(ctx, "cl")[:255]
    cluster_arn = ecs.create_cluster(
        clusterName=cluster, tags=[{"key": k, "value": v} for k, v in _TAGS.items()]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _gone(lambda: ecs.delete_cluster(cluster=cluster)))

    scope = {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE], "detail": {"clusterArn": [cluster_arn]}}
    queues: dict[str, dict] = {}
    for label, extra in (
        ("draining", {"status": ["DRAINING"], "agentConnected": [True]}),
        ("active", {"status": ["ACTIVE"], "agentConnected": [True]}),
        ("draining_disconnected", {"status": ["DRAINING"], "agentConnected": [False]}),
    ):
        pattern = json.loads(json.dumps(scope))
        pattern["detail"].update(extra)
        queues[label] = _create_queue(ctx)
        _rule_to_queue(ctx, {"$or": [pattern, {"source": [_WARMUP_SOURCE],
                                                "detail": {"token": [f"{token}-{label}"]}}]},
                       queues[label])
    _warm_up(ctx, {label: q["url"] for label, q in queues.items()}, token)

    ci = _launch_real_container_instance(ctx, net, cluster)
    ci_arn = ci["containerInstanceArn"]
    instance_id = ci["ec2InstanceId"]

    connected = _poll_until(
        lambda: ecs.describe_container_instances(cluster=cluster, containerInstances=[ci_arn])[
            "containerInstances"][0],
        lambda c: c["status"] == "ACTIVE" and c["agentConnected"] is True,
        ctx=ctx, timeout_s=_budget_s(ctx, 120), interval_s=1,
        description=f"container instance {ci_arn} is ACTIVE with its agent connected",
    )
    version_before = connected["version"]

    sinks: dict[str, list[dict]] = {label: [] for label in queues}

    def _drain_all():
        for label, q in queues.items():
            _drain_once(ctx, q["url"], sinks[label])
        return sinks

    def _for_ci(label: str, status: str | None = None) -> list[dict]:
        return [b for b in sinks[label] if b["detail"].get("containerInstanceArn") == ci_arn
                and (status is None or b["detail"].get("status") == status)]

    resp = ecs.update_container_instances_state(
        cluster=cluster, containerInstances=[ci_arn], status="DRAINING")
    assert resp["failures"] == [], f"UpdateContainerInstancesState DRAINING failed: {resp['failures']!r}"
    assert resp["containerInstances"][0]["status"] == "DRAINING", (
        f"the drain call's own response reports {resp['containerInstances'][0]['status']!r}, not DRAINING"
    )

    _poll_until(_drain_all, lambda _s: _for_ci("draining", "DRAINING"),
                ctx=ctx, timeout_s=_budget_s(ctx, _EVENT_WAIT_S), interval_s=0.5,
                description="the DRAINING rule's queue receives the drain event for this instance")

    drained = _for_ci("draining", "DRAINING")[0]
    detail = drained["detail"]
    assert ci_arn in drained["resources"], (
        f"the drain event's resources {drained['resources']!r} must contain the container instance "
        f"ARN {ci_arn!r}"
    )
    assert drained["source"] == _SOURCE and drained["detail-type"] == _DETAIL_TYPE, (
        f"envelope source/detail-type were {drained['source']!r}/{drained['detail-type']!r}"
    )
    assert detail["status"] == "DRAINING" and detail["agentConnected"] is True, (
        f"drain event detail status/agentConnected were {detail['status']!r}/"
        f"{detail['agentConnected']!r}, expected DRAINING/True"
    )
    assert detail["clusterArn"] == cluster_arn, f"detail.clusterArn {detail['clusterArn']!r} != {cluster_arn!r}"
    assert detail["ec2InstanceId"] == instance_id, (
        f"detail.ec2InstanceId {detail.get('ec2InstanceId')!r} != the instance launched {instance_id!r}"
    )
    assert detail["version"] > version_before, (
        f"the drain event's version {detail['version']!r} must exceed the pre-drain version "
        f"{version_before!r}"
    )
    drain_version = detail["version"]

    # Close the loop: the ACTIVE queue is reachable, and only the status filter kept the drain out.
    resp = ecs.update_container_instances_state(
        cluster=cluster, containerInstances=[ci_arn], status="ACTIVE")
    assert resp["failures"] == [], f"UpdateContainerInstancesState ACTIVE failed: {resp['failures']!r}"
    _poll_until(
        _drain_all,
        lambda _s: [b for b in _for_ci("active", "ACTIVE") if b["detail"]["version"] > drain_version],
        ctx=ctx, timeout_s=_budget_s(ctx, _EVENT_WAIT_S), interval_s=0.5,
        description="the ACTIVE rule's queue receives the re-activation event for this instance",
    )
    reactivated = [b for b in _for_ci("active", "ACTIVE") if b["detail"]["version"] > drain_version][0]
    assert ci_arn in reactivated["resources"] and reactivated["detail"]["agentConnected"] is True, (
        f"re-activation event resources/agentConnected were {reactivated['resources']!r}/"
        f"{reactivated['detail'].get('agentConnected')!r}"
    )

    # Near-miss negatives, read once the re-activation event, caused after the drain, has been
    # delivered: the drain event has had at least that long to reach every queue.
    leaked = [b["detail"].get("status") for b in _for_ci("active") if b["detail"].get("status") != "ACTIVE"]
    assert leaked == [], (
        f"the rule filtered on status ACTIVE received event(s) with status {leaked!r} for this instance"
    )
    assert [b for b in _for_ci("active") if b["detail"].get("version") == drain_version] == [], (
        f"the ACTIVE rule received the drain transition (version {drain_version!r})"
    )
    assert _for_ci("draining_disconnected") == [], (
        f"the rule filtered on DRAINING + agentConnected false received "
        f"{[(b['detail'].get('status'), b['detail'].get('agentConnected')) for b in _for_ci('draining_disconnected')]!r}"
        f" for a drain of an instance whose agent is connected"
    )
    wrong = [b["detail"].get("status") for b in _for_ci("draining") if b["detail"].get("status") != "DRAINING"]
    assert wrong == [], f"the DRAINING rule received events with status {wrong!r}"
    for label in queues:
        foreign = [b["detail"].get("containerInstanceArn") for b in sinks[label]
                   if b["detail"].get("containerInstanceArn") != ci_arn]
        assert foreign == [], f"queue {label!r} received events for instances this check never ran: {foreign!r}"


_XSVC_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}
_TEARDOWN_S = 300.0


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


_LANDED = "<call landed>"


def _attempt(fn) -> str:
    """Teardown only: run *fn* and return its ClientError code, or _LANDED when the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return str(exc.response.get("Error", {}).get("Code"))
    return _LANDED


def _gone(fn) -> None:
    """Teardown: run *fn*; success or a not-found code is done, any other error code raises."""
    code = _attempt(fn)
    if code != _LANDED and not code.endswith(("NotFound", "NotFoundException", "NoSuchEntity")):
        raise RuntimeError(f"teardown call failed with {code}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, ctx=None):
    """Poll until predicate holds; RAISE on timeout (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _retry_delete(what: str, fn) -> None:
    """Retry a delete through DependencyViolation (ENIs detaching); raise if it never lands."""
    deadline = time.monotonic() + _TEARDOWN_S
    code = "unattempted"
    while time.monotonic() < deadline:
        code = _attempt(fn)
        if code == _LANDED or code.endswith("NotFound"):
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
    """A private VPC with one public subnet in an AZ that offers the instance type, an IGW route
    and an egress-only SG. Created here: a fresh account may have no default VPC."""
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ in {ctx.region} offers {_INSTANCE_TYPE!r}; offerings {sorted(offered)!r}"

    vpc = ec2.create_vpc(CidrBlock="10.78.0.0/16",
                         TagSpecifications=_ec2_tags(ctx, "vpc", "vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(f"vpc {vpc}", lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    igw = ec2.create_internet_gateway(
        TagSpecifications=_ec2_tags(ctx, "internet-gateway", "igw"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(f"igw {igw}", lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        f"igw attachment {igw}", lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw, VpcId=vpc)))

    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.78.1.0/24", AvailabilityZone=usable[0],
                               TagSpecifications=_ec2_tags(ctx, "subnet", "sn"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(f"subnet {subnet}", lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet)))

    rt = ec2.create_route_table(VpcId=vpc, TagSpecifications=_ec2_tags(ctx, "route-table", "rt"))[
        "RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(f"route table {rt}", lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt)))
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=rt, SubnetId=subnet)["AssociationId"]
    ctx.on_cleanup(lambda: _gone(lambda: ec2.disassociate_route_table(AssociationId=assoc)))

    sg = ec2.create_security_group(
        GroupName=_xname(ctx, "sg")[:255], Description="sim2real-xsvc egress-only ECS instance SG",
        VpcId=vpc, TagSpecifications=_ec2_tags(ctx, "security-group", "sg"))["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(f"security group {sg}", lambda: _delete_net(ec2, "delete_security_group", GroupId=sg)))
    return {"vpc": vpc, "subnet": subnet, "sg": sg}


def _launch_real_container_instance(ctx, net: dict, cluster: str) -> dict:
    """Launch a real EC2 instance running the ECS-optimized AMI's agent, pointed at `cluster`, and
    wait until the agent has registered it. Every create is paired with its cleanup."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id")["Parameter"]["Value"]

    role = _xname(ctx, "ci-role")[:64]
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])
    ctx.on_cleanup(lambda: _gone(lambda: iam.delete_role(RoleName=role)))
    policy = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
    iam.attach_role_policy(RoleName=role, PolicyArn=policy)
    ctx.on_cleanup(lambda: _gone(lambda: iam.detach_role_policy(RoleName=role, PolicyArn=policy)))
    iam.create_instance_profile(InstanceProfileName=role)
    ctx.on_cleanup(lambda: _gone(lambda: iam.delete_instance_profile(InstanceProfileName=role)))
    iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
    ctx.on_cleanup(lambda: _gone(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role, RoleName=role)))
    profile_arn = iam.get_instance_profile(InstanceProfileName=role)["InstanceProfile"]["Arn"]

    user_data = base64.b64encode(
        f"#!/bin/bash\necho ECS_CLUSTER={cluster} >> /etc/ecs/ecs.config\n".encode()).decode()
    instance_id = None
    last = None
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while instance_id is None and time.monotonic() < deadline:
        try:
            instance_id = ec2.run_instances(
                ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
                IamInstanceProfile={"Arn": profile_arn}, UserData=user_data,
                NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": net["subnet"], "Groups": [net["sg"]],
                                    "AssociatePublicIpAddress": True}],
                TagSpecifications=_ec2_tags(ctx, "instance", "ci") + _ec2_tags(ctx, "volume", "vol"),
            )["Instances"][0]["InstanceId"]
        except ClientError as exc:
            # A just-created instance profile is not yet visible to EC2: IAM propagation, which
            # exposes no condition to poll. Retry that one code only.
            if exc.response["Error"]["Code"] != "InvalidParameterValue":
                raise
            last = exc
            time.sleep(2)
    if not instance_id and _budget_spent(ctx):
        raise TimeoutError("RunInstances accepting the new instance profile: the run budget ended first; "
                           "not graded")
    assert instance_id, f"RunInstances never accepted the new instance profile: {last!r}"

    def _terminate():
        _attempt(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
        try:
            ec2.get_waiter("instance_terminated").wait(
                InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150})
        except Exception as exc:  # noqa: BLE001 - re-raised
            raise RuntimeError(
                f"instance {instance_id} did not reach terminated: {exc}"
            ) from exc

    ctx.on_cleanup(_terminate)

    def _find():
        arns = ecs.list_container_instances(cluster=cluster).get("containerInstanceArns", [])
        if not arns:
            return None
        for c in ecs.describe_container_instances(cluster=cluster, containerInstances=arns)["containerInstances"]:
            if c.get("ec2InstanceId") == instance_id:
                return c
        return None

    ci = _poll_until(_find, lambda c: c is not None, ctx=ctx, timeout_s=_budget_s(ctx, _REGISTER_S), interval_s=2,
                     description=f"EC2 instance {instance_id} registers as a container instance")
    ci_arn = ci["containerInstanceArn"]
    ctx.on_cleanup(lambda: _gone(lambda: ecs.deregister_container_instance(
        cluster=cluster, containerInstance=ci_arn, force=True)))
    return ci


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
        code = _attempt(lambda: events.remove_targets(Rule=n, Ids=["q"], Force=True))
        if code not in (_LANDED, "ResourceNotFoundException"):
            _leaks.append((f"could not remove target from rule {n}: {code}", None))
        code = _attempt(lambda: events.delete_rule(Name=n, Force=True))
        if code not in (_LANDED, "ResourceNotFoundException"):
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
    deadline = time.monotonic() + _budget_s(ctx, 180)
    last_put = 0.0
    while pending and time.monotonic() < deadline:
        if time.monotonic() - last_put > 5:
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
    if pending and _budget_spent(ctx):
        raise TimeoutError(f"rules for {sorted(pending)!r} delivering their warm-up event: the run budget "
                           "ended first; not graded")
    assert not pending, f"rules for {sorted(pending)!r} never delivered their warm-up event in time"
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


# Network deletes wait (bounded) for AWS-managed ENIs to leave: a load balancer, endpoint, cluster
# or instance deletes asynchronously, so an immediate DeleteSubnet/DeleteSecurityGroup/DeleteVpc
# fails with DependencyViolation. Retry inside the window, then raise naming the attached ENIs.
_NET_TEARDOWN_S = 420.0
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
