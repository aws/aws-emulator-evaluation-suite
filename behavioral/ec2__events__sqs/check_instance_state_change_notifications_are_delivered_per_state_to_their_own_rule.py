"""instance-state-change-notifications-are-delivered-per-state-to-their-own-rule."""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-state-change-notifications-are-delivered-per-state-to-their-own-rule"
GROUP = "event-propagation"
SERVICES = ["ec2", "events", "sqs"]

_VPC_CIDR = "10.82.0.0/16"
_SUBNET_CIDR = "10.82.1.0/24"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SOURCE = "aws.ec2"
_DETAIL_TYPE = "EC2 Instance State-change Notification"
_MODELLED_STATES = {"pending", "running", "stopping", "stopped", "shutting-down", "terminated"}
_NARROW_STATE = "shutting-down"
_DRAIN_TIMEOUT_S = 420.0
_WIRING_SETTLE_S = 60.0
_QUIET_RECEIVES = 3
_CLOCK_SLACK_S = 300
_GONE_CODES = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
               "InvalidInstanceID.NotFound", "ResourceNotFoundException",
               "AWS.SimpleQueueService.NonExistentQueue")
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:eventing", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Each EC2 instance state change reaches a broad rule's SQS queue as an EC2 Instance State-change
    Notification, while a rule pinned to one state stays empty (no messages, depth 0) until the
    terminate, when it receives exactly one message."""
    ec2 = ctx.client("ec2")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    st: dict = {"instances": [], "sgs": [], "subnets": [], "queues": [], "rules": []}
    try:
        _build(ctx, ec2, events, sqs, st)
        _legs(ctx, ec2, sqs, st)
    finally:
        _teardown(ec2, events, sqs, st)


# ===== the legs ==============================================================


def _legs(ctx, ec2, sqs, st) -> None:
    instance_id = st["instance"]
    broad, narrow = st["broad_queue"], st["narrow_queue"]
    started_at = datetime.now(timezone.utc)

    # --- leg 1: the stop. The broad rule must deliver both states of the transition. ---
    ec2.stop_instances(InstanceIds=[instance_id])
    _poll(lambda: _state(ec2, instance_id), lambda s: s == "stopped",
          timeout_s=900.0, interval_s=10.0,
          what=f"{STATE_MARKER}: instance {instance_id} reaching 'stopped'")
    stop_events = _collect(sqs, broad, want={"stopping", "stopped"},
                           instance_id=instance_id, what="the stop transition")
    _assert_envelopes(ctx, st, stop_events, started_at)

    # --- leg 2: absence, bounded by leg 1's demonstrated delivery on the same wiring ---
    _assert_empty(sqs, narrow, why=(
        f"the narrow rule pins detail.state to {_NARROW_STATE!r} and the instance has only been "
        f"stopped, so it must be empty — and it is asserted empty at a moment when the broad rule "
        f"on the identical wiring has just delivered "
        f"{sorted(e['detail']['state'] for e in stop_events)!r}"))

    # --- leg 3: the start. Same wiring, two more states, narrow rule still withheld. ---
    ec2.start_instances(InstanceIds=[instance_id])
    _poll(lambda: _state(ec2, instance_id), lambda s: s == "running",
          timeout_s=900.0, interval_s=10.0,
          what=f"{STATE_MARKER}: instance {instance_id} reaching 'running' again")
    start_events = _collect(sqs, broad, want={"pending", "running"},
                            instance_id=instance_id, what="the start transition")
    _assert_envelopes(ctx, st, start_events, started_at)
    _assert_empty(sqs, narrow, why=(
        f"the narrow rule must still be empty after a start, having just been proven reachable by "
        f"the broad rule delivering {sorted(e['detail']['state'] for e in start_events)!r}"))

    # --- leg 4: repair the withheld delivery. The narrow rule must now produce exactly one. ---
    ec2.terminate_instances(InstanceIds=[instance_id])
    _poll(lambda: _state(ec2, instance_id), lambda s: s in ("terminated", "__gone__"),
          timeout_s=900.0, interval_s=10.0,
          what=f"{STATE_MARKER}: instance {instance_id} reaching 'terminated'")
    narrow_events = _collect(sqs, narrow, want={_NARROW_STATE},
                             instance_id=instance_id, what="the terminate transition")
    _assert_envelopes(ctx, st, narrow_events, started_at)
    delivered_states = {e["detail"]["state"] for e in narrow_events}
    assert delivered_states == {_NARROW_STATE}, (
        f"a rule pinning detail.state to {_NARROW_STATE!r} must deliver only that state; it "
        f"delivered {sorted(delivered_states)!r}"
    )
    terminate_events = _collect(sqs, broad, want={"shutting-down", "terminated"},
                                instance_id=instance_id, what="the terminate transition")
    _assert_envelopes(ctx, st, terminate_events, started_at)

    # --- the whole lifecycle, as observed at the consumer ---
    all_states = {e["detail"]["state"] for e in stop_events + start_events + terminate_events}
    assert all_states == {"stopping", "stopped", "pending", "running", "shutting-down",
                          "terminated"}, (
        f"the broad rule must have delivered one event per transition this check drove; the states "
        f"received were {sorted(all_states)!r}"
    )


def _assert_envelopes(ctx, st, envelopes, started_at) -> None:
    """Every field of the documented envelope, on every message received."""
    assert envelopes, "refusing to assert over an empty envelope list: it would assert nothing"
    horizon = datetime.now(timezone.utc) + timedelta(seconds=_CLOCK_SLACK_S)
    floor = started_at - timedelta(seconds=_CLOCK_SLACK_S)
    for envelope in envelopes:
        assert envelope["source"] == _SOURCE, (
            f"expected source {_SOURCE!r}, got {envelope['source']!r} in {envelope!r}"
        )
        assert envelope["detail-type"] == _DETAIL_TYPE, (
            f"expected detail-type {_DETAIL_TYPE!r}, got {envelope['detail-type']!r}"
        )
        assert envelope["account"] == st["account"], (
            f"expected the event to carry this account {st['account']!r}, got "
            f"{envelope['account']!r}"
        )
        assert envelope["region"] == ctx.region, (
            f"expected the event to carry region {ctx.region!r}, got {envelope['region']!r}"
        )
        assert envelope["resources"] == [st["instance_arn"]], (
            f"expected resources to be exactly [{st['instance_arn']!r}], got "
            f"{envelope['resources']!r}"
        )
        assert envelope["detail"]["instance-id"] == st["instance"], (
            f"expected detail.instance-id {st['instance']!r}, got "
            f"{envelope['detail']['instance-id']!r}"
        )
        assert envelope["detail"]["state"] in _MODELLED_STATES, (
            f"detail.state must be one of the six modelled values {sorted(_MODELLED_STATES)!r}, got "
            f"{envelope['detail']['state']!r}"
        )
        # the live clock: no recording can carry a timestamp inside THIS run's window
        stamped = _parse_time(envelope["time"])
        assert floor <= stamped <= horizon, (
            f"the event's own time {envelope['time']!r} must fall inside this run's window "
            f"[{floor.isoformat()}, {horizon.isoformat()}]; a fabricated or replayed timestamp does "
            f"not. Envelope: {envelope!r}"
        )


def _parse_time(raw):
    """EventBridge stamps ISO-8601 UTC with a trailing Z, which fromisoformat rejects on older
    interpreters, so the Z is normalised rather than trusted."""
    text = raw.replace("Z", "+00:00")
    stamped = datetime.fromisoformat(text)
    assert stamped.tzinfo is not None, f"the event time must carry a timezone, got {raw!r}"
    return stamped


def _collect(sqs, url, *, want, instance_id, what):
    """Drain `url` until every state in `want` has been seen for `instance_id`, or raise.

    Messages for OTHER instances are deleted and ignored, so a concurrent run in the same account
    cannot make this check pass or fail. Raises rather than returning a partial set, because a
    partial set is exactly the failure this leg exists to detect.
    """
    deadline = time.monotonic() + _DRAIN_TIMEOUT_S
    collected: list[dict] = []
    seen: set[str] = set()
    other = 0
    while time.monotonic() < deadline and not want <= seen:
        for message in _receive(sqs, url):
            envelope = json.loads(message["Body"])
            if envelope.get("detail", {}).get("instance-id") != instance_id:
                other += 1
                continue
            collected.append(envelope)
            seen.add(envelope["detail"]["state"])
    assert want <= seen, (
        f"{what}: the states {sorted(want)!r} must all be delivered to {url!r} within "
        f"{_DRAIN_TIMEOUT_S}s; only {sorted(seen)!r} arrived ({other} messages for other instances "
        f"were skipped). A target that never publishes state-change events fails exactly here"
    )
    return collected


def _receive(sqs, url, wait=10):
    """One long-poll receive, deleting whatever it takes so the queue drains monotonically."""
    messages = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait).get("Messages", [])
    if messages:
        sqs.delete_message_batch(QueueUrl=url, Entries=[
            {"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]}
            for i, m in enumerate(messages)])
    return messages


def _assert_empty(sqs, url, *, why):
    """Absence on TWO independent observables: consecutive empty long polls AND the queue's own
    depth attribute. Neither is a sleep; both are reads."""
    for attempt in range(_QUIET_RECEIVES):
        messages = _receive(sqs, url, wait=10)
        assert not messages, (
            f"{why}. Receive {attempt + 1} of {_QUIET_RECEIVES} returned "
            f"{[json.loads(m['Body']).get('detail') for m in messages]!r}"
        )
    attributes = sqs.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    assert attributes["ApproximateNumberOfMessages"] == "0", (
        f"{why}. The queue's own depth attribute reports "
        f"{attributes['ApproximateNumberOfMessages']!r} messages"
    )
    assert attributes["ApproximateNumberOfMessagesNotVisible"] == "0", (
        f"{why}. The queue reports {attributes['ApproximateNumberOfMessagesNotVisible']!r} in-flight "
        f"messages, so something WAS delivered and is merely hidden"
    )


# ===== the fixture ===========================================================


def _build(ctx, ec2, events, sqs, st) -> None:
    name = ctx.unique_name("sim2real-b1ecev-")
    st["name"] = name
    st["account"] = ctx.client("sts").get_caller_identity()["Account"]

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    az = sorted(_zones_offering(ec2, _INSTANCE_TYPE))[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    sg_id = ec2.create_security_group(
        GroupName=name + "-sg", VpcId=vpc_id,
        Description="sim2real EC2 state-change eventing check",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(name)}],
    )["GroupId"]
    st["sgs"].append(sg_id)

    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    instance_id = ec2.run_instances(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        SubnetId=subnet_id, SecurityGroupIds=[sg_id],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": _tags_for(name)},
            {"ResourceType": "volume", "Tags": _tags_for(name)},
        ],
    )["Instances"][0]["InstanceId"]
    st["instances"].append(instance_id)
    st["instance"] = instance_id
    st["instance_arn"] = f"arn:aws:ec2:{ctx.region}:{st['account']}:instance/{instance_id}"
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))
    # Wait for 'running' BEFORE the rules exist, deliberately: the launch's own pending/running
    # events are therefore out of scope, and every event this check asserts is one it caused.
    _poll(lambda: _state(ec2, instance_id), lambda s: s == "running",
          timeout_s=900.0, interval_s=10.0,
          what=f"{STATE_MARKER}: instance {instance_id} reaching 'running'")

    st["broad_queue"] = _wire(
        ctx, events, sqs, st, suffix="broad",
        pattern={"source": [_SOURCE], "detail-type": [_DETAIL_TYPE],
                 "detail": {"instance-id": [instance_id]}})
    st["narrow_queue"] = _wire(
        ctx, events, sqs, st, suffix="narrow",
        pattern={"source": [_SOURCE], "detail-type": [_DETAIL_TYPE],
                 "detail": {"instance-id": [instance_id], "state": [_NARROW_STATE]}})
    # New rules, targets and queue policies take effect after a delay: SQS documents up to 60 s
    # for a queue attribute change to propagate, so the first state change waits that long.
    time.sleep(_WIRING_SETTLE_S)


def _wire(ctx, events, sqs, st, *, suffix, pattern):
    """One SQS queue, its resource policy, one default-bus rule and its target. Returns the URL."""
    region, account = ctx.region, st["account"]
    queue_name = f"{st['name']}-{suffix}"[:75]
    url = sqs.create_queue(
        QueueName=queue_name,
        Attributes={"ReceiveMessageWaitTimeSeconds": "10", "VisibilityTimeout": "30"},
        tags={"sim2real": "1", "Name": queue_name},
    )["QueueUrl"]
    st["queues"].append(url)
    ctx.on_cleanup(lambda: _unless_gone(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    rule_name = f"{st['name']}-{suffix}"[:64]
    events.put_rule(
        Name=rule_name, State="ENABLED", EventPattern=json.dumps(pattern),
        Description="sim2real EC2 instance state-change notification check",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    st["rules"].append(rule_name)
    ctx.on_cleanup(lambda: _unless_gone(lambda: events.delete_rule(Name=rule_name, Force=True)))
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowEventBridge", "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnEquals": {
                "aws:SourceArn": f"arn:aws:events:{region}:{account}:rule/{rule_name}"}},
        }],
    })})
    failed = events.put_targets(Rule=rule_name, Targets=[{"Id": "q", "Arn": arn}])
    assert failed["FailedEntryCount"] == 0, (
        f"PutTargets must attach {arn} to {rule_name}: {failed!r}"
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: events.remove_targets(Rule=rule_name, Ids=["q"], Force=True)))

    # Read the wiring back through a different operation than the one that made it.
    described = events.describe_rule(Name=rule_name)
    assert described["State"] == "ENABLED", (
        f"rule {rule_name} must be ENABLED, got {described!r}"
    )
    assert json.loads(described["EventPattern"]) == pattern, (
        f"rule {rule_name} must carry the pattern this check wrote; DescribeRule returned "
        f"{described['EventPattern']!r}"
    )
    targets = events.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert [t["Arn"] for t in targets] == [arn], (
        f"rule {rule_name} must have exactly one target, the queue {arn}; it has {targets!r}"
    )
    return url


# ===== in-band teardown ======================================================


def _teardown(ec2, events, sqs, st) -> None:
    """Delete everything the check created; raise naming whatever is left (and any in-flight error)."""
    steps = []
    for rule in st.get("rules", []):
        steps.append((f"targets {rule}",
                      lambda r=rule: events.remove_targets(Rule=r, Ids=["q"], Force=True)))
        steps.append((f"rule {rule}", lambda r=rule: events.delete_rule(Name=r, Force=True)))
    for url in st.get("queues", []):
        steps.append((f"queue {url}", lambda u=url: sqs.delete_queue(QueueUrl=u)))
    for iid in st.get("instances", []):
        steps.append((f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i])))
    for iid in st.get("instances", []):
        steps.append((f"instance-wait {iid}", lambda i=iid: _poll(
            lambda: _state(ec2, i), lambda s: s in ("terminated", "__gone__"),
            timeout_s=900.0, interval_s=2.0, what=f"instance {i} reaching 'terminated'")))
    if st.get("vpc"):
        steps.append(("eni-drain", lambda: _poll(
            lambda: _vpc_enis(ec2, st["vpc"]), lambda enis: enis == [],
            timeout_s=420.0, interval_s=2.0, what=f"every ENI in {st['vpc']!r} draining")))
    for sg in st.get("sgs", []):
        steps.append((f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s))))
    for subnet in st.get("subnets", []):
        steps.append((f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s))))
    if st.get("vpc"):
        steps.append(("vpc", lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=st["vpc"]))))
        steps.append(("vpc-gone", lambda: _assert_vpc_gone(ec2, st["vpc"])))
    left: list[str] = []
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            if _code(exc) not in _GONE_CODES:
                left.append(f"{label}: {_code(exc)}")
        except Exception as exc:  # noqa: BLE001 — collected, raised below
            left.append(f"{label}: {exc!r}")
    if left:
        found = sys.exc_info()[1]
        prefix = f"{found!r}; " if found is not None else ""
        raise AssertionError(f"{prefix}teardown could not remove everything the check created: {left!r}")


def _assert_vpc_gone(ec2, vpc_id) -> None:
    """A deleted VPC answers InvalidVpcID.NotFound; anything else means it is still there."""
    try:
        still = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    except ClientError as exc:
        if _code(exc) != "InvalidVpcID.NotFound":
            raise
        return
    raise AssertionError(f"vpc {vpc_id} is still describable: {still!r}")


def _unless_gone(fn) -> None:
    """A registered cleanup: the in-band teardown in run() deletes the same resources first, so a
    not-found answer here is done; any other failure raises."""
    try:
        fn()
    except ClientError as exc:
        if _code(exc) not in _GONE_CODES:
            raise


def _tags_for(name):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "Name", "Value": name}]


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _poll(probe, predicate, *, timeout_s, interval_s, what):
    """Bounded retry that RAISES on timeout — never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} was not observed within {timeout_s}s; last saw {last!r}")


def _retry_dependency(fn, timeout_s=240.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) in _GONE_CODES:
                return
            if _code(exc) not in ("DependencyViolation", "InvalidParameterDependency",
                                  "RequestLimitExceeded") or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _describe(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    if not resv or not resv[0].get("Instances"):
        return None
    return resv[0]["Instances"][0]


def _state(ec2, instance_id):
    inst = _describe(ec2, instance_id)
    return "__gone__" if inst is None else inst["State"]["Name"]


def _vpc_enis(ec2, vpc_id):
    return [
        eni["NetworkInterfaceId"]
        for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for eni in page["NetworkInterfaces"]
    ]


def _zones_offering(ec2, instance_type):
    offered = {
        o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    usable = {
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered
    }
    assert usable, f"no available zone in this region offers {instance_type!r}"
    return usable


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
