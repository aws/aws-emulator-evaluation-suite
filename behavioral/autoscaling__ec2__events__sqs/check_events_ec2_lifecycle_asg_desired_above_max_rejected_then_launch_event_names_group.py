"""events-ec2-lifecycle-asg-desired-above-max-rejected-then-launch-event-names-group."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-ec2-lifecycle-asg-desired-above-max-rejected-then-launch-event-names-group"
GROUP = "event-propagation"
SERVICES = ["autoscaling", "ec2", "events", "sqs"]

_SOURCE = "aws.autoscaling"
_DETAIL_TYPE = "EC2 Instance Launch Successful"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_VPC_CIDR = "10.89.0.0/16"
_SUBNET_CIDR = "10.89.1.0/24"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:eventing", "concern:negative-classes",
      "concern:data-plane", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """SetDesiredCapacity above MaxSize is refused with ValidationError and changes nothing; within
    MaxSize it launches one instance whose service-emitted `EC2 Instance Launch Successful` event
    names the group, the instance, the subnet and a DescribeScalingActivities activity."""
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-evlc-asg-")
    started_at = datetime.now(timezone.utc)

    subnet, _az = _network(ctx, ec2, name)
    ami = _ami(ctx)
    ctx.on_cleanup(lambda: _terminate_group_instances(ec2, name))
    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami, "InstanceType": _INSTANCE_TYPE,
            "TagSpecifications": [
                {"ResourceType": "instance",
                 "Tags": _tags_for(name) + [{"Key": "sim2real-asg", "Value": name}]},
                {"ResourceType": "volume", "Tags": _tags_for(name)}]},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_for(name)}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt))

    queue = _wire(ctx, events, sqs, account, name + "-launch", {
        "source": [_SOURCE], "detail-type": [_DETAIL_TYPE],
        "detail": {"AutoScalingGroupName": [name]}})
    _prove_pipeline(ctx, events, sqs, account, name)  # PutEvents control on a separate rule

    asg.create_auto_scaling_group(
        AutoScalingGroupName=name, MinSize=0, MaxSize=1, DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateId": lt, "Version": "$Latest"},
        VPCZoneIdentifier=subnet,
        Tags=[{"Key": "sim2real", "Value": "1", "PropagateAtLaunch": True}])
    ctx.on_cleanup(lambda: _delete_group(asg, name))
    group = _group(asg, name)
    assert group is not None and group["MaxSize"] == 1, f"the group must exist with MaxSize 1: {group!r}"
    group_arn = group["AutoScalingGroupARN"]

    code, message = _error(lambda: asg.set_desired_capacity(AutoScalingGroupName=name,
                                                            DesiredCapacity=2),
                           what="SetDesiredCapacity(2) on a MaxSize=1 group")
    assert code == "ValidationError", (
        f"a desired capacity above MaxSize must be refused with ValidationError, got {code!r}"
    )
    expected = "New SetDesiredCapacity value 2 is above max value 1 for the AutoScalingGroup."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    group = _group(asg, name)
    assert (group["DesiredCapacity"], group["Instances"]) == (0, []), (
        f"the refused request must leave the group at desired 0 with no instances: "
        f"{(group['DesiredCapacity'], group['Instances'])!r}"
    )

    # The in-bounds launch's event is the barrier: only after it arrives is it asserted that exactly
    # one instance was ever launched, so the refused request contributed nothing.
    asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1)
    got: list = []
    _collect(sqs, queue, got, bool, what=f"an '{_DETAIL_TYPE}' event for group {name}",
             timeout_s=_budget_s(ctx, _DRAIN_TIMEOUT_S), ctx=ctx)
    for _ in range(3):
        got.extend(_drain(sqs, queue, wait=2))

    launched = {e["detail"].get("EC2InstanceId") for e in got}
    members = _poll(lambda: [i["InstanceId"] for i in _group(asg, name)["Instances"]],
                    lambda ids: len(ids) >= 1, timeout_s=300.0, interval_s=5.0,
                    what=f"group {name} listing its launched instance")
    assert len(launched) == 1 and launched == set(members), (
        f"exactly one instance may ever have launched for {name} (the over-max request was "
        f"refused); launch events named {sorted(launched, key=str)!r}, the group lists "
        f"{members!r}"
    )
    iid = members[0]
    activities = {a["ActivityId"]: a for page in asg.get_paginator(
        "describe_scaling_activities").paginate(AutoScalingGroupName=name)
        for a in page["Activities"]}

    for env in got:
        d = env["detail"]
        assert d.get("AutoScalingGroupName") == name, (
            f"the launch event must name the group {name!r}: {d!r}"
        )
        assert d.get("EC2InstanceId") == iid, f"the launch event must name {iid!r}: {d!r}"
        assert d.get("ActivityId") in activities, (
            f"the event's ActivityId {d.get('ActivityId')!r} must be one of the group's scaling "
            f"activities {sorted(activities)!r}"
        )
        assert iid in activities[d["ActivityId"]]["Description"], (
            f"activity {d['ActivityId']} must describe launching {iid}: "
            f"{activities[d['ActivityId']]['Description']!r}"
        )
        assert d.get("Details", {}).get("Subnet ID") == subnet, (
            f"the launch event must name the subnet {subnet!r}: {d.get('Details')!r}"
        )
        want = {group_arn, f"arn:aws:ec2:{ctx.region}:{account}:instance/{iid}"}
        assert set(env.get("resources", [])) == want and len(env["resources"]) == 2, (
            f"resources must be exactly the group ARN and the instance ARN {sorted(want)!r}, got "
            f"{env.get('resources')!r}"
        )
        _assert_envelope(ctx, account, env, source=_SOURCE, detail_type=_DETAIL_TYPE,
                         resources=env["resources"], started_at=started_at)
    _assert_distinct_ids(got)


def _group(asg, name):
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    return groups[0] if groups else None


def _delete_group(asg, name):
    try:
        asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    except ClientError as exc:
        if "not found" not in str(exc).lower():
            raise
    _poll(lambda: _group(asg, name), lambda g: g is None, timeout_s=900.0, interval_s=10.0,
          what=f"Auto Scaling group {name} disappearing after ForceDelete")


def _terminate_group_instances(ec2, name):
    """Safety net behind the group delete: any instance this group launched, found by the tag the
    launch template stamped at launch, is terminated and waited for."""
    ids = [i["InstanceId"] for page in ec2.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "tag:sim2real-asg", "Values": [name]},
                 {"Name": "instance-state-name",
                  "Values": ["pending", "running", "stopping", "stopped", "shutting-down"]}])
        for r in page["Reservations"] for i in r["Instances"]]
    if ids:
        ec2.terminate_instances(InstanceIds=ids)
    for iid in ids:
        _poll(lambda i=iid: _state(ec2, i), lambda s: s in ("terminated", "__gone__"),
              timeout_s=600.0, interval_s=10.0, what=f"instance {iid} terminating")


def _error(fn, *, what):
    """The exact error (code, message) of a call that must be refused; an accepted call raises."""
    try:
        fn()
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"{what} was ACCEPTED; real AWS refuses it")


_DRAIN_TIMEOUT_S = 600.0
_CLOCK_SLACK_S = 300
_ISO_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_GONE = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidInstanceID.NotFound")


def _tags_for(name):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "Name", "Value": name}]


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _poll(probe, predicate, *, timeout_s, interval_s, what):
    """Bounded poll that RAISES on timeout — never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} was not observed within {timeout_s}s; last saw {last!r}")


def _retry_dependency(fn, attempts=30, delay=10.0):
    for attempt in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) in _GONE:
                return
            if _code(exc) != "DependencyViolation" or attempt == attempts - 1:
                raise
            time.sleep(delay)


def _zones_offering(ec2, instance_type):
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r}"
    return usable


def _network(ctx, ec2, name):
    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags_for(name)}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc)))
    az = _zones_offering(ec2, _INSTANCE_TYPE)[0]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
                               TagSpecifications=[{"ResourceType": "subnet",
                                                   "Tags": _tags_for(name)}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet)))
    return subnet, az


def _ami(ctx):
    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    return ami


def _launch(ctx, ec2, ami, subnet, name, protected=False):
    iid = ec2.run_instances(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
        DisableApiTermination=protected,
        TagSpecifications=[{"ResourceType": "instance", "Tags": _tags_for(name)},
                           {"ResourceType": "volume", "Tags": _tags_for(name)}],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, iid))
    return iid


def _terminate_and_wait(ec2, iid):
    try:
        ec2.modify_instance_attribute(InstanceId=iid, DisableApiTermination={"Value": False})
        ec2.terminate_instances(InstanceIds=[iid])
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    _poll(lambda: _state(ec2, iid), lambda s: s in ("terminated", "__gone__"), timeout_s=600.0,
          interval_s=10.0, what=f"instance {iid} reaching 'terminated' during cleanup")


def _state(ec2, iid):
    try:
        resv = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _wire(ctx, events, sqs, account, name, pattern):
    """One SQS queue, a default-bus rule, and the rule->queue target. Returns the queue URL."""
    url = sqs.create_queue(QueueName=name[:80],
                           Attributes={"ReceiveMessageWaitTimeSeconds": "10"},
                           tags={"sim2real": "1"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    rule = name[:64]
    rule_arn = events.put_rule(Name=rule, EventPattern=json.dumps(pattern), State="ENABLED",
                               Description="sim2real events-ec2-lifecycle check",
                               Tags=[{"Key": "sim2real", "Value": "1"}])["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, Force=True))
    assert rule_arn == f"arn:aws:events:{ctx.region}:{account}:rule/{rule}", (
        f"PutRule returned rule ARN {rule_arn!r}"
    )
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": queue_arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})
    resp = events.put_targets(Rule=rule, Targets=[{"Id": "q", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, Ids=["q"], Force=True))
    assert resp["FailedEntryCount"] == 0, f"PutTargets failed for {rule}: {resp!r}"
    return url


def _drain(sqs, url, wait=10):
    msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                               WaitTimeSeconds=wait).get("Messages", [])
    if msgs:
        sqs.delete_message_batch(QueueUrl=url, Entries=[
            {"Id": str(i), "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)])
    return [json.loads(m["Body"]) for m in msgs]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _collect(sqs, url, into, done, *, what, timeout_s=_DRAIN_TIMEOUT_S, ctx=None):
    deadline = time.monotonic() + timeout_s
    while not done(into) and time.monotonic() < deadline:
        into.extend(_drain(sqs, url, wait=2))
    if not done(into) and ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
    assert done(into), (
        f"{what}: not delivered within {timeout_s:.0f}s. Received "
        f"{[(e.get('detail-type'), e.get('time'), e.get('detail')) for e in into]!r}. A target "
        f"that never emits its own events fails exactly here"
    )


def _prove_pipeline(ctx, events, sqs, account, name):
    """Positive control on a SEPARATE rule: EventBridge -> SQS delivers in this account right now.
    PutEvents is used ONLY here — never for the event under test."""
    source = "sim2real.control"
    nonce = ctx.unique_name("nonce-")
    url = _wire(ctx, events, sqs, account, name + "-ctl",
                {"source": [source], "detail": {"nonce": [nonce]}})

    def attempt():
        resp = events.put_events(Entries=[{"Source": source, "DetailType": "sim2real control",
                                           "Detail": json.dumps({"nonce": nonce})}])
        assert resp["FailedEntryCount"] == 0, f"control PutEvents failed: {resp!r}"
        return [e for e in _drain(sqs, url) if e.get("detail", {}).get("nonce") == nonce]

    got = _poll(attempt, bool, timeout_s=240.0, interval_s=2.0,
                what="the PutEvents positive control reaching its own queue")
    assert got[0]["source"] == source and got[0]["account"] == account, (
        f"control event arrived with the wrong envelope: {got[0]!r}"
    )


def _stamp(env):
    raw = env.get("time")
    assert isinstance(raw, str) and _ISO_SECONDS.match(raw), (
        f"event time must be an ISO-8601 UTC instant like 2026-01-01T00:00:00Z, got {raw!r}"
    )
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _assert_envelope(ctx, account, env, *, source, detail_type, resources, started_at):
    assert env.get("version") == "0", f"envelope version must be '0', got {env.get('version')!r}"
    assert env.get("source") == source, f"expected source {source!r}, got {env.get('source')!r}"
    assert env.get("detail-type") == detail_type, (
        f"expected detail-type {detail_type!r}, got {env.get('detail-type')!r}"
    )
    assert env.get("account") == account, (
        f"expected account {account!r}, got {env.get('account')!r}"
    )
    assert env.get("region") == ctx.region, (
        f"expected region {ctx.region!r}, got {env.get('region')!r}"
    )
    assert env.get("resources") == resources, (
        f"expected resources {resources!r}, got {env.get('resources')!r}"
    )
    assert isinstance(env.get("id"), str) and _UUID.match(env["id"]), (
        f"event id must be a UUID, got {env.get('id')!r}"
    )
    stamped = _stamp(env)
    floor = started_at - timedelta(seconds=_CLOCK_SLACK_S)
    ceiling = datetime.now(timezone.utc) + timedelta(seconds=_CLOCK_SLACK_S)
    assert floor <= stamped <= ceiling, (
        f"event time {env['time']!r} must fall inside this run's window "
        f"[{floor.isoformat()}, {ceiling.isoformat()}]"
    )


def _assert_distinct_ids(envs):
    """At-least-once delivery may repeat an event (same id, same payload). Two DIFFERENT events
    must never share an id, and every distinct event must carry its own."""
    by_id: dict = {}
    for env in envs:
        payload = json.dumps({k: env.get(k) for k in ("detail-type", "resources", "detail")},
                             sort_keys=True)
        prior = by_id.setdefault(env["id"], payload)
        assert prior == payload, (
            f"id {env['id']!r} was carried by two different events: {prior} and {payload}"
        )
    distinct_payloads = {json.dumps({k: e.get(k) for k in ("detail-type", "resources", "detail")},
                                    sort_keys=True) for e in envs}
    assert len(by_id) == len(distinct_payloads), (
        f"{len(distinct_payloads)} distinct events arrived under {len(by_id)} ids"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
