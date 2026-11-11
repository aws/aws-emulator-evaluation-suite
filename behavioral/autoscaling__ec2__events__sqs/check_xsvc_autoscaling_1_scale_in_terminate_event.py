"""xsvc-autoscaling-1-scale-in-terminate-event."""
from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-autoscaling-1-scale-in-terminate-event"
GROUP = "event-propagation"
SERVICES = ["autoscaling", "ec2", "events", "sqs"]

_SOURCE = "aws.autoscaling"
_LAUNCH = "EC2 Instance Launch Successful"
_TERMINATE = "EC2 Instance Terminate Successful"
_CONTROL = "sim2real.control"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_VPC_CIDR = "10.91.0.0/16"
_SUBNET_CIDR = "10.91.1.0/24"


@tags(
    "cap:c1",
    "cap:c4",
    "concern:eventing",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "axis:happy-path",
)
def run(ctx) -> None:
    """Scaling a group from 2 to 1 terminates one instance and delivers an 'EC2 Instance Terminate
    Successful' event naming that instance, its scaling activity and the group and instance ARNs."""
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-xsvc-asgt-")
    started_at = datetime.now(timezone.utc)

    subnet = _network(ctx, ec2, name)
    ami = _ami(ctx)
    ctx.on_cleanup(lambda: _terminate_group_instances(ec2, name))
    lt = _launch_template(ctx, ec2, name, ami)

    url, queue_arn = _queue(ctx, sqs, name)
    nonces = {dt: ctx.unique_name("nonce-") for dt in (_LAUNCH, _TERMINATE)}
    rule_arns = [
        _rule(ctx, events, name + suffix, queue_arn, {"$or": [
            {"source": [_SOURCE], "detail-type": [dt],
             "detail": {"AutoScalingGroupName": [name]}},
            {"source": [_CONTROL], "detail": {"nonce": [nonces[dt]]}}]})
        for suffix, dt in (("-launch", _LAUNCH), ("-term", _TERMINATE))
    ]
    _allow_rules(sqs, url, queue_arn, rule_arns)
    _await_rules_live(events, sqs, url, nonces)

    asg.create_auto_scaling_group(
        AutoScalingGroupName=name, MinSize=0, MaxSize=2, DesiredCapacity=2,
        LaunchTemplate={"LaunchTemplateId": lt, "Version": "$Latest"},
        VPCZoneIdentifier=subnet,
        Tags=[{"Key": "sim2real", "Value": "1", "PropagateAtLaunch": True}])
    ctx.on_cleanup(lambda: _delete_group(asg, name))
    try:
        _scale_in(ctx, asg, ec2, sqs, account, name, url, started_at)
    finally:
        _retire(asg, ec2, [name])



def _scale_in(ctx, asg, ec2, sqs, account, name, url, started_at):
    group_arn = _group(asg, name)["AutoScalingGroupARN"]

    # --- positive control: both launches of the scale-up arrive through the launch rule ---
    got: list = []
    _collect(sqs, url, got,
             lambda es: len({e["detail"].get("EC2InstanceId") for e in es
                             if e.get("detail-type") == _LAUNCH}) >= 2,
             what=f"two '{_LAUNCH}' events for group {name}")
    members = _poll(lambda: _in_service(asg, name), lambda ids: len(ids) == 2,
                    timeout_s=600.0, interval_s=10.0,
                    what=f"group {name} reporting 2 InService instances")
    launched = {e["detail"]["EC2InstanceId"] for e in got if e.get("detail-type") == _LAUNCH}
    assert launched == set(members), (
        f"the launch events named {sorted(launched)!r}; the group lists {sorted(members)!r}"
    )
    for env in (e for e in got if e.get("detail-type") == _LAUNCH):
        d = env["detail"]
        assert (d.get("Origin"), d.get("Destination")) == ("EC2", "AutoScalingGroup"), (
            f"a launch event must flow EC2 -> AutoScalingGroup: {d!r}"
        )
    early = [e for e in got if e.get("detail-type") == _TERMINATE]
    assert early == [], f"no terminate event may precede the scale-in request: {early!r}"

    # --- the act: scale in 2 -> 1 ---
    asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1, HonorCooldown=False)
    _collect(sqs, url, got, lambda es: any(e.get("detail-type") == _TERMINATE for e in es),
             what=f"a '{_TERMINATE}' event for group {name}")
    for _ in range(2):
        got.extend(_drain(sqs, url))

    survivors = _poll(lambda: [i["InstanceId"] for i in _group(asg, name)["Instances"]],
                      lambda ids: len(ids) == 1, timeout_s=600.0, interval_s=10.0,
                      what=f"group {name} shrinking to one instance")
    removed = set(members) - set(survivors)
    assert len(removed) == 1, (
        f"scale-in must remove exactly one of {sorted(members)!r}; the group now lists "
        f"{survivors!r}"
    )
    victim = removed.pop()
    terms = [e for e in got if e.get("detail-type") == _TERMINATE]
    assert {e["detail"].get("EC2InstanceId") for e in terms} == {victim}, (
        f"terminate events must name only the removed instance {victim!r}: "
        f"{[e['detail'] for e in terms]!r}"
    )
    assert _state(ec2, victim) in ("shutting-down", "terminated"), (
        f"the instance the event reports terminated, {victim}, is {_state(ec2, victim)!r} in EC2"
    )
    activities = {a["ActivityId"]: a for page in asg.get_paginator(
        "describe_scaling_activities").paginate(AutoScalingGroupName=name)
        for a in page["Activities"]}

    for env in terms:
        d = env["detail"]
        assert d.get("AutoScalingGroupName") == name, f"the event must name group {name!r}: {d!r}"
        assert d.get("Origin") == "AutoScalingGroup", (
            f"a scale-in termination must originate at 'AutoScalingGroup': {d.get('Origin')!r}"
        )
        assert d.get("Destination") == "EC2", (
            f"a scale-in termination must be destined for 'EC2': {d.get('Destination')!r}"
        )
        aid = d.get("ActivityId")
        assert aid in activities, (
            f"the event's ActivityId {aid!r} must be one of the group's scaling activities "
            f"{sorted(activities)!r}"
        )
        assert victim in activities[aid]["Description"] and \
            activities[aid]["Description"].startswith("Terminating"), (
            f"activity {aid} must describe terminating {victim}: "
            f"{activities[aid]['Description']!r}"
        )
        want = {group_arn, f"arn:aws:ec2:{ctx.region}:{account}:instance/{victim}"}
        assert len(env.get("resources", [])) == 2 and set(env["resources"]) == want, (
            f"resources must be exactly the group ARN and the instance ARN {sorted(want)!r}, got "
            f"{env.get('resources')!r}"
        )
        _assert_envelope(ctx, account, env, source=_SOURCE, detail_type=_TERMINATE,
                         started_at=started_at)
    _assert_distinct_ids(got)


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


def _retry_dependency(fn, attempts=5, delay=5.0):
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
    return subnet


def _ami(ctx):
    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    return ami


def _launch_template(ctx, ec2, name, ami):
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
    return lt


def _group(asg, name):
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    return groups[0] if groups else None


def _in_service(asg, name):
    return [i["InstanceId"] for i in _group(asg, name)["Instances"]
            if i["LifecycleState"] == "InService"]


def _delete_group(asg, name):
    """Registered cleanup: issue the ForceDelete and return. It deliberately does NOT wait — the
    engine bounds the whole cleanup chain (60 s by default), and a wait here is what starved every
    later teardown in an earlier draft. The wait lives in `_retire`, inside the check's budget."""
    try:
        asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    except ClientError as exc:
        if "not found" not in str(exc).lower():
            raise


def _group_instance_ids(ec2, name):
    return [i["InstanceId"] for page in ec2.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "tag:sim2real-asg", "Values": [name]},
                 {"Name": "instance-state-name",
                  "Values": ["pending", "running", "stopping", "stopped", "shutting-down"]}])
        for r in page["Reservations"] for i in r["Instances"]]


def _terminate_group_instances(ec2, name):
    """Registered safety net: terminate any instance this group launched, found by the tag the
    launch template stamped at launch. Issues the call and returns, for the same budget reason."""
    ids = [i for i in _group_instance_ids(ec2, name)]
    if ids:
        ec2.terminate_instances(InstanceIds=ids)


def _retire(asg, ec2, names):
    """Run from the check's own `finally`, so the slow part of teardown — ForceDelete, then the
    group and every instance it launched actually gone — is bounded by the check timeout and not
    by the cleanup chain's. Tries every group, then raises naming what is left, prefixed with the
    body's in-flight error so the verdict is never masked."""
    found = sys.exc_info()[1]
    left = []
    for name in names:
        try:
            _delete_group(asg, name)
        except Exception as exc:  # noqa: BLE001 - collected and raised below
            left.append(f"ForceDelete of group {name} failed: {exc!r}")
    deadline = time.monotonic() + 900.0
    for name in names:
        try:
            while time.monotonic() < deadline and _group(asg, name) is not None:
                time.sleep(2)
            while time.monotonic() < deadline and _group_instance_ids(ec2, name):
                _terminate_group_instances(ec2, name)
                time.sleep(2)
            if _group(asg, name) is not None or _group_instance_ids(ec2, name):
                left.append(f"group {name} or its instances outlived the 900s retire window")
        except Exception as exc:  # noqa: BLE001 - collected and raised below
            left.append(f"retiring group {name} failed: {exc!r}")
    if left:
        raise RuntimeError((f"{found!r}; " if found else "")
                           + f"teardown left groups behind: {left!r}")


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


def _queue(ctx, sqs, name):
    url = sqs.create_queue(QueueName=name[:80],
                           Attributes={"ReceiveMessageWaitTimeSeconds": "10"},
                           tags={"sim2real": "1"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url,
                                   AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _rule(ctx, events, name, queue_arn, pattern):
    """A default-bus rule targeting the queue. Returns the rule ARN."""
    rule = name[:64]
    rule_arn = events.put_rule(Name=rule, EventPattern=json.dumps(pattern), State="ENABLED",
                               Description="sim2real xsvc-autoscaling check",
                               Tags=[{"Key": "sim2real", "Value": "1"}])["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, Force=True))
    resp = events.put_targets(Rule=rule, Targets=[{"Id": "q", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, Ids=["q"], Force=True))
    assert resp["FailedEntryCount"] == 0, f"PutTargets failed for {rule}: {resp!r}"
    return rule_arn


def _allow_rules(sqs, url, queue_arn, rule_arns):
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": queue_arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": rule_arns}}}]})})


def _drain_raw(sqs, url, wait=10):
    msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                               WaitTimeSeconds=wait).get("Messages", [])
    if msgs:
        sqs.delete_message_batch(QueueUrl=url, Entries=[
            {"Id": str(i), "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)])
    return [json.loads(m["Body"]) for m in msgs]


def _drain(sqs, url, wait=10):
    """Auto Scaling's events only: a late (at-least-once) redelivery of a PutEvents barrier
    nonce is plumbing, never part of the asserted set."""
    return [e for e in _drain_raw(sqs, url, wait) if e.get("source") != _CONTROL]


def _await_rules_live(events, sqs, url, nonces):
    """Barrier: publish each rule's nonce until every one has come back through its own rule to
    the queue — proof that those exact rules, targets and the queue policy are live before any
    Auto Scaling event is provoked."""
    seen: set = set()

    def attempt():
        for dt, nonce in nonces.items():
            if nonce in seen:
                continue
            resp = events.put_events(Entries=[{"Source": _CONTROL, "DetailType": "sim2real barrier",
                                               "Detail": json.dumps({"nonce": nonce})}])
            assert resp["FailedEntryCount"] == 0, f"barrier PutEvents failed: {resp!r}"
        for e in _drain_raw(sqs, url, wait=5):
            if e.get("source") == _CONTROL:
                seen.add(e.get("detail", {}).get("nonce"))
        return seen

    _poll(attempt, lambda s: s >= set(nonces.values()), timeout_s=300.0, interval_s=2.0,
          what=f"barrier nonces {sorted(nonces.values())!r} arriving through their own rules")


def _collect(sqs, url, into, done, *, what):
    deadline = time.monotonic() + _DRAIN_TIMEOUT_S
    while not done(into) and time.monotonic() < deadline:
        into.extend(_drain(sqs, url))
    assert done(into), (
        f"{what}: not delivered within {_DRAIN_TIMEOUT_S}s. Received "
        f"{[(e.get('detail-type'), e.get('time'), e.get('detail')) for e in into]!r}. A target "
        f"that never emits its own events fails exactly here"
    )


def _stamp(env):
    raw = env.get("time")
    assert isinstance(raw, str) and _ISO_SECONDS.match(raw), (
        f"event time must be an ISO-8601 UTC instant like 2026-01-01T00:00:00Z, got {raw!r}"
    )
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _assert_envelope(ctx, account, env, *, source, detail_type, started_at):
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
    must never share an id."""
    by_id: dict = {}
    for env in envs:
        payload = json.dumps({k: env.get(k) for k in ("detail-type", "resources", "detail")},
                             sort_keys=True)
        prior = by_id.setdefault(env["id"], payload)
        assert prior == payload, (
            f"id {env['id']!r} was carried by two different events: {prior} and {payload}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
