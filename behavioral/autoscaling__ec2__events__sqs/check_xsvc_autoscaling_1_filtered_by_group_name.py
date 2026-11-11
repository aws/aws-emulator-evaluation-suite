"""xsvc-autoscaling-1-filtered-by-group-name."""
from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-autoscaling-1-filtered-by-group-name"
GROUP = "event-propagation"
SERVICES = ["autoscaling", "ec2", "events", "sqs"]

_SOURCE = "aws.autoscaling"
_LAUNCH = "EC2 Instance Launch Successful"
_CONTROL = "sim2real.control"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_VPC_CIDR = "10.93.0.0/16"
_SUBNET_CIDR = "10.93.1.0/24"
_BARRIER_ROUNDS = 6


@tags(
    "axis:negative-delivery",
    "concern:eventing",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A rule filtered on detail.AutoScalingGroupName delivers the launch event of the group it
    names and never of a sibling group, while an unfiltered control rule receives both groups'
    events."""
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    base = ctx.unique_name("sim2real-xsvc-asgf-")
    one, two = base + "-a", base + "-b"
    started_at = datetime.now(timezone.utc)

    subnet = _network(ctx, ec2, base)
    ami = _ami(ctx)
    ctx.on_cleanup(lambda: _terminate_group_instances(ec2, two))
    ctx.on_cleanup(lambda: _terminate_group_instances(ec2, one))
    lts = {g: _launch_template(ctx, ec2, g, ami) for g in (one, two)}

    nonces = {"filt": ctx.unique_name("nonce-"), "ctl": ctx.unique_name("nonce-")}
    f_url, f_arn = _queue(ctx, sqs, base + "-filt")
    _allow_rules(sqs, f_url, f_arn, [_rule(ctx, events, base + "-filt", f_arn, {"$or": [
        {"source": [_SOURCE], "detail-type": [_LAUNCH],
         "detail": {"AutoScalingGroupName": [one]}},
        {"source": [_CONTROL], "detail": {"nonce": [nonces["filt"]]}}]})])
    c_url, c_arn = _queue(ctx, sqs, base + "-ctl")
    _allow_rules(sqs, c_url, c_arn, [_rule(ctx, events, base + "-ctl", c_arn, {"$or": [
        {"source": [_SOURCE], "detail-type": [_LAUNCH],
         "detail": {"AutoScalingGroupName": [{"prefix": base + "-"}]}},
        {"source": [_CONTROL], "detail": {"nonce": [nonces["ctl"]]}}]})])
    _await_rules_live(events, sqs, {f_url: nonces["filt"], c_url: nonces["ctl"]})

    try:
        _filtered(ctx, asg, sqs, account, base, one, two, lts, subnet, f_url, c_url, started_at)
    finally:
        _retire(asg, ec2, [one, two])


def _filtered(ctx, asg, sqs, account, base, one, two, lts, subnet, f_url, c_url, started_at):
    arns = {}
    for g in (one, two):
        asg.create_auto_scaling_group(
            AutoScalingGroupName=g, MinSize=0, MaxSize=1, DesiredCapacity=1,
            LaunchTemplate={"LaunchTemplateId": lts[g], "Version": "$Latest"},
            VPCZoneIdentifier=subnet,
            Tags=[{"Key": "sim2real", "Value": "1", "PropagateAtLaunch": True}])
        ctx.on_cleanup(lambda g=g: _delete_group(asg, g))
        arns[g] = _group(asg, g)["AutoScalingGroupARN"]

    ctl: list = []
    _collect(sqs, c_url, ctl,
             lambda es: {e["detail"].get("AutoScalingGroupName") for e in es} >= {one, two},
             what=f"the control queue receiving launch events for both {one} and {two}")
    filt: list = []
    _collect(sqs, f_url, filt,
             lambda es: any(e["detail"].get("AutoScalingGroupName") == one for e in es),
             what=f"the filtered queue receiving the launch event for {one}")
    for _ in range(_BARRIER_ROUNDS):
        filt.extend(_drain(sqs, f_url))
        ctl.extend(_drain(sqs, c_url))

    names_filt = [e["detail"].get("AutoScalingGroupName") for e in filt]
    assert set(names_filt) == {one}, (
        f"the rule filtered on AutoScalingGroupName={one!r} delivered events for "
        f"{sorted(set(names_filt))!r}; group {two!r}'s launch (which the control queue DID "
        f"receive) must never match it"
    )
    names_ctl = {e["detail"].get("AutoScalingGroupName") for e in ctl}
    assert names_ctl == {one, two}, (
        f"the prefix-filtered control rule must deliver exactly both groups' events, got "
        f"{sorted(names_ctl)!r}"
    )

    for g in (one, two):
        members = _poll(lambda g=g: [i["InstanceId"] for i in _group(asg, g)["Instances"]],
                        lambda ids: len(ids) == 1, timeout_s=300.0, interval_s=5.0,
                        what=f"group {g} listing its launched instance")
        mine = [e for e in ctl if e["detail"].get("AutoScalingGroupName") == g]
        assert {e["detail"].get("EC2InstanceId") for e in mine} == set(members), (
            f"control events for {g} named {[e['detail'].get('EC2InstanceId') for e in mine]!r}; "
            f"the group lists {members!r}"
        )
        for env in mine:
            want = {arns[g], f"arn:aws:ec2:{ctx.region}:{account}:instance/{members[0]}"}
            assert set(env.get("resources", [])) == want, (
                f"resources for {g}'s launch must be {sorted(want)!r}: {env.get('resources')!r}"
            )
            _assert_envelope(ctx, account, env, source=_SOURCE, detail_type=_LAUNCH,
                             started_at=started_at)

    ids_filt = {e["id"] for e in filt}
    ids_ctl_one = {e["id"] for e in ctl if e["detail"].get("AutoScalingGroupName") == one}
    assert ids_filt == ids_ctl_one, (
        f"group {one}'s launch event must reach both rules as ONE event (same id): filtered "
        f"queue saw {sorted(ids_filt)!r}, control queue saw {sorted(ids_ctl_one)!r}"
    )
    _assert_distinct_ids(filt + ctl)


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


def _await_rules_live(events, sqs, nonce_by_queue):
    """Barrier: publish each rule's nonce until every one has come back through its own rule to
    its own queue — proof that those exact rules, targets and queue policies are live before any
    Auto Scaling event is provoked."""
    seen: set = set()

    def attempt():
        for url, nonce in nonce_by_queue.items():
            if nonce in seen:
                continue
            resp = events.put_events(Entries=[{"Source": _CONTROL, "DetailType": "sim2real barrier",
                                               "Detail": json.dumps({"nonce": nonce})}])
            assert resp["FailedEntryCount"] == 0, f"barrier PutEvents failed: {resp!r}"
            for e in _drain_raw(sqs, url, wait=2):
                if e.get("source") == _CONTROL:
                    seen.add(e.get("detail", {}).get("nonce"))
        return seen

    _poll(attempt, lambda s: s >= set(nonce_by_queue.values()), timeout_s=300.0, interval_s=2.0,
          what=f"barrier nonces {sorted(nonce_by_queue.values())!r} arriving through their rules")


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
