"""xsvc-autoscaling-2-disabled-cmk-launch-is-cancelled-and-evented-until-the-key-is-enabled."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-autoscaling-2-disabled-cmk-launch-is-cancelled-and-evented-until-the-key-is-enabled"
GROUP = "error-propagation"
SERVICES = ["autoscaling", "ec2", "events", "kms", "sqs"]

_SOURCE = "aws.autoscaling"
_FAILED = "EC2 Instance Launch Unsuccessful"
_LAUNCHED = "EC2 Instance Launch Successful"
_KMS_REASON = "Client.InvalidKMSKey.InvalidState"
_STATE_REASON_MESSAGE = (
    "Client.InvalidKMSKey.InvalidState: The KMS key provided is in an incorrect state"
)
_ACTIVITY_MESSAGE = (
    "Instance became unhealthy while waiting for instance to be in InService state. "
    "Termination Reason: " + _STATE_REASON_MESSAGE
)
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_VPC_CIDR = "10.141.0.0/16"
_SUBNET_CIDR = "10.141.1.0/24"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:eventing", "concern:negative-classes",
      "concern:e2e", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A launch whose template encrypts the root volume with a DISABLED CMK is Cancelled with
    Client.InvalidKMSKey.InvalidState on the activity, instance and event; re-enabling the key lets
    the group's own retry launch under that key, and ForceDelete removes the group and instance."""
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    events = ctx.client("events")
    kms = ctx.client("kms")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-xsvc-askms-")
    started_at = datetime.now(timezone.utc)

    # Cleanups run in reverse registration order within a 60 s bound: the slow network goes first
    # so it is torn down last.
    subnet, _az = _network(ctx, ec2, name)
    # The rule next, so it has the longest possible time to become effective.
    queue = _wire(ctx, events, sqs, account, name, {
        "source": [_SOURCE], "detail-type": [_FAILED, _LAUNCHED],
        "detail": {"AutoScalingGroupName": [name]}})

    ami = _ami(ctx)
    root_device = ec2.describe_images(ImageIds=[ami])["Images"][0]["RootDeviceName"]

    key = kms.create_key(Description=f"sim2real {name}",
                         Tags=[{"TagKey": "sim2real", "TagValue": "1"}])["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: _retire_key(kms, key_id))

    ctx.on_cleanup(lambda: _terminate_group_instances(ec2, name, wait=False))
    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami, "InstanceType": _INSTANCE_TYPE,
            "BlockDeviceMappings": [{"DeviceName": root_device, "Ebs": {
                "Encrypted": True, "KmsKeyId": key_arn, "VolumeSize": 8, "VolumeType": "gp3",
                "DeleteOnTermination": True}}],
            "TagSpecifications": [
                {"ResourceType": "instance",
                 "Tags": _tags_for(name) + [{"Key": "sim2real-asg", "Value": name}]},
                {"ResourceType": "volume", "Tags": _tags_for(name)}]},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_for(name)}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_launch_template(LaunchTemplateId=lt)))

    asg.create_auto_scaling_group(
        AutoScalingGroupName=name, MinSize=0, MaxSize=1, DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateId": lt, "Version": "$Latest"},
        VPCZoneIdentifier=subnet,
        Tags=[{"Key": "sim2real", "Value": "1", "PropagateAtLaunch": True}])
    ctx.on_cleanup(lambda: _force_delete(asg, name))
    group = _group(asg, name)
    assert group is not None, f"group {name} must exist after CreateAutoScalingGroup"
    group_arn = group["AutoScalingGroupARN"]
    slr = group.get("ServiceLinkedRoleARN")
    assert slr == (f"arn:aws:iam::{account}:role/aws-service-role/autoscaling.amazonaws.com/"
                   "AWSServiceRoleForAutoScaling"), f"unexpected ServiceLinkedRoleARN {slr!r}"

    # The key policy lets Auto Scaling's role use the key from the start, so the ONLY variable
    # this check flips is the key's enabled/disabled state.
    _grant_slr(kms, key_id, account, slr)
    kms.disable_key(KeyId=key_id)
    state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"DisableKey must leave the key Disabled, got {state!r}"

    # --- the broken launch ---
    asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1)
    got: list = []
    _collect(sqs, queue, got, lambda es: any(e["detail-type"] == _FAILED for e in es),
             what=f"an '{_FAILED}' event for group {name} while its CMK is disabled")
    failed_events = [e for e in got if e["detail-type"] == _FAILED]
    assert not [e for e in got if e["detail-type"] == _LAUNCHED], (
        f"a launch SUCCEEDED while the root-volume key was disabled: "
        f"{[e['detail'] for e in got if e['detail-type'] == _LAUNCHED]!r}"
    )

    # Effect absent, observed at the barrier the failure event provides. AWS reports the activity
    # as Cancelled, not Failed, and the group retries about once a minute; a just-created rule may
    # miss the first event, so each event is matched to whichever cancelled activity it names.
    group = _group(asg, name)
    in_service = [i for i in group["Instances"] if i["LifecycleState"] == "InService"]
    assert in_service == [], f"no instance may be InService with a disabled key: {in_service!r}"
    assert group["DesiredCapacity"] == 1, (
        f"a cancelled launch must not move DesiredCapacity off 1: {group['DesiredCapacity']!r}"
    )

    evented = {e["detail"].get("ActivityId") for e in failed_events}
    activities = _poll(lambda: _activities(asg, name),
                       lambda acts: evented <= {a["ActivityId"] for a in acts
                                                if a["StatusCode"] == "Cancelled"},
                       timeout_s=120.0, interval_s=5.0,
                       what=f"the evented activities {sorted(evented, key=str)!r} reading Cancelled")
    cancelled = {a["ActivityId"]: a for a in activities if a["StatusCode"] == "Cancelled"}
    assert cancelled, (
        f"the disabled-key launch must leave a Cancelled scaling activity; activities were "
        f"{[(a['StatusCode'], a.get('StatusMessage')) for a in activities]!r}"
    )
    for act in cancelled.values():
        msg = act.get("StatusMessage")
        assert msg == _ACTIVITY_MESSAGE, (
            f"the cancelled activity's StatusMessage must be {_ACTIVITY_MESSAGE!r}: {msg!r}"
        )
        assert act["Progress"] == 100, f"a Cancelled activity must be complete: {act!r}"

    failed_ids = set()
    for env in failed_events:
        d = env["detail"]
        assert d.get("ActivityId") in cancelled, (
            f"the '{_FAILED}' event names ActivityId {d.get('ActivityId')!r}, which is not one of "
            f"the group's Cancelled activities {sorted(cancelled)!r}"
        )
        act = cancelled[d["ActivityId"]]
        assert d.get("StatusCode") == "Cancelled", (
            f"detail.StatusCode must be the activity's 'Cancelled', got {d.get('StatusCode')!r}"
        )
        assert d.get("StatusMessage") == act["StatusMessage"], (
            f"detail.StatusMessage must equal the activity's: {d.get('StatusMessage')!r} vs "
            f"{act['StatusMessage']!r}"
        )
        assert d.get("AutoScalingGroupName") == name, f"event must name {name!r}: {d!r}"
        iid = d.get("EC2InstanceId")
        assert isinstance(iid, str) and iid.startswith("i-") and iid in act["Description"], (
            f"the event's EC2InstanceId {iid!r} must be the instance activity {act['ActivityId']} "
            f"describes: {act['Description']!r}"
        )
        assert env["resources"][0] == group_arn, (
            f"resources[0] must be the group ARN {group_arn!r}: {env['resources']!r}"
        )
        _assert_envelope(ctx, account, env, source=_SOURCE, detail_type=_FAILED,
                         resources=[group_arn, f"arn:aws:ec2:{ctx.region}:{account}:instance/{iid}"],
                         started_at=started_at)
        failed_ids.add(iid)

    # Cross-service: EC2 itself records why the instance Auto Scaling launched did not survive.
    for iid in sorted(failed_ids):
        inst = _poll(lambda i=iid: _instance(ec2, i),
                     lambda x: x is not None and x["State"]["Name"] == "terminated",
                     timeout_s=300.0, interval_s=5.0, what=f"failed instance {iid} terminated")
        reason = inst.get("StateReason", {})
        assert reason == {"Code": _KMS_REASON, "Message": _STATE_REASON_MESSAGE}, (
            f"EC2 must record {_KMS_REASON!r} with message {_STATE_REASON_MESSAGE!r} as {iid}'s "
            f"state reason, got {reason!r}"
        )

    # --- repair the one broken thing; the group's own retry must now succeed on the SAME queue ---
    kms.enable_key(KeyId=key_id)
    _collect(sqs, queue, got, lambda es: any(e["detail-type"] == _LAUNCHED for e in es),
             what=f"an '{_LAUNCHED}' event for group {name} after re-enabling its CMK")
    launched = [e for e in got if e["detail-type"] == _LAUNCHED]
    good = _poll(lambda: [i for i in _group(asg, name)["Instances"]
                          if i["LifecycleState"] == "InService"],
                 lambda xs: len(xs) == 1, timeout_s=600.0, interval_s=10.0,
                 what=f"group {name} reaching one InService instance after EnableKey")
    good_iid = good[0]["InstanceId"]
    assert good_iid not in failed_ids, (
        f"the InService instance {good_iid} must be a NEW launch, not one that failed"
    )
    group = _group(asg, name)
    assert group["DesiredCapacity"] == 1, (
        f"DesiredCapacity must still be 1 after recovery, got {group['DesiredCapacity']!r}"
    )
    activities = {a["ActivityId"]: a for a in _activities(asg, name)}
    for env in launched:
        d = env["detail"]
        assert d.get("EC2InstanceId") == good_iid, (
            f"the success event must name the InService instance {good_iid!r}: {d!r}"
        )
        assert d.get("ActivityId") in activities and d["ActivityId"] not in cancelled, (
            f"the success event's ActivityId {d.get('ActivityId')!r} must be a new activity of the "
            f"group, not a cancelled one"
        )
        # The event is a snapshot taken mid-activity; the activity's terminal state is graded below.
        assert env["resources"][0] == group_arn, (
            f"resources[0] must be the group ARN {group_arn!r}: {env['resources']!r}"
        )
        _assert_envelope(ctx, account, env, source=_SOURCE, detail_type=_LAUNCHED,
                         resources=[group_arn,
                                    f"arn:aws:ec2:{ctx.region}:{account}:instance/{good_iid}"],
                         started_at=started_at)
    done = _poll(lambda: _activities_by_id(asg, name).get(launched[0]["detail"]["ActivityId"]),
                 lambda a: a is not None and a["StatusCode"] == "Successful",
                 timeout_s=300.0, interval_s=5.0, what="the success activity reaching Successful")
    assert good_iid in done["Description"], f"activity must describe {good_iid}: {done!r}"
    _assert_distinct_ids(got)

    # The data the key actually protects: the surviving root volume is encrypted under THIS key.
    vols = _poll(lambda: ec2.describe_volumes(Filters=[
        {"Name": "attachment.instance-id", "Values": [good_iid]}])["Volumes"],
        lambda v: len(v) == 1, timeout_s=120.0, interval_s=5.0,
        what=f"the root volume of {good_iid}")
    vol = vols[0]
    assert vol["Encrypted"] is True and vol.get("KmsKeyId") == key_arn, (
        f"{good_iid}'s root volume must be encrypted under {key_arn!r}: "
        f"Encrypted={vol['Encrypted']!r} KmsKeyId={vol.get('KmsKeyId')!r}"
    )

    # --- graded teardown leg ---
    # Done here rather than in cleanup: one ForceDelete of a group with a live instance does not fit
    # the 60 s cleanup bound. It must remove the group AND terminate every instance it launched.
    _delete_when_idle(asg, name)
    _poll(lambda: _group(asg, name), lambda g: g is None, timeout_s=900.0, interval_s=10.0,
          what=f"group {name} disappearing after ForceDelete")
    alive = _terminate_group_instances(ec2, name, wait=True, act=False)
    assert alive == [], f"ForceDelete left instances of {name} not terminated: {alive!r}"
    gone = _instance(ec2, good_iid)
    assert gone is None or gone["State"]["Name"] == "terminated", (
        f"ForceDelete must terminate the group's instance {good_iid}: {gone and gone['State']!r}"
    )


def _grant_slr(kms, key_id, account, slr):
    policy = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "Root", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
         "Action": "kms:*", "Resource": "*"},
        {"Sid": "AutoScalingUse", "Effect": "Allow", "Principal": {"AWS": slr},
         "Action": ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*",
                    "kms:DescribeKey"], "Resource": "*"},
        {"Sid": "AutoScalingGrant", "Effect": "Allow", "Principal": {"AWS": slr},
         "Action": "kms:CreateGrant", "Resource": "*",
         "Condition": {"Bool": {"kms:GrantIsForAWSResource": True}}}]})
    # A role Auto Scaling has only just created is not yet a valid KMS principal everywhere.
    deadline = time.monotonic() + 120.0
    while True:
        try:
            kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=policy)
            return
        except ClientError as exc:
            if _code(exc) != "MalformedPolicyDocumentException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _retire_key(kms, key_id):
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
        if state != "PendingDeletion":
            # Same exception type and code, so a caller catching ClientError still collects it.
            raise type(exc)(
                {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                    f"KMS key {key_id} ({state}) could not be scheduled for deletion: {exc}"
                )}},
                exc.operation_name,
            ) from exc


def _activities(asg, name):
    return [a for page in asg.get_paginator("describe_scaling_activities").paginate(
        AutoScalingGroupName=name) for a in page["Activities"]]


def _activities_by_id(asg, name):
    return {a["ActivityId"]: a for a in _activities(asg, name)}


def _instance(ec2, iid):
    try:
        resv = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    return resv[0]["Instances"][0] if resv and resv[0].get("Instances") else None


def _group(asg, name):
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    return groups[0] if groups else None


def _force_delete(asg, name):
    """Issue the ForceDelete and return without waiting, to stay within the 60 s cleanup bound."""
    try:
        asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    except ClientError as exc:
        if "not found" not in str(exc).lower():
            # Same exception type and code, so a caller catching ClientError still collects it.
            raise type(exc)(
                {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                    f"could not ForceDelete Auto Scaling group {name}: {exc}"
                )}},
                exc.operation_name,
            ) from exc


def _terminate_group_instances(ec2, name, *, wait, act=True):
    """Non-terminated instances this group launched, found by the launch template's tag.

    act=True terminates them and returns at once; wait=True waits for EC2 to report them gone."""
    def alive():
        return sorted(i["InstanceId"] for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "tag:sim2real-asg", "Values": [name]},
                     {"Name": "instance-state-name",
                      "Values": ["pending", "running", "stopping", "stopped", "shutting-down"]}])
            for r in page["Reservations"] for i in r["Instances"])
    ids = alive()
    if act and ids:
        ec2.terminate_instances(InstanceIds=ids)
    if not wait:
        return ids
    deadline = time.monotonic() + 600.0
    while ids and time.monotonic() < deadline:
        time.sleep(5)
        ids = alive()
    return ids


def _delete_when_idle(asg, name):
    """ForceDelete, retried only while Auto Scaling reports an activity still in progress."""
    deadline = time.monotonic() + 300.0
    while True:
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            return
        except ClientError as exc:
            if _code(exc) != "ScalingActivityInProgress" or time.monotonic() >= deadline:
                raise
            time.sleep(5)



_DRAIN_TIMEOUT_S = 900.0
_CLOCK_SLACK_S = 300
_ISO_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_GONE = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
         "InvalidLaunchTemplateId.NotFound")


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
            if attempt == attempts - 1:
                raise RuntimeError(f"teardown step never converged: {exc}") from exc
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
    ctx.on_cleanup(lambda: _retry_dependency(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc)))
    az = _zones_offering(ec2, _INSTANCE_TYPE)[0]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
                               TagSpecifications=[{"ResourceType": "subnet",
                                                   "Tags": _tags_for(name)}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet)))
    return subnet, az


def _ami(ctx):
    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    return ami


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
                               Description="sim2real autoscaling disabled-cmk check",
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
    must never share an id."""
    by_id: dict = {}
    for env in envs:
        payload = json.dumps({k: env.get(k) for k in ("detail-type", "resources", "detail")},
                             sort_keys=True)
        prior = by_id.setdefault(env["id"], payload)
        assert prior == payload, (
            f"id {env['id']!r} was carried by two different events: {prior} and {payload}"
        )


# Deletes in this VPC are asynchronous: their ENIs linger, so DeleteSubnet / DeleteSecurityGroup /
# DeleteVpc fail with DependencyViolation. Wait (bounded) for the ENIs, retry inside the window, and
# raise naming any ENIs still attached.
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
        _time.sleep(5)
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
        _time.sleep(5)


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
