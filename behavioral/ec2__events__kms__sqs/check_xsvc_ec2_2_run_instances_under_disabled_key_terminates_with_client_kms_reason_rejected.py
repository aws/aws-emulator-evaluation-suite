"""xsvc-ec2-2-run-instances-under-disabled-key-terminates-with-client-kms-reason-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-ec2-2-run-instances-under-disabled-key-terminates-with-client-kms-reason-rejected"
GROUP = "event-propagation"
SERVICES = ["ec2", "events", "kms", "sqs"]

_SOURCE = "aws.ec2"
_DETAIL_TYPE = "EC2 Instance State-change Notification"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_VPC_CIDR = "10.86.0.0/16"
_SUBNET_CIDR = "10.86.1.0/24"
_KMS_REASON = "Client.InvalidKMSKey.InvalidState"
_KMS_REASON_MESSAGE = "Client.InvalidKMSKey.InvalidState: The KMS key provided is in an incorrect state"
_DELIVERY_BUDGET_S = 600.0  # state-change delivery can take over 300s


@tags(
    "axis:rejection",
    "concern:eventing",
    "concern:negative-classes",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """RunInstances with a root volume under a disabled KMS key is accepted, then terminates with
    StateReason Client.InvalidKMSKey.InvalidState; EventBridge delivers shutting-down and terminated
    but never running. The same request under an enabled key reaches running (positive control).
    """
    ec2 = ctx.client("ec2")
    kms = ctx.client("kms")
    sqs = ctx.client("sqs")
    events = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-xsvc-rikms-")

    key_off = _new_key(ctx, kms, name + "-off")
    key_on = _new_key(ctx, kms, name + "-on")
    subnet = _network(ctx, ec2, name)
    ami = _ami(ctx)
    queue = _wire(ctx, events, sqs, name, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]})

    kms.disable_key(KeyId=key_off)
    state = kms.describe_key(KeyId=key_off)["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"the key must be Disabled before RunInstances, got {state!r}"

    # RunInstances under the disabled key is ACCEPTED synchronously (it mints an instance id); the
    # KMS refusal is asynchronous and graded below on the instance's terminal state.
    bad = _launch(ctx, ec2, ami, subnet, name + "-off", key_off)
    good = _launch(ctx, ec2, ami, subnet, name + "-on", key_on)
    assert _launched_state[bad] == "pending", (
        f"RunInstances under a disabled key must be ACCEPTED synchronously as 'pending' (the KMS "
        f"refusal is asynchronous); got {_launched_state[bad]!r}"
    )
    assert _launched_state[good] == "pending", (
        f"the control launch must start 'pending', got {_launched_state[good]!r}"
    )

    fate = _poll(lambda: _describe(ec2, bad), lambda i: i["State"]["Name"] in ("running", "terminated"),
                 timeout_s=600.0, interval_s=5.0, what=f"{bad} settling")
    assert fate["State"]["Name"] == "terminated", (
        f"an instance whose root volume is under a disabled key must never run; settled as "
        f"{fate['State']!r} {fate.get('StateReason')!r}"
    )
    reason = (fate.get("StateReason") or {}).get("Code")
    assert reason == _KMS_REASON, (
        f"StateReason.Code must be exactly {_KMS_REASON!r}, got {fate.get('StateReason')!r}"
    )
    reason_message = (fate.get("StateReason") or {}).get("Message")
    assert reason_message == _KMS_REASON_MESSAGE, (
        f"StateReason.Message must be exactly {_KMS_REASON_MESSAGE!r}, got {reason_message!r}"
    )
    ok = _poll(lambda: _describe(ec2, good), lambda i: i["State"]["Name"] in ("running", "terminated"),
               timeout_s=600.0, interval_s=5.0, what=f"control {good} settling")
    assert ok["State"]["Name"] == "running", (
        f"the enabled-key control must reach 'running', got {ok['State']!r} {ok.get('StateReason')!r}"
    )

    # EventBridge does not order deliveries (`terminated` can arrive before `shutting-down`), so
    # the barrier is the full required set for both instances.
    got: list = []
    _collect(sqs, queue, got,
             lambda g: {"shutting-down", "terminated"} <= _states(g, bad)
             and "running" in _states(g, good),
             what=f"shutting-down+terminated for {bad} and running for control {good}")
    for _ in range(3):
        got.extend(_drain(sqs, queue, wait=5))

    bad_states = _states(got, bad)
    for want in ("shutting-down", "terminated"):
        assert want in bad_states, (
            f"the KMS-failed instance {bad} must emit a {want!r} notification; got {sorted(bad_states)!r}"
        )
    assert "running" not in bad_states, (
        f"the KMS-failed instance {bad} must never emit 'running'; got {sorted(bad_states)!r}"
    )
    good_states = _states(got, good)
    assert {"pending", "running"} <= good_states and not good_states & {"shutting-down", "terminated"}, (
        f"the control {good} must emit pending and running only (so far); got {sorted(good_states)!r}"
    )
    for env in got:
        iid = (env.get("detail") or {}).get("instance-id")
        if iid not in (bad, good):
            continue
        assert env.get("source") == _SOURCE and env.get("detail-type") == _DETAIL_TYPE, (
            f"envelope source/detail-type: got {(env.get('source'), env.get('detail-type'))!r}"
        )
        assert env.get("account") == account and env.get("region") == ctx.region, (
            f"envelope account/region: got {(env.get('account'), env.get('region'))!r}"
        )
        assert env.get("resources") == [f"arn:aws:ec2:{ctx.region}:{account}:instance/{iid}"], (
            f"state-change resources must be the instance arn, got {env.get('resources')!r}"
        )


_GONE = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidInstanceID.NotFound")


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _tags_for(name):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "Name", "Value": name}]


def _poll(probe, predicate, *, timeout_s, interval_s, what):
    """Bounded poll that raises on timeout rather than returning its last observation."""
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


def _new_key(ctx, kms, desc):
    arn = kms.create_key(Description=desc, Tags=[{"TagKey": "sim2real", "TagValue": CHECK[:200]}]
                         )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _network(ctx, ec2, name):
    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags_for(name)}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc)))
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {_INSTANCE_TYPE!r}; offerings were {sorted(offered)!r}"
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=usable[0],
                               TagSpecifications=[{"ResourceType": "subnet",
                                                   "Tags": _tags_for(name)}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet)))
    return subnet


def _ami(ctx):
    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    return ami


def _launch(ctx, ec2, ami, subnet, name, key_arn):
    inst = ec2.run_instances(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {
            "Encrypted": True, "KmsKeyId": key_arn, "VolumeSize": 8, "VolumeType": "gp3",
            "DeleteOnTermination": True}}],
        TagSpecifications=[{"ResourceType": "instance", "Tags": _tags_for(name)},
                           {"ResourceType": "volume", "Tags": _tags_for(name)}],
    )["Instances"][0]
    iid = inst["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, iid))
    _launched_state[iid] = inst["State"]["Name"]
    return iid


#: RunInstances' synchronous State.Name, per instance id.
_launched_state: dict = {}


def _terminate_and_wait(ec2, iid):
    try:
        ec2.terminate_instances(InstanceIds=[iid])
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    _poll(lambda: _gone_or_state(ec2, iid), lambda s: s == "terminated",
          timeout_s=600.0, interval_s=10.0, what=f"instance {iid} reaching 'terminated'")


def _describe(ec2, iid):
    """The instance, or a not-yet-visible placeholder: DescribeInstances is eventually consistent
    right after RunInstances, so NotFound here means 'not visible yet', never 'terminated'."""
    try:
        return ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return {"State": {"Name": "__not_visible__"}, "StateReason": None}
        raise


def _gone_or_state(ec2, iid):
    """Teardown view: after a terminate, NotFound does mean the instance is gone."""
    name = _describe(ec2, iid)["State"]["Name"]
    return "terminated" if name == "__not_visible__" else name


def _wire(ctx, events, sqs, name, pattern):
    url = sqs.create_queue(QueueName=name[:80], tags={"sim2real": "1"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    rule = name[:64]
    rule_arn = events.put_rule(Name=rule, EventPattern=json.dumps(pattern), State="ENABLED",
                               Tags=[{"Key": "sim2real", "Value": "1"}])["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, Force=True))
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
    deadline = time.monotonic() + _DELIVERY_BUDGET_S
    while not done(into) and time.monotonic() < deadline:
        into.extend(_drain(sqs, url))
    assert done(into), (
        f"{what}: not delivered within {_DELIVERY_BUDGET_S}s. Received "
        f"{[e.get('detail') for e in into]!r}"
    )


def _states(envs, iid):
    return {e["detail"].get("state") for e in envs
            if (e.get("detail") or {}).get("instance-id") == iid}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
