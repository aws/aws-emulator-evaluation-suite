"""xsvc-rds-1-near-miss-rules-not-delivered-after-matching-rule-receives."""
from __future__ import annotations

import json
import secrets
import string
import time
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-rds-1-near-miss-rules-not-delivered-after-matching-rule-receives"
GROUP = 'event-routing'
SERVICES = ['events', 'rds', 'sqs']

DB_CLASS = "db.t4g.micro"
EVENT_ID = "RDS-EVENT-0006"
DELIVERY_BUDGET_S = 600


def _pattern(db_arn: str, *, detail_type="RDS DB Instance Event", event_id=EVENT_ID,
             source_arn=None) -> dict:
    return {"source": ["aws.rds"], "detail-type": [detail_type],
            "detail": {"EventID": [event_id], "SourceArn": [source_arn or db_arn]}}


@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "concern:negative-classes",
      "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Rules one field away from the matching RDS reboot rule receive nothing; repaired, they do.

    Near-miss queues must be empty once the matching rule has received; after repair and a second
    reboot the same queues receive, so the absence came from the pattern, not the queue.
    """
    rds = ctx.client("rds")
    ev = ctx.client("events")
    sqs = ctx.client("sqs")
    ec2 = ctx.client("ec2")
    ident = ctx.client("sts").get_caller_identity()
    account, partition = ident["Account"], ident["Arn"].split(":")[1]

    db_id = ctx.unique_name("sim2real-xsvc-rds1-")
    db_arn = f"arn:{partition}:rds:{ctx.region}:{account}:db:{db_id}"
    ghost_arn = f"arn:{partition}:rds:{ctx.region}:{account}:db:{db_id}-absent"
    est = _Estate(ctx)

    good = _pattern(db_arn)
    near_miss = {
        "wrong-event-id": _pattern(db_arn, event_id="RDS-EVENT-0087"),
        "wrong-source-arn": _pattern(db_arn, source_arn=ghost_arn),
        "snapshot-detail-type": _pattern(db_arn, detail_type="RDS DB Snapshot Event"),
    }
    good_rule = ctx.unique_name("sim2real-xsvc-rds1-rule-")
    good_url = _rule_to_queue(ctx, est, ev, sqs, good_rule, good)
    probes = {}
    for label, pattern in near_miss.items():
        rule = ctx.unique_name("sim2real-xsvc-rds1-rule-")
        probes[label] = (rule, _rule_to_queue(ctx, est, ev, sqs, rule, pattern))

    _create_instance(ctx, est, rds, ec2, db_id)
    _wait_available(rds, db_id, 1200)

    # ---- positive control: the matching rule receives the post-reboot event ------------ #
    cutoff = _server_time(rds.reboot_db_instance(DBInstanceIdentifier=db_id)) - timedelta(seconds=1)
    got = _await_post(sqs, good_url, cutoff, DELIVERY_BUDGET_S)
    assert got, (
        f"the exactly-matching rule received no {EVENT_ID} dated after the reboot "
        f"({cutoff.isoformat()}) within {DELIVERY_BUDGET_S}s, so no absence could be attributed "
        f"to a pattern"
    )
    _drain_empty(sqs, good_url)

    # ---- the effect is absent on every near-miss queue ---------------------------------- #
    for label, (_rule, url) in probes.items():
        leaked = _receive(sqs, url, wait=20)
        assert leaked == [], (
            f"near-miss rule {label!r} ({near_miss[label]!r}) delivered {len(leaked)} "
            f"event(s): {leaked[:2]!r}"
        )
        depth = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=[
            "ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"])["Attributes"]
        assert depth == {"ApproximateNumberOfMessages": "0",
                         "ApproximateNumberOfMessagesNotVisible": "0"}, (
            f"near-miss rule {label!r}'s queue reports {depth!r}, not empty"
        )

    # ---- repair the one broken field; the SAME queues must now receive ----------------- #
    for rule, _url in probes.values():
        ev.put_rule(Name=rule, EventPattern=json.dumps(good), State="ENABLED")
    _wait_available(rds, db_id, 900)
    cutoff2 = _server_time(rds.reboot_db_instance(DBInstanceIdentifier=db_id)) - timedelta(seconds=1)
    for label, (_rule, url) in probes.items():
        arrived = _await_post(sqs, url, cutoff2, DELIVERY_BUDGET_S)
        assert arrived, (
            f"after repairing near-miss rule {label!r} to the matching pattern, its queue received "
            f"no post-reboot {EVENT_ID} within {DELIVERY_BUDGET_S}s — the earlier zero cannot be "
            f"attributed to the pattern"
        )
        d = arrived[0]["detail"]
        assert d.get("SourceArn") == db_arn and d.get("EventID") == EVENT_ID, (
            f"repaired rule {label!r} delivered an unexpected event: {d!r}"
        )

    est.teardown()


def _await_post(sqs, url, cutoff, budget_s) -> list[dict]:
    """Every EVENT_ID event dated at/after `cutoff` received before the first one arrives."""
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        hits = [e for e in (json.loads(b) for b in _receive(sqs, url))
                if e.get("detail", {}).get("EventID") == EVENT_ID
                and _parse(e["detail"].get("Date")) >= cutoff]
        if hits:
            return hits
    return []


def _drain_empty(sqs, url) -> None:
    empties = 0
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and empties < 2:
        empties = empties + 1 if not _receive(sqs, url, wait=5) else 0
    assert empties >= 2, f"control queue {url!r} would not drain to empty inside 120 s"


def _parse(value) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _server_time(resp) -> datetime:
    return parsedate_to_datetime(resp["ResponseMetadata"]["HTTPHeaders"]["date"])


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


class _Estate:
    """Teardown steps run at the end of the body and also registered as cleanups.

    RDS instance and subnet deletion takes minutes, longer than the 60 s cleanup bound, so the
    happy path tears down in the body. Each step runs at most once.
    """

    def __init__(self, ctx):
        self.ctx = ctx
        self.steps = []

    def add(self, fn) -> None:
        box = {"done": False}

        def step():
            if box["done"]:
                return
            box["done"] = True
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - teardown reports, never raises
                print(f"{CHECK}: teardown step failed: {exc!r}")

        self.steps.append(step)
        self.ctx.on_cleanup(step)

    def teardown(self) -> None:
        while self.steps:
            self.steps.pop()()


def _rule_to_queue(ctx, est, ev, sqs, rule, pattern) -> str:
    rule_arn = ev.put_rule(Name=rule, EventPattern=json.dumps(pattern), State="ENABLED",
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["RuleArn"]
    est.add(lambda: ev.delete_rule(Name=rule))
    url = _queue(ctx, est, sqs, rule_arn)
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    resp = ev.put_targets(Rule=rule, Targets=[{"Id": "q", "Arn": arn}])
    est.add(lambda: ev.remove_targets(Rule=rule, Ids=["q"]))
    assert resp["FailedEntryCount"] == 0, f"put_targets failed: {resp.get('FailedEntries')!r}"
    return url


def _queue(ctx, est, sqs, rule_arn) -> str:
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-rds1-q-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    est.add(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowEventBridgeRule", "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    })})
    return url


def _receive(sqs, url, wait: int = 10) -> list[str]:
    msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                               WaitTimeSeconds=wait).get("Messages", [])
    if msgs:
        sqs.delete_message_batch(QueueUrl=url, Entries=[
            {"Id": str(i), "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)])
    return [m["Body"] for m in msgs]


def _create_instance(ctx, est, rds, ec2, db_id) -> None:
    """A private VPC + two-AZ subnet group the check owns, then the instance in it."""
    version = rds.describe_db_engine_versions(Engine="postgres", DefaultOnly=True)["DBEngineVersions"][0]["EngineVersion"]
    offered = {az["Name"]
               for page in rds.get_paginator("describe_orderable_db_instance_options").paginate(
                   Engine="postgres", EngineVersion=version, DBInstanceClass=DB_CLASS)
               for o in page["OrderableDBInstanceOptions"] for az in o["AvailabilityZones"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert len(usable) >= 2, f"need two AZs offering {DB_CLASS} postgres {version}; got {usable!r}"

    name = ctx.unique_name("sim2real-xsvc-rds1-net-")
    tag_spec = lambda kind: [{"ResourceType": kind, "Tags": [  # noqa: E731
        {"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": CHECK}]}]
    vpc = ec2.create_vpc(CidrBlock="10.71.0.0/16", TagSpecifications=tag_spec("vpc"))["Vpc"]["VpcId"]
    est.add(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc)))
    subnets = []
    for i, az in enumerate(usable[:2]):
        sn = ec2.create_subnet(VpcId=vpc, CidrBlock=f"10.71.{i}.0/24", AvailabilityZone=az,
                               TagSpecifications=tag_spec("subnet"))["Subnet"]["SubnetId"]
        est.add(lambda sn=sn: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=sn)))
        subnets.append(sn)
    rds.create_db_subnet_group(DBSubnetGroupName=name, DBSubnetGroupDescription="sim2real xsvc",
                               SubnetIds=subnets, Tags=[{"Key": "sim2real", "Value": CHECK}])
    est.add(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))

    rds.create_db_instance(
        DBInstanceIdentifier=db_id, Engine="postgres", EngineVersion=version,
        DBInstanceClass=DB_CLASS, AllocatedStorage=20, MasterUsername="s2radmin",
        MasterUserPassword=_rand_password(), DBSubnetGroupName=name, PubliclyAccessible=False,
        MultiAZ=False, BackupRetentionPeriod=0, Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    est.add(lambda: _delete_instance(rds, db_id))


def _retry_dependency(fn, budget_s: int = 300) -> None:
    deadline = time.monotonic() + budget_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_instance(rds, db_id, budget_s: int = 1200) -> None:
    deadline = time.monotonic() + budget_s
    while True:
        try:
            rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True,
                                   DeleteAutomatedBackups=True)
            break
        except ClientError as exc:
            if _code(exc) == "DBInstanceNotFound":
                return
            if _code(exc) != "InvalidDBInstanceState" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=db_id)
        except ClientError as exc:
            if _code(exc) == "DBInstanceNotFound":
                return
            raise
        time.sleep(2)
    raise RuntimeError(f"instance {db_id} still present {budget_s}s after delete")


def _wait_available(rds, db_id, timeout_s: int) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == "available":
            return last
        time.sleep(2)
    raise AssertionError(
        f"instance {db_id} never became available within {timeout_s}s; last status "
        f"{last and last['DBInstanceStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
