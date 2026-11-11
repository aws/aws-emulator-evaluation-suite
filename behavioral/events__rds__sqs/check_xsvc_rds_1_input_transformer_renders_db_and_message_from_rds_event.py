"""xsvc-rds-1-input-transformer-renders-db-and-message-from-rds-event."""
from __future__ import annotations

import json
import secrets
import string
import time
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-rds-1-input-transformer-renders-db-and-message-from-rds-event"
GROUP = 'event-routing'
SERVICES = ['events', 'rds', 'sqs']

DB_CLASS = "db.t4g.micro"
EVENT_ID = "RDS-EVENT-0006"
MESSAGE = "DB instance restarted"
DELIVERY_BUDGET_S = 600
PATHS = {"db": "$.detail.SourceIdentifier", "msg": "$.detail.Message"}
#: A quoted plain-text template: EventBridge substitutes the paths and delivers the string
#: WITH its surrounding quotes.
TEMPLATE = '"<db> :: <msg>"'


@tags("axis:happy-path", "cap:c4", "concern:eventing", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An InputTransformer target receives '<db> :: <msg>' rendered from a real RDS reboot event.

    A raw sibling target on the same rule shows the event's fields, so the expected body is
    derived from the event the transformer saw; the transformed queue gets only that string.
    """
    rds = ctx.client("rds")
    ev = ctx.client("events")
    sqs = ctx.client("sqs")
    ec2 = ctx.client("ec2")
    ident = ctx.client("sts").get_caller_identity()
    account, partition = ident["Account"], ident["Arn"].split(":")[1]

    db_id = ctx.unique_name("sim2real-xsvc-rds1-")
    db_arn = f"arn:{partition}:rds:{ctx.region}:{account}:db:{db_id}"
    est = _Estate(ctx)

    rule = ctx.unique_name("sim2real-xsvc-rds1-rule-")
    pattern = {"source": ["aws.rds"], "detail-type": ["RDS DB Instance Event"],
               "detail": {"EventID": [EVENT_ID], "SourceArn": [db_arn]}}
    raw_url = _rule_to_queue(ctx, est, ev, sqs, rule, pattern)
    rule_arn = ev.describe_rule(Name=rule)["Arn"]
    xf_url = _queue(ctx, est, sqs, rule_arn)
    xf_arn = sqs.get_queue_attributes(QueueUrl=xf_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    resp = ev.put_targets(Rule=rule, Targets=[{
        "Id": "xf", "Arn": xf_arn,
        "InputTransformer": {"InputPathsMap": dict(PATHS), "InputTemplate": TEMPLATE}}])
    est.add(lambda: ev.remove_targets(Rule=rule, Ids=["xf"]))
    assert resp["FailedEntryCount"] == 0, f"put_targets failed: {resp.get('FailedEntries')!r}"
    listed = {t["Id"]: t for t in ev.list_targets_by_rule(Rule=rule)["Targets"]}
    assert set(listed) == {"q", "xf"} and "InputTransformer" not in listed["q"], (
        f"rule targets are {listed!r}; expected one raw and one transformed queue"
    )

    _create_instance(ctx, est, rds, ec2, db_id)
    _wait_available(rds, db_id, _budget_s(ctx, 1200), ctx=ctx)
    cutoff = _server_time(rds.reboot_db_instance(DBInstanceIdentifier=db_id)) - timedelta(seconds=1)

    # ---- the raw sibling: a post-reboot RDS-EVENT-0006 fired, and these are its fields ---- #
    raw_hit = None
    raw_budget = _budget_s(ctx, DELIVERY_BUDGET_S)
    deadline = time.monotonic() + raw_budget
    while time.monotonic() < deadline and raw_hit is None:
        for body in _receive(sqs, raw_url):
            d = json.loads(body).get("detail", {})
            if d.get("EventID") == EVENT_ID and _parse(d.get("Date")) >= cutoff:
                raw_hit = d
    if raw_hit is None and _budget_spent(ctx):
        raise TimeoutError(f"a post-reboot {EVENT_ID} on the raw target: the run budget ended first; not graded")
    assert raw_hit is not None, (
        f"the raw target received no post-reboot {EVENT_ID} within {raw_budget:.0f}s, so the "
        f"transformed queue cannot be graded"
    )
    assert raw_hit.get("SourceIdentifier") == db_id and raw_hit.get("Message") == MESSAGE, (
        f"raw event identifier/message were {raw_hit.get('SourceIdentifier')!r}/"
        f"{raw_hit.get('Message')!r}"
    )
    expected = f'"{db_id} :: {MESSAGE}"'

    # ---- the transformed sibling: exactly the rendered template, nothing else ---------- #
    bodies: list[str] = []
    xf_budget = _budget_s(ctx, 180)
    deadline = time.monotonic() + xf_budget
    while time.monotonic() < deadline and expected not in bodies:
        bodies += _receive(sqs, xf_url)
    if expected not in bodies and _budget_spent(ctx):
        raise TimeoutError(f"{expected!r} on the transformed queue: the run budget ended first; not graded")
    assert expected in bodies, (
        f"the InputTransformer target never delivered {expected!r} within {xf_budget:.0f} s of the raw "
        f"sibling; it delivered {bodies[:3]!r}"
    )
    wrong = [b for b in bodies if b != expected]
    assert wrong == [], (
        f"the transformed queue received bodies other than the rendered template: {wrong[:3]!r}"
    )
    est.teardown()


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _receive(sqs, url, wait: int = 2) -> list[str]:
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


def _wait_available(rds, db_id, timeout_s: int, ctx=None) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == "available":
            return last
        time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"instance {db_id} becoming available: the run budget ended first; not graded")
    raise AssertionError(
        f"instance {db_id} never became available within {timeout_s}s; last status "
        f"{last and last['DBInstanceStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
