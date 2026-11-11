"""xsvc-ecs-2-ecs-target-without-passrole-dead-letters-the-event-and-launches-no-task."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-ecs-2-ecs-target-without-passrole-dead-letters-the-event-and-launches-no-task"
GROUP = "event-propagation"
SERVICES = ["ecs", "events", "logs", "sqs"]

_SOURCE = "sim2real.xsvc.ecs2"
_DETAIL_TYPE = "sim2real launch request"
_IMAGE = "public.ecr.aws/docker/library/busybox:latest"
_CONTAINER = "work"
_PROOF_WAIT_S = 600.0
_DLQ_WAIT_S = 180.0
_REPUBLISH_S = 60.0
_GOOD, _BAD = "sim2real-good", "sim2real-bad"
_EXPECTED_ERROR_CODE = "NO_PERMISSIONS"


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Of two ECS targets differing only in iam:PassRole, the control launches a task and dead-letters
    nothing, while the target without PassRole launches nothing and dead-letters the transformed
    input with ERROR_CODE NO_PERMISSIONS and RULE_ARN / TARGET_ARN naming this rule and cluster."""
    ecs, events, sqs = (ctx.client(s) for s in ("ecs", "events", "sqs"))
    account = ctx.client("sts").get_caller_identity()["Account"]

    net = _network(ctx)
    cluster = _xname(ctx, "cl")[:255]
    cluster_arn = ecs.create_cluster(
        clusterName=cluster, tags=[{"key": k, "value": v} for k, v in _TAGS.items()]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drop(lambda: ecs.delete_cluster(cluster=cluster)))
    ctx.on_cleanup(lambda: _stop_all_tasks(ctx, cluster))

    log_group = f"/{_xname(ctx, 'lg')}"[:512]
    ctx.client("logs").create_log_group(logGroupName=log_group, tags=dict(_TAGS))
    ctx.on_cleanup(lambda: _drop(lambda: ctx.client("logs").delete_log_group(logGroupName=log_group)))

    exec_role_arn = _execution_role(ctx)
    family = _xname(ctx, "td")[:255]
    td_arn = _task_definition(ctx, family, exec_role_arn, log_group)
    good_role = _events_role(ctx, account, family, cluster_arn, exec_role_arn, pass_role=True)
    bad_role = _events_role(ctx, account, family, cluster_arn, exec_role_arn, pass_role=False)

    rule = _xname(ctx, "rule")[:64]
    rule_arn = events.put_rule(
        Name=rule, EventPattern=json.dumps({"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _delete_rule(ctx, rule, ["good", "bad"]))
    dlq = {label: _create_dlq(ctx, rule_arn) for label in ("good", "bad")}

    good_t = _ecs_target("good", cluster_arn, good_role, td_arn, net, marker=_GOOD)
    bad_t = _ecs_target("bad", cluster_arn, bad_role, td_arn, net, marker=_BAD)
    good_t["DeadLetterConfig"] = {"Arn": dlq["good"]["arn"]}
    bad_t["DeadLetterConfig"] = {"Arn": dlq["bad"]["arn"]}
    resp = events.put_targets(Rule=rule, Targets=[good_t, bad_t])
    assert resp["FailedEntryCount"] == 0, f"PutTargets rejected the targets: {resp['FailedEntries']!r}"

    published: list[str] = []
    found = None
    deadline = time.monotonic() + _PROOF_WAIT_S
    last_put = 0.0
    while found is None and time.monotonic() < deadline:
        if time.monotonic() - last_put > _REPUBLISH_S:
            token = uuid.uuid4().hex[:16]
            put = events.put_events(Entries=[{"Source": _SOURCE, "DetailType": _DETAIL_TYPE,
                                              "Detail": json.dumps({"token": token})}])
            assert put["FailedEntryCount"] == 0, f"PutEvents rejected the launch request: {put!r}"
            published.append(token)
            last_put = time.monotonic()
        found = _find_proof_line(ctx, log_group, published, marker=_GOOD)
        if found is None:
            time.sleep(5)
    assert found is not None, (
        f"positive control: the target WITH iam:PassRole never logged '{_GOOD}-<token>' within "
        f"{_PROOF_WAIT_S}s over {len(published)} event(s); tasks: {_task_summary(ctx, cluster)!r}"
    )
    barrier = found["token"]

    # The SAME event, fanned to the broken target, must be dead-lettered there.
    letters: dict[str, list[dict]] = {"good": [], "bad": []}

    def _drain_dlqs():
        for label, q in dlq.items():
            r = sqs.receive_message(QueueUrl=q["url"], MaxNumberOfMessages=10, WaitTimeSeconds=2,
                                    MessageAttributeNames=["All"])
            for m in r.get("Messages", []):
                sqs.delete_message(QueueUrl=q["url"], ReceiptHandle=m["ReceiptHandle"])
                letters[label].append(m)
        return letters

    def _rendered(label: str, token: str) -> dict:
        marker = _GOOD if label == "good" else _BAD
        return {"containerOverrides": [{"name": _CONTAINER, "command": ["sh", "-c", f"echo {marker}-{token}"]}]}

    def _for(label: str, token: str) -> list[dict]:
        return [m for m in letters[label] if json.loads(m["Body"]) == _rendered(label, token)]

    _poll_until(_drain_dlqs, lambda _l: _for("bad", barrier), timeout_s=_DLQ_WAIT_S, interval_s=0.5,
                description=f"the broken target's DLQ receives the event carrying token {barrier!r}")
    settle = time.monotonic() + 20
    while time.monotonic() < settle:
        _drain_dlqs()

    letter = _for("bad", barrier)[0]
    body = json.loads(letter["Body"])
    attrs = {k: v.get("StringValue") for k, v in letter.get("MessageAttributes", {}).items()}
    assert body == _rendered("bad", barrier), (
        f"the dead letter's body must be the target's transformed input for token {barrier!r}, got {body!r}"
    )
    unexpected = [json.loads(m["Body"]) for m in letters["bad"]
                  if json.loads(m["Body"]) not in [_rendered("bad", t) for t in published]]
    assert unexpected == [], f"the broken target's DLQ received bodies for no published event: {unexpected!r}"
    assert attrs.get("RULE_ARN") == rule_arn, f"RULE_ARN attribute {attrs.get('RULE_ARN')!r} != {rule_arn!r}"
    assert attrs.get("TARGET_ARN") == cluster_arn, (
        f"TARGET_ARN attribute {attrs.get('TARGET_ARN')!r} != the cluster {cluster_arn!r}"
    )
    assert attrs.get("ERROR_CODE") == _EXPECTED_ERROR_CODE, (
        f"ERROR_CODE attribute was {attrs.get('ERROR_CODE')!r}, expected {_EXPECTED_ERROR_CODE!r}; "
        f"all attributes {attrs!r}"
    )
    assert _for("good", barrier) == [], (
        f"the control target launched a task for {barrier!r} yet its DLQ also received that event: "
        f"{[m.get('MessageAttributes') for m in _for('good', barrier)]!r}"
    )

    bad_line = _find_proof_line(ctx, log_group, published, marker=_BAD)
    assert bad_line is None, f"the target whose role lacks iam:PassRole launched a task that logged {bad_line!r}"
    bad_tasks = [t["taskArn"] for t in _list_tasks(ctx, cluster) if _BAD in json.dumps(t.get("overrides", {}))]
    assert bad_tasks == [], f"tasks launched for the role without iam:PassRole: {bad_tasks!r}"


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}
_TEARDOWN_S = 300.0


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


_GONE = {"ResourceNotFoundException", "NoSuchEntity", "ClusterNotFoundException", "Gateway.NotAttached"}


def _drop(fn, *retry: str) -> None:
    """Run one teardown call: done on success or a not-found code; retry the `retry` codes
    (ENIs detaching) every 2 s up to _TEARDOWN_S; raise every other failure."""
    deadline = time.monotonic() + _TEARDOWN_S
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _GONE or code.endswith("NotFound"):
                return
            if code not in retry or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _ec2_tags(ctx, resource_type: str, kind: str) -> list[dict]:
    tags = [{"Key": "Name", "Value": _xname(ctx, kind)}, {"Key": "sim2real", "Value": CHECK[:200]}]
    tags += [{"Key": k, "Value": v} for k, v in _TAGS.items()]
    return [{"ResourceType": resource_type, "Tags": tags}]


def _network(ctx) -> dict[str, str]:
    """A private VPC with one public subnet in a derived AZ, an IGW route and an egress-only SG.
    Created here: a fresh account may have no default VPC."""
    ec2 = ctx.client("ec2")
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert zones, f"region {ctx.region} reports no available availability zone"
    vpc = ec2.create_vpc(CidrBlock="10.79.0.0/16",
                         TagSpecifications=_ec2_tags(ctx, "vpc", "vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _drop(lambda: ec2.delete_vpc(VpcId=vpc), "DependencyViolation"))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    igw = ec2.create_internet_gateway(
        TagSpecifications=_ec2_tags(ctx, "internet-gateway", "igw"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _drop(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw), "DependencyViolation"))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _drop(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc), "DependencyViolation"))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.79.1.0/24", AvailabilityZone=zones[0],
                               TagSpecifications=_ec2_tags(ctx, "subnet", "sn"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _drop(lambda: ec2.delete_subnet(SubnetId=subnet), "DependencyViolation"))
    rt = ec2.create_route_table(VpcId=vpc, TagSpecifications=_ec2_tags(ctx, "route-table", "rt"))[
        "RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _drop(lambda: ec2.delete_route_table(RouteTableId=rt), "DependencyViolation"))
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=rt, SubnetId=subnet)["AssociationId"]
    ctx.on_cleanup(lambda: _drop(lambda: ec2.disassociate_route_table(AssociationId=assoc)))
    sg = ec2.create_security_group(
        GroupName=_xname(ctx, "sg")[:255], Description="sim2real-xsvc egress-only task SG", VpcId=vpc,
        TagSpecifications=_ec2_tags(ctx, "security-group", "sg"))["GroupId"]
    ctx.on_cleanup(lambda: _drop(lambda: ec2.delete_security_group(GroupId=sg), "DependencyViolation"))
    return {"vpc": vpc, "subnet": subnet, "sg": sg}


def _role(ctx, kind: str, service: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = _xname(ctx, kind)[:64]
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop(lambda: iam.delete_role(RoleName=name)))
    return name, arn


def _execution_role(ctx) -> str:
    """The task execution role: lets the awslogs driver write to CloudWatch Logs."""
    iam = ctx.client("iam")
    name, arn = _role(ctx, "exec", "ecs-tasks.amazonaws.com")
    policy = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(lambda: _drop(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy)))
    return arn


def _events_role(ctx, account: str, family: str, cluster_arn: str, exec_role_arn: str,
                 pass_role: bool) -> str:
    """The rule target's role: ecs:RunTask on this family in this cluster, and (only when asked)
    iam:PassRole on the task's execution role. Nothing else differs between the two variants."""
    iam = ctx.client("iam")
    name, arn = _role(ctx, "evrole", "events.amazonaws.com")
    statements = [{"Effect": "Allow", "Action": "ecs:RunTask",
                   "Resource": f"arn:aws:ecs:{ctx.region}:{account}:task-definition/{family}:*",
                   "Condition": {"ArnEquals": {"ecs:cluster": cluster_arn}}}]
    if pass_role:
        statements.append({"Effect": "Allow", "Action": "iam:PassRole", "Resource": exec_role_arn,
                           "Condition": {"StringLike": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}})
    iam.put_role_policy(RoleName=name, PolicyName="runtask",
                        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
    ctx.on_cleanup(lambda: _drop(lambda: iam.delete_role_policy(RoleName=name, PolicyName="runtask")))
    return arn


def _task_definition(ctx, family: str, exec_role_arn: str, log_group: str) -> str:
    ecs = ctx.client("ecs")
    arn = ecs.register_task_definition(
        family=family, requiresCompatibilities=["FARGATE"], networkMode="awsvpc", cpu="256", memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[{
            "name": _CONTAINER, "image": _IMAGE, "essential": True,
            "command": ["sh", "-c", "echo sim2real-proof-unset"],
            "logConfiguration": {"logDriver": "awslogs", "options": {
                "awslogs-group": log_group, "awslogs-region": ctx.region, "awslogs-stream-prefix": "proof"}},
        }],
        tags=[{"key": k, "value": v} for k, v in _TAGS.items()],
    )["taskDefinition"]["taskDefinitionArn"]

    def _deregister():
        _drop(lambda: ecs.deregister_task_definition(taskDefinition=arn))
        _drop(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))

    ctx.on_cleanup(_deregister)
    return arn


def _ecs_target(target_id: str, cluster_arn: str, role_arn: str, td_arn: str, net: dict,
                marker: str = "sim2real-proof") -> dict:
    return {
        "Id": target_id, "Arn": cluster_arn, "RoleArn": role_arn,
        "EcsParameters": {
            "TaskDefinitionArn": td_arn, "TaskCount": 1, "LaunchType": "FARGATE",
            "NetworkConfiguration": {"awsvpcConfiguration": {
                "Subnets": [net["subnet"]], "SecurityGroups": [net["sg"]], "AssignPublicIp": "ENABLED"}},
        },
        "InputTransformer": {
            "InputPathsMap": {"tok": "$.detail.token"},
            "InputTemplate": json.dumps({"containerOverrides": [{
                "name": _CONTAINER, "command": ["sh", "-c", f"echo {marker}-TOKPLACEHOLDER"]}]}
            ).replace("TOKPLACEHOLDER", "<tok>"),
        },
        "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
    }


def _delete_rule(ctx, rule: str, target_ids: list[str]) -> None:
    events = ctx.client("events")
    _drop(lambda: events.remove_targets(Rule=rule, Ids=target_ids, Force=True))
    _drop(lambda: events.delete_rule(Name=rule, Force=True))


def _list_tasks(ctx, cluster: str) -> list[dict]:
    ecs = ctx.client("ecs")
    arns: list[str] = []
    for status in ("RUNNING", "STOPPED"):
        for page in ecs.get_paginator("list_tasks").paginate(cluster=cluster, desiredStatus=status):
            arns.extend(page["taskArns"])
    out: list[dict] = []
    for i in range(0, len(arns), 100):
        out.extend(ecs.describe_tasks(cluster=cluster, tasks=arns[i:i + 100])["tasks"])
    return out


def _task_summary(ctx, cluster: str) -> list:
    return [(t["taskArn"].rsplit("/", 1)[-1], t.get("lastStatus"), t.get("stoppedReason"))
            for t in _list_tasks(ctx, cluster)]


def _stop_all_tasks(ctx, cluster: str) -> None:
    ecs = ctx.client("ecs")
    for t in _list_tasks(ctx, cluster):
        if t.get("lastStatus") != "STOPPED":
            _drop(lambda a=t["taskArn"]: ecs.stop_task(cluster=cluster, task=a))
    deadline = time.monotonic() + _TEARDOWN_S
    while time.monotonic() < deadline:
        if all(t.get("lastStatus") == "STOPPED" for t in _list_tasks(ctx, cluster)):
            return
        time.sleep(2)
    raise RuntimeError(f"tasks in cluster {cluster} did not all stop")


def _find_proof_line(ctx, log_group: str, tokens: list[str], marker: str = "sim2real-proof") -> dict | None:
    """The first awslogs event whose message is '<marker>-<token>' for a token we published."""
    logs = ctx.client("logs")
    wanted = {f"{marker}-{t}": t for t in tokens}
    kwargs = {"logGroupName": log_group, "filterPattern": f'"{marker}-"'}
    while True:
        page = logs.filter_log_events(**kwargs)
        for ev in page.get("events", []):
            tok = wanted.get(ev["message"].strip())
            if tok is not None:
                return {**ev, "token": tok}
        if not page.get("nextToken"):
            return None
        kwargs["nextToken"] = page["nextToken"]


def _create_dlq(ctx, rule_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = _xname(ctx, "dlq")[:80]
    url = sqs.create_queue(QueueName=name, tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})
    return {"url": url, "arn": arn}


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
