"""events-workload-state-change-batch-failed-event-carries-exit-code-and-attempts-only-on-failed-rule."""

from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import tarfile
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-workload-state-change-batch-failed-event-carries-exit-code-and-attempts-only-on-failed-rule"
GROUP = "event-propagation"
SERVICES = ["batch", "events", "sqs"]

_SOURCE = "aws.batch"
_DETAIL_TYPE = "Batch Job State Change"
_WARMUP_SOURCE = "sim2real.warmup"
_FAIL_CODE = 9
_READY_S = 300.0
_JOB_TERMINAL_S = 600.0
_EVENT_WAIT_S = 180.0
_MIN_SETTLE_S = 30.0
_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Of two Fargate Batch jobs differing only in exit code (9 and 0), each terminal Job State
    Change event reaches only its own FAILED or SUCCEEDED rule, and the FAILED event carries the
    real container exitCode and attempts equal to DescribeJobs, so a fabricated event fails."""
    bat = ctx.client("batch")
    token = ctx.unique_name("w")[-12:]
    streams: list[str] = []
    ctx.on_cleanup(lambda: _delete_log_streams(ctx, streams))

    net = _network(ctx)
    exec_role = _execution_role(ctx)
    jq_name, jq_arn, teardown_batch = _fargate_queue(ctx, bat, net)

    scope = {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE], "detail": {"jobQueue": [jq_arn]}}
    queues: dict[str, dict] = {}
    for status in ("FAILED", "SUCCEEDED"):
        pattern = json.loads(json.dumps(scope))
        pattern["detail"]["status"] = [status]
        queues[status] = _create_queue(ctx)
        _rule_to_queue(ctx, {"$or": [pattern, {"source": [_WARMUP_SOURCE],
                                                "detail": {"token": [f"{token}-{status}"]}}]},
                       queues[status])
    _warm_up(ctx, {s: q["url"] for s, q in queues.items()}, token)

    jd_name = _xname(ctx, "jd")[:128]
    jd = bat.register_job_definition(
        jobDefinitionName=jd_name, type="container", platformCapabilities=["FARGATE"],
        retryStrategy={"attempts": 1},
        containerProperties={
            "image": _target_image(ctx, "busybox"), "command": ["sh", "-c", "sleep 3; exit 0"],
            "executionRoleArn": exec_role,
            "resourceRequirements": [{"type": "VCPU", "value": "0.25"}, {"type": "MEMORY", "value": "512"}],
            "networkConfiguration": {"assignPublicIp": "ENABLED"},
        },
        tags=dict(_TAGS),
    )
    ctx.on_cleanup(lambda: _cleanup_call(lambda: bat.deregister_job_definition(jobDefinition=jd["jobDefinitionArn"])))
    ctx.on_cleanup(lambda: _purge_batch_task_definitions(ctx, jd_name))

    jobs: dict[str, str] = {}
    for status, code in (("FAILED", _FAIL_CODE), ("SUCCEEDED", 0)):
        jid = bat.submit_job(
            jobName=_xname(ctx, "job")[:128], jobQueue=jq_name, jobDefinition=jd["jobDefinitionArn"],
            containerOverrides={"command": ["sh", "-c", f"sleep 3; exit {code}"]},
        )["jobId"]
        jobs[status] = jid
        ctx.on_cleanup(lambda j=jid: _cleanup_call(lambda: bat.terminate_job(jobId=j, reason="sim2real cleanup")))

    t0 = time.monotonic()
    described: dict[str, dict] = {}
    for status, jid in jobs.items():
        described[status] = _poll_until(
            lambda j=jid: bat.describe_jobs(jobs=[j])["jobs"][0],
            lambda j: j["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=_JOB_TERMINAL_S, interval_s=5,
            description=f"job {jid} reaches a terminal status",
        )
        for att in described[status].get("attempts") or []:
            if (att.get("container") or {}).get("logStreamName"):
                streams.append(att["container"]["logStreamName"])
    run_s = time.monotonic() - t0
    assert described["FAILED"]["status"] == "FAILED", (
        f"the job exiting {_FAIL_CODE} must be FAILED per DescribeJobs, got "
        f"{described['FAILED']['status']!r} ({described['FAILED'].get('statusReason')!r})"
    )
    assert described["SUCCEEDED"]["status"] == "SUCCEEDED", (
        f"the job exiting 0 must be SUCCEEDED per DescribeJobs, got "
        f"{described['SUCCEEDED']['status']!r} ({described['SUCCEEDED'].get('statusReason')!r})"
    )

    sinks: dict[str, list[dict]] = {s: [] for s in queues}

    def _of(queue_status: str, job_status: str) -> list[dict]:
        return [b for b in sinks[queue_status] if b["detail"].get("jobId") == jobs[job_status]]

    def _drain_all():
        for s, q in queues.items():
            _drain_once(ctx, q["url"], sinks[s])
        return sinks

    _poll_until(
        _drain_all,
        lambda _s: _of("FAILED", "FAILED") and _of("SUCCEEDED", "SUCCEEDED"),
        timeout_s=_EVENT_WAIT_S, interval_s=0.5,
        description="the FAILED rule receives the failing job and the SUCCEEDED rule the passing one",
    )
    settle_until = time.monotonic() + max(_MIN_SETTLE_S, 0.5 * run_s)
    while time.monotonic() < settle_until:
        _drain_all()

    assert _of("SUCCEEDED", "FAILED") == [], (
        f"the SUCCEEDED-status rule received {len(_of('SUCCEEDED', 'FAILED'))} event(s) for the job "
        f"that exited {_FAIL_CODE}: statuses {[b['detail'].get('status') for b in _of('SUCCEEDED', 'FAILED')]!r}"
    )
    assert _of("FAILED", "SUCCEEDED") == [], (
        f"the FAILED-status rule received an event for the job that exited 0: statuses "
        f"{[b['detail'].get('status') for b in _of('FAILED', 'SUCCEEDED')]!r}"
    )
    for s in queues:
        wrong = [(b["detail"].get("jobId"), b["detail"].get("status")) for b in sinks[s]
                 if b["detail"].get("jobId") not in jobs.values() or b["detail"].get("status") != s]
        assert wrong == [], f"the {s} rule received events outside its own status/jobs: {wrong!r}"

    body = _of("FAILED", "FAILED")[-1]
    detail, d = body["detail"], described["FAILED"]
    assert body["resources"] == [d["jobArn"]], (
        f"envelope resources must be exactly the job ARN {d['jobArn']!r}, got {body['resources']!r}"
    )
    assert detail["statusReason"] == d["statusReason"], (
        f"event statusReason {detail.get('statusReason')!r} must equal DescribeJobs {d.get('statusReason')!r}"
    )
    assert (detail.get("container") or {}).get("exitCode") == d["container"].get("exitCode") == _FAIL_CODE, (
        f"event container.exitCode {(detail.get('container') or {}).get('exitCode')!r} must equal "
        f"DescribeJobs {d['container'].get('exitCode')!r} and the real exit status {_FAIL_CODE}"
    )
    ev_attempts, api_attempts = detail.get("attempts") or [], d.get("attempts") or []
    assert len(ev_attempts) == len(api_attempts) == 1, (
        f"retryStrategy attempts=1 means exactly one attempt record in both the event "
        f"({len(ev_attempts)}) and DescribeJobs ({len(api_attempts)})"
    )
    ea, aa = ev_attempts[0], api_attempts[0]
    assert (ea.get("container") or {}).get("exitCode") == (aa.get("container") or {}).get("exitCode") == _FAIL_CODE, (
        f"attempts[0].container.exitCode: event {(ea.get('container') or {}).get('exitCode')!r}, "
        f"DescribeJobs {(aa.get('container') or {}).get('exitCode')!r}, expected {_FAIL_CODE}"
    )
    assert (ea.get("startedAt"), ea.get("stoppedAt"), ea.get("statusReason")) == (
        aa.get("startedAt"), aa.get("stoppedAt"), aa.get("statusReason")), (
        f"the event's attempt record must equal DescribeJobs': event "
        f"{(ea.get('startedAt'), ea.get('stoppedAt'), ea.get('statusReason'))!r}, api "
        f"{(aa.get('startedAt'), aa.get('stoppedAt'), aa.get('statusReason'))!r}"
    )
    assert isinstance(ea.get("startedAt"), int) and ea["stoppedAt"] >= ea["startedAt"], (
        f"the attempt must carry integer startedAt <= stoppedAt, got {ea.get('startedAt')!r}..{ea.get('stoppedAt')!r}"
    )
    ok = _of("SUCCEEDED", "SUCCEEDED")[-1]["detail"]
    assert (ok.get("container") or {}).get("exitCode") == 0, (
        f"the SUCCEEDED event must carry container.exitCode 0, got {(ok.get('container') or {}).get('exitCode')!r}"
    )

    # Queue -> compute-environment deletion is serial and slower than the engine's cleanup budget,
    # so it runs here, inside the body's budget; the registered cleanups are idempotent fallbacks.
    teardown_batch()


_XSVC_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}
_TEARDOWN_S = 240.0


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _cleanup_call(fn) -> str | None:
    """Run one best-effort teardown call; return its error code, or None when the call succeeded.

    Teardown only: no assertion reads its result, so a success here is the expected outcome.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


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


def _execution_role(ctx) -> str:
    """A per-run ECS task execution role (image pull + awslogs) for the Fargate job."""
    iam = ctx.client("iam")
    name = _xname(ctx, "exec")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]

    def _delete(n=name):
        _cleanup_call(lambda: iam.detach_role_policy(RoleName=n, PolicyArn=_EXEC_POLICY))
        code = _cleanup_call(lambda: iam.delete_role(RoleName=n))
        if code not in (None, "NoSuchEntity"):
            raise RuntimeError(f"could not delete role {n}: {code}")

    ctx.on_cleanup(_delete)
    iam.attach_role_policy(RoleName=name, PolicyArn=_EXEC_POLICY)
    return arn


def _fargate_queue(ctx, bat, net: dict):
    """A MANAGED FARGATE compute environment (no idle cost) and an ENABLED queue, both VALID.

    Returns (queue name, queue ARN, teardown). The teardown is registered as a cleanup AND handed
    back so the body can run it within its own budget: DeleteJobQueue must finish before the
    compute environment can go, and that chain regularly outlasts the engine's cleanup deadline.
    """
    ce_name = _xname(ctx, "ce")[:128]
    ce_arn = bat.create_compute_environment(
        computeEnvironmentName=ce_name, type="MANAGED", state="ENABLED",
        computeResources={"type": "FARGATE", "maxvCpus": 2, "subnets": [net["subnet"]],
                          "securityGroupIds": [net["sg"]]},
        tags=dict(_TAGS),
    )["computeEnvironmentArn"]
    jq_name = _xname(ctx, "jq")[:128]
    done: list[bool] = []

    def _gone(describe, delete, what: str, budget_s: float) -> bool:
        deadline = time.monotonic() + budget_s
        while time.monotonic() < deadline:
            items = describe()
            if not items or items[0]["status"] == "DELETED":
                return True
            if items[0]["state"] == "DISABLED" and items[0]["status"] in ("VALID", "INVALID"):
                _cleanup_call(delete)
            time.sleep(3)
        print(f"{what} still present after {budget_s}s")
        return False

    def _teardown() -> None:
        if done:
            return
        # DeleteComputeEnvironment requires DISABLED and no queue referencing it; disable both now.
        _cleanup_call(lambda: bat.update_job_queue(jobQueue=jq_name, state="DISABLED"))
        _cleanup_call(lambda: bat.update_compute_environment(computeEnvironment=ce_name, state="DISABLED"))
        if _gone(lambda: bat.describe_job_queues(jobQueues=[jq_name])["jobQueues"],
                 lambda: bat.delete_job_queue(jobQueue=jq_name), f"job queue {jq_name}", 120.0):
            if _gone(lambda: bat.describe_compute_environments(computeEnvironments=[ce_name])["computeEnvironments"],
                     lambda: bat.delete_compute_environment(computeEnvironment=ce_name),
                     f"compute environment {ce_name}", 120.0):
                done.append(True)

    ctx.on_cleanup(_teardown)
    ce = _poll_until(
        lambda: bat.describe_compute_environments(computeEnvironments=[ce_name])["computeEnvironments"][0],
        lambda c: c["status"] in ("VALID", "INVALID"), timeout_s=_READY_S, interval_s=5,
        description=f"compute environment {ce_name} settles",
    )
    assert ce["status"] == "VALID", f"compute environment {ce_name} is {ce['status']!r}: {ce.get('statusReason')!r}"

    jq_arn = bat.create_job_queue(
        jobQueueName=jq_name, state="ENABLED", priority=1,
        computeEnvironmentOrder=[{"order": 1, "computeEnvironment": ce_arn}], tags=dict(_TAGS),
    )["jobQueueArn"]
    jq = _poll_until(
        lambda: bat.describe_job_queues(jobQueues=[jq_name])["jobQueues"][0],
        lambda q: q["status"] in ("VALID", "INVALID"), timeout_s=_READY_S, interval_s=3,
        description=f"job queue {jq_name} settles",
    )
    assert jq["status"] == "VALID", f"job queue {jq_name} is {jq['status']!r}: {jq.get('statusReason')!r}"
    return jq_name, jq_arn, _teardown


def _purge_batch_task_definitions(ctx, family: str) -> None:
    """Batch registers an ECS task definition per Fargate job definition, named after it; reap it."""
    ecs = ctx.client("ecs")
    for status in ("ACTIVE", "INACTIVE"):
        arns = ecs.list_task_definitions(familyPrefix=family, status=status).get("taskDefinitionArns", [])
        for a in arns:
            if status == "ACTIVE":
                _cleanup_call(lambda x=a: ecs.deregister_task_definition(taskDefinition=x))
            _cleanup_call(lambda x=a: ecs.delete_task_definitions(taskDefinitions=[x]))


def _delete_log_streams(ctx, names: list[str]) -> None:
    """Reap only the /aws/batch/job streams this run's attempts wrote; the group is shared."""
    _leaks: list = []
    logs = ctx.client("logs")
    for n in sorted(set(names)):
        code = _cleanup_call(lambda s=n: logs.delete_log_stream(logGroupName="/aws/batch/job", logStreamName=s))
        if code not in (None, "ResourceNotFoundException"):
            _leaks.append((f"could not delete log stream /aws/batch/job {n}: {code}", None))
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


def _retry_delete(what: str, fn) -> None:
    """Retry a delete through DependencyViolation (ENIs detaching); raise if it never lands."""
    deadline = time.monotonic() + _TEARDOWN_S
    code = "unattempted"
    while time.monotonic() < deadline:
        code = _cleanup_call(fn)
        if code is None or code.endswith("NotFound") or code.endswith(".NotFound"):
            return
        if code != "DependencyViolation":
            break
        time.sleep(10)
    raise RuntimeError(f"could not delete {what}: {code}")


def _ec2_tags(ctx, resource_type: str, kind: str) -> list[dict]:
    tags = [{"Key": "Name", "Value": _xname(ctx, kind)}, {"Key": "sim2real", "Value": CHECK[:200]}]
    tags += [{"Key": k, "Value": v} for k, v in _TAGS.items()]
    return [{"ResourceType": resource_type, "Tags": tags}]


def _network(ctx) -> dict[str, str]:
    """A private VPC with one public subnet in a derived AZ, an IGW route and an egress-only SG.

    Created here rather than borrowed from the account: a fresh account may have no default VPC.
    Every piece is tagged at create time and torn down in reverse order.
    """
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.77.0.0/16",
                         TagSpecifications=_ec2_tags(ctx, "vpc", "vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(f"vpc {vpc}", lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc])

    igw = ec2.create_internet_gateway(
        TagSpecifications=_ec2_tags(ctx, "internet-gateway", "igw"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(f"igw {igw}", lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        f"igw attachment {igw}", lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw, VpcId=vpc)))

    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert zones, f"region {ctx.region} reports no available availability zone"
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.77.1.0/24", AvailabilityZone=zones[0],
                               TagSpecifications=_ec2_tags(ctx, "subnet", "sn"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(f"subnet {subnet}", lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet)))

    rt = ec2.create_route_table(VpcId=vpc, TagSpecifications=_ec2_tags(ctx, "route-table", "rt"))[
        "RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(f"route table {rt}", lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt)))
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=rt, SubnetId=subnet)["AssociationId"]
    ctx.on_cleanup(lambda: _cleanup_call(lambda: ec2.disassociate_route_table(AssociationId=assoc)))

    sg = ec2.create_security_group(
        GroupName=_xname(ctx, "sg")[:255], Description="sim2real-xsvc egress-only task SG", VpcId=vpc,
        TagSpecifications=_ec2_tags(ctx, "security-group", "sg"))["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(f"security group {sg}", lambda: _delete_net(ec2, "delete_security_group", GroupId=sg)))
    return {"vpc": vpc, "subnet": subnet, "sg": sg}


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
        code = _cleanup_call(lambda: events.remove_targets(Rule=n, Ids=["q"], Force=True))
        if code not in (None, "ResourceNotFoundException"):
            _leaks.append((f"could not remove target from rule {n}: {code}", None))
        code = _cleanup_call(lambda: events.delete_rule(Name=n, Force=True))
        if code not in (None, "ResourceNotFoundException"):
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
    deadline = time.monotonic() + 180
    last_put = 0.0
    while pending and time.monotonic() < deadline:
        if time.monotonic() - last_put > 10:
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
    assert not pending, f"rules for {sorted(pending)!r} never delivered their warm-up event within 180s"
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


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that leaked the
# VPC while the check PASSED. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached. Every other error propagates. Teardown-only: nothing run() executes calls this, so it
# cannot change the verdict. The window is shared by all of one check's network deletes.
_NET_TEARDOWN_S = 210.0
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
        _time.sleep(10)
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
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


# ===== target-sourced container image (self-contained) =====
#: Images the tasks run: the reference, its linux/amd64 image ID (the config digest), and the file
#: the runner pre-seeds it as with `docker save`. The check never pulls from a registry.
_SEED_IMAGES = {
    "busybox": (
        "public.ecr.aws/docker/library/busybox:1.36",
        "sha256:b116e155074440ffd9e449559433feb4cd2341eb3554b1da1c638c976e56451d",
        "busybox-1.36.tar",
    ),
}
_SEED_DIR = pathlib.Path.home() / ".cache" / "sim2real" / "images"
_LAYER_PART_BYTES = 8 * 1024 * 1024
_PUSHED: dict[tuple[int, str], tuple[object, str]] = {}


def _seeded_image(key: str) -> tuple[bytes, list[bytes]]:
    """The pre-seeded image's config and gzip layers, verified against its pinned image ID.

    A runner without the archive, or with one holding another image, is a runner fault:
    ``tool_missing``, never a finding about the target.
    """
    from fidelity_tests_runner import RequiredToolMissing

    ref, image_id, archive_name = _SEED_IMAGES[key]
    path = _SEED_DIR / archive_name
    need = (
        f"{ref} ({image_id}) saved at {path}; pre-seed it with `docker pull --platform "
        f"linux/amd64 {ref} && docker save {ref} -o {path}`"
    )
    try:
        with tarfile.open(path) as archive:
            entry = json.load(archive.extractfile("manifest.json"))[0]
            config = archive.extractfile(entry["Config"]).read()
            raw = [archive.extractfile(name).read() for name in entry["Layers"]]
        plain = [gzip.decompress(b) if b[:2] == b"\x1f\x8b" else b for b in raw]
        recorded = json.loads(config).get("rootfs", {}).get("diff_ids")
    except (OSError, EOFError, tarfile.TarError, KeyError, IndexError, ValueError, TypeError,
            AttributeError) as exc:
        raise RequiredToolMissing([f"{need} ({type(exc).__name__}: {exc})"]) from None
    diff_ids = ["sha256:" + hashlib.sha256(b).hexdigest() for b in plain]
    if "sha256:" + hashlib.sha256(config).hexdigest() != image_id or recorded != diff_ids:
        raise RequiredToolMissing([f"{need} (the archive there holds another image)"])
    return config, [gzip.compress(b, compresslevel=1, mtime=0) for b in plain]


def _target_image(ctx, key: str = "busybox") -> str:
    """The URI of the pre-seeded image in an ECR repository this check creates, pushed once.

    Every blob goes through the target's own ECR layer-upload API (InitiateLayerUpload,
    UploadLayerPart, CompleteLayerUpload, PutImage), so the task's image comes from the target.
    """
    hit = _PUSHED.get((id(ctx), key))
    if hit and hit[0] is ctx:
        return hit[1]
    config, layers = _seeded_image(key)
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-img-").lower()
    repo = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    descriptors = []
    for blob in [config, *layers]:
        digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
        for first in range(0, len(blob), _LAYER_PART_BYTES):
            part = blob[first:first + _LAYER_PART_BYTES]
            ecr.upload_layer_part(
                repositoryName=name, uploadId=upload_id, partFirstByte=first,
                partLastByte=first + len(part) - 1, layerPartBlob=part,
            )
        ecr.complete_layer_upload(repositoryName=name, uploadId=upload_id, layerDigests=[digest])
        descriptors.append({"size": len(blob), "digest": digest})
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json", **descriptors[0]},
        "layers": [
            {"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", **d}
            for d in descriptors[1:]
        ],
    }
    ecr.put_image(
        repositoryName=name, imageManifest=json.dumps(manifest), imageTag="seeded",
        imageManifestMediaType=manifest["mediaType"],
    )
    uri = f"{repo['repositoryUri']}:seeded"
    _PUSHED[(id(ctx), key)] = (ctx, uri)
    return uri
# ===== end target-sourced container image =====


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
