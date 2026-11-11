"""xsvc-ecs-3-secret-injection-no-kms-decrypt-rejected."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "xsvc-ecs-3-secret-injection-no-kms-decrypt-rejected"

GROUP = "container-secret-injection"

SERVICES = ["ecs", "kms", "logs", "ssm"]


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An execution role with ssm:GetParameters but not kms:Decrypt on the CMK cannot inject a
    SecureString secret: the task fails to start, KMS's denial names the execution role, and no
    container runs, while an otherwise identical control with kms:Decrypt prints the plaintext."""
    net = _network(ctx)
    log_group = _create_log_group(ctx)
    cluster = _create_cluster(ctx)
    key_arn = _create_cmk(ctx)
    secret_value = "s3cr3t:" + ctx.unique_name("") + "/+=v"
    _param_name, param_arn = _put_secure_parameter(ctx, secret_value, key_arn)
    container = _container(param_arn, log_group, ctx.region)

    # Break exactly one thing: kms:Decrypt is missing from the execution role.
    bad_role = _iam_role(ctx, "exec-nokms", [_logs_stmt(), _ssm_stmt(param_arn)])
    ok_role = _iam_role(ctx, "exec-ok", [_logs_stmt(), _ssm_stmt(param_arn), _kms_stmt(key_arn)])
    bad_td = _register_task_def(ctx, [container], execution_role_arn=bad_role)
    ok_td = _register_task_def(ctx, [container], execution_role_arn=ok_role)
    launch_deadline = time.monotonic() + _capped(ctx, _PROPAGATION_S)
    bad_arn = _run_task(ctx, cluster, bad_td["taskDefinitionArn"], net, launch_deadline)
    ok_arn = _run_task(ctx, cluster, ok_td["taskDefinitionArn"], net, launch_deadline)

    bad_arn, bad = _await_settled_task(ctx, cluster, bad_arn, bad_td["taskDefinitionArn"], net,
                                       launch_deadline, outcome="kms:Decrypt")
    print(f"[observed] bad stopCode={bad.get('stopCode')!r} reason={bad.get('stoppedReason')!r}")
    assert bad.get("stopCode") == "TaskFailedToStart", (
        f"a task whose execution role lacks kms:Decrypt was not failed at start: "
        f"stopCode={bad.get('stopCode')!r} reason={bad.get('stoppedReason')!r}"
    )
    reason = bad.get("stoppedReason", "")
    assert "ResourceInitializationError" in reason, f"stoppedReason={reason!r}"
    # Observed on real AWS: SSM surfaces KMS's own AccessDeniedException, naming OUR key and the
    # EXECUTION role's assumed-role session as the principal that was refused.
    kms_denied = (f"is not authorized to perform: kms:Decrypt on resource: {key_arn} "
        "because no identity-based policy allows the kms:Decrypt action")
    assert kms_denied in reason, f"expected {kms_denied!r} in stoppedReason={reason!r}"
    bad_role_name = bad_role.rsplit("/", 1)[-1]
    assert f"assumed-role/{bad_role_name}/" in reason, (
        f"the denial does not name the execution role {bad_role_name!r}: {reason!r}"
    )
    # `is None`, not falsiness: a container that ran and exited 0 reports exitCode 0.
    assert bad["containers"][0].get("exitCode") is None, (
        f"the container ran despite the failed secret fetch: {bad['containers'][0]!r}"
    )
    assert secret_value not in json.dumps(bad, default=str), "plaintext leaked into DescribeTasks"

    # Positive control, same instant: identical except kms:Decrypt is granted.
    ok_arn, ok = _await_settled_task(ctx, cluster, ok_arn, ok_td["taskDefinitionArn"], net,
                                     launch_deadline)
    assert ok["containers"][0].get("exitCode") == 0, (
        f"control task failed: stopCode={ok.get('stopCode')!r} reason={ok.get('stoppedReason')!r}"
    )
    ok_stream = f"ecs/app/{ok_arn.rsplit('/', 1)[-1]}"
    msgs = _await_log_line(ctx, log_group, ok_stream, f"injected={secret_value}", timeout_s=300)
    assert f"injected={secret_value}" in msgs, msgs

    # Effect absent, asserted AFTER the control delivered (the differential barrier): the bad task's
    # container never ran, so its stream was never created and no event names the value.
    bad_stream = f"ecs/app/{bad_arn.rsplit('/', 1)[-1]}"
    assert _stream_names(ctx, log_group, bad_stream) == [], (
        f"log stream exists for a task that never started: {bad_stream!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}]


def _ecs_tags_kv():
    return [{"key": "sim2real", "value": CHECK}]


#: Bound on relaunching a task that failed only because a fresh role had not propagated yet.
_PROPAGATION_S = 180.0


def _capped(ctx, budget_s):
    """*budget_s*, capped by the time the run has left so a wait fails with its own message."""
    left = ctx.time_left()
    return budget_s if left is None else min(budget_s, max(0.0, left - 10.0))


def _propagation_lag(reason, outcome=None):
    """Whether a stoppedReason or RunTask refusal is IAM propagation (the fresh execution role not
    yet assumable, or one of its grants not yet effective) rather than the `outcome` under test."""
    lowered = (reason or "").lower()
    if outcome and outcome.lower() in lowered:
        return False
    return "unable to assume the role" in lowered or "is not authorized to perform" in lowered


def _await_settled_task(ctx, cluster, arn, td_arn, net, deadline, outcome=None):
    """Await the task's STOPPED record, relaunching it to `deadline` while it failed to start only
    on IAM propagation. Returns (task arn, task record)."""
    while True:
        task = _await_task(ctx, cluster, arn, timeout_s=600)
        if not (task.get("stopCode") == "TaskFailedToStart"
                and _propagation_lag(task.get("stoppedReason"), outcome)
                and time.monotonic() < deadline):
            return arn, task
        time.sleep(2)
        arn = _run_task(ctx, cluster, td_arn, net, deadline)


def _swallow(fn, *, retry=(), deadline=0.0):
    """Run a teardown step; only the resource's own not-found code means it is already gone. A
    `retry` code (a dependency still being released) is retried every 2 s until `deadline`."""
    while True:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 - re-raised unless gone or still releasing
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "") if hasattr(
                exc, "response") else ""
            if "NotFound" in code or "NoSuchEntity" in code:
                return
            if code not in retry or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0, description="condition"):
    """Poll probe() until predicate(result) holds; RAISE on timeout, never return the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _tagspec(kind, name):
    return [{"ResourceType": kind, "Tags": [{"Key": "Name", "Value": name},
                                            {"Key": "sim2real", "Value": CHECK}]}]


def _network(ctx):
    """A self-owned VPC with one public subnet in a derived AZ; no default VPC is assumed.

    Tasks get the new VPC's own default security group (all egress), which is deleted with the
    VPC, so no further resource is needed to pull a public image."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(_XSVC_PREFIX + "vpc-")
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert zones, f"no available availability-zone in {ctx.region}"
    net = {}
    net["vpc"] = ec2.create_vpc(CidrBlock="10.42.0.0/16",
                                TagSpecifications=_tagspec("vpc", name))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _teardown_network(ctx, net))
    net["igw"] = ec2.create_internet_gateway(
        TagSpecifications=_tagspec("internet-gateway", name))["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=net["igw"], VpcId=net["vpc"])
    net["rt"] = ec2.create_route_table(
        VpcId=net["vpc"], TagSpecifications=_tagspec("route-table", name))["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=net["rt"], DestinationCidrBlock="0.0.0.0/0", GatewayId=net["igw"])
    net["subnet"] = ec2.create_subnet(
        VpcId=net["vpc"], CidrBlock="10.42.0.0/24", AvailabilityZone=zones[0],
        TagSpecifications=_tagspec("subnet", name))["Subnet"]["SubnetId"]
    net["assoc"] = ec2.associate_route_table(
        RouteTableId=net["rt"], SubnetId=net["subnet"])["AssociationId"]
    return net


#: Bound on the network deletes while the tasks' ENIs are released after they stop.
_NET_RELEASE_S = 300.0


def _teardown_network(ctx, net):
    """Idempotent cleanup: delete the VPC estate child-first, retrying DependencyViolation while
    task ENIs are released; any other failure, or a dependency outliving _NET_RELEASE_S, raises."""
    if net.get("done") or not net.get("vpc"):
        return
    ec2 = ctx.client("ec2")
    held = {"retry": ("DependencyViolation",), "deadline": time.monotonic() + _NET_RELEASE_S}
    if net.get("assoc"):
        _swallow(lambda: ec2.disassociate_route_table(AssociationId=net["assoc"]))
    if net.get("subnet"):
        _swallow(lambda: ec2.delete_subnet(SubnetId=net["subnet"]), **held)
    if net.get("rt"):
        _swallow(lambda: ec2.delete_route_table(RouteTableId=net["rt"]), **held)
    if net.get("igw"):
        _swallow(lambda: ec2.detach_internet_gateway(InternetGatewayId=net["igw"], VpcId=net["vpc"]),
                 **held)
        _swallow(lambda: ec2.delete_internet_gateway(InternetGatewayId=net["igw"]))
    _swallow(lambda: ec2.delete_vpc(VpcId=net["vpc"]), **held)
    net["done"] = True


def _create_cmk(ctx):
    """A symmetric customer-managed key with the default key policy (IAM policies govern use)."""
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name(_XSVC_PREFIX + "cmk-"),
        KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    # Seven days is the floor AWS allows; the key is unusable from the moment this is scheduled.
    ctx.on_cleanup(lambda: _swallow(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)))
    alias = "alias/" + ctx.unique_name(_XSVC_PREFIX + "cmk-")
    kms.create_alias(AliasName=alias, TargetKeyId=key_id)
    ctx.on_cleanup(lambda: _swallow(lambda: kms.delete_alias(AliasName=alias)))
    return meta["Arn"]


def _put_secure_parameter(ctx, value, key_arn):
    ssm = ctx.client("ssm")
    name = ctx.unique_name(_XSVC_PREFIX + "param-")
    ssm.put_parameter(Name=name, Value=value, Type="SecureString", KeyId=key_arn,
                      Tags=_tags_kv())
    ctx.on_cleanup(lambda: _swallow(lambda: ssm.delete_parameter(Name=name)))
    arn = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]["ARN"]
    return name, arn


def _logs_stmt():
    return {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*"}


def _ssm_stmt(param_arn):
    return {"Effect": "Allow", "Action": "ssm:GetParameters", "Resource": param_arn}


def _kms_stmt(key_arn):
    return {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key_arn}


def _iam_role(ctx, kind, statements):
    """A role trusting ecs-tasks.amazonaws.com with ONE inline policy; returns its ARN.

    IAM exposes no condition saying a policy is effective at ECS, so the task launch is retried
    while it fails on propagation (_await_settled_task)."""
    iam = ctx.client("iam")
    name = ctx.unique_name(_XSVC_PREFIX + kind + "-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _drop():
        _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        _swallow(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_drop)
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    _poll_until(
        lambda: _safe(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
        lambda r: r is not None, timeout_s=60, interval_s=2,
        description=f"role {name} inline policy readable",
    )
    return arn


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_XSVC_PREFIX + "ecs-")
    ecs.create_cluster(clusterName=name, tags=_ecs_tags_kv())
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.delete_cluster(cluster=name),
                                    retry=("ClusterContainsTasksException",),
                                    deadline=time.monotonic() + 120))
    return name


def _create_log_group(ctx):
    logs = ctx.client("logs")
    name = ctx.unique_name(_XSVC_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _swallow(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _container(param_arn, log_group, region):
    return {
        "name": "app",
        "image": _PUBLIC_IMAGE,
        "essential": True,
        "command": ["sh", "-c", 'echo "injected=$SIM2REAL_SECRET"; echo "len=${#SIM2REAL_SECRET}"'],
        "secrets": [{"name": "SIM2REAL_SECRET", "valueFrom": param_arn}],
        "logConfiguration": {
            "logDriver": "awslogs",
            "options": {"awslogs-group": log_group, "awslogs-region": region,
                        "awslogs-stream-prefix": "ecs"},
        },
    }


def _register_task_def(ctx, container_defs, *, execution_role_arn, task_role_arn=None):
    ecs = ctx.client("ecs")
    kwargs = dict(
        family=ctx.unique_name(_XSVC_PREFIX + "td-"),
        containerDefinitions=container_defs,
        requiresCompatibilities=["FARGATE"], networkMode="awsvpc", cpu="256", memory="512",
        executionRoleArn=execution_role_arn, tags=_ecs_tags_kv(),
    )
    if task_role_arn:
        kwargs["taskRoleArn"] = task_role_arn
    td = ecs.register_task_definition(**kwargs)["taskDefinition"]
    arn = td["taskDefinitionArn"]
    def _drop():
        _swallow(lambda: ecs.deregister_task_definition(taskDefinition=arn))
        _swallow(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))

    ctx.on_cleanup(_drop)
    return td


def _run_task(ctx, cluster, td_arn, net, deadline):
    # RunTask on Fargate needs AWSServiceRoleForECS; already-exists is success.
    _safe(lambda: ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com"))
    ecs = ctx.client("ecs")
    while True:
        try:
            resp = ecs.run_task(
                cluster=cluster, taskDefinition=td_arn, launchType="FARGATE", count=1,
                networkConfiguration={"awsvpcConfiguration": {
                    "subnets": [net["subnet"]], "assignPublicIp": "ENABLED"}},
                tags=_ecs_tags_kv(),
            )
            break
        except Exception as exc:  # noqa: BLE001 - re-raised unless it is IAM propagation
            message = getattr(exc, "response", {}).get("Error", {}).get("Message", "")
            if "unable to assume the role" not in message.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    assert not resp.get("failures"), f"RunTask failures: {resp.get('failures')!r}"
    arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.stop_task(cluster=cluster, task=arn)))
    return arn


def _await_task(ctx, cluster, task_arn, timeout_s=600):
    ecs = ctx.client("ecs")

    def probe():
        found = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        return found[0] if found else {}

    return _poll_until(probe, lambda t: t.get("lastStatus") == "STOPPED", timeout_s=timeout_s,
                       interval_s=5, description=f"task {task_arn} STOPPED")


def _log_messages(ctx, group, stream):
    logs = ctx.client("logs")
    out, token = [], None
    while True:
        kwargs = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
        if token:
            kwargs["nextToken"] = token
        page = _safe(lambda: logs.get_log_events(**kwargs))
        if not page:
            return out
        out.extend(e.get("message", "") for e in page.get("events", []))
        nxt = page.get("nextForwardToken")
        if not nxt or nxt == token:
            return out
        token = nxt


def _stream_names(ctx, group, prefix):
    """Every stream in `group` whose name starts with `prefix` (paginated)."""
    logs = ctx.client("logs")
    out, token = [], None
    while True:
        kwargs = {"logGroupName": group, "logStreamNamePrefix": prefix}
        if token:
            kwargs["nextToken"] = token
        page = logs.describe_log_streams(**kwargs)
        out.extend(s["logStreamName"] for s in page.get("logStreams", []))
        token = page.get("nextToken")
        if not token:
            return out


def _await_log_line(ctx, group, stream, line, timeout_s=300):
    return _poll_until(lambda: _log_messages(ctx, group, stream), lambda ms: line in ms,
                       timeout_s=timeout_s, interval_s=5,
                       description=f"exact line {line!r} in {group}/{stream}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
