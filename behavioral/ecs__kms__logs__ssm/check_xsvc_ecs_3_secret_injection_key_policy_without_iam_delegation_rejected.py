"""xsvc-ecs-3-secret-injection-key-policy-without-iam-delegation-rejected."""

from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import tarfile
import time

from behavioral_harness import tags

CHECK = "xsvc-ecs-3-secret-injection-key-policy-without-iam-delegation-rejected"

GROUP = "container-secret-injection"

SERVICES = ["ecs", "kms", "logs", "ssm"]


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A key policy that does not delegate to IAM blocks SecureString injection for an execution
    role whose identity policy grants kms:Decrypt; the role the key policy names starts and logs it.
    Both roles carry identical inline policies, so only the key policy separates the outcomes.
    """
    net = _network(ctx)
    log_group = _create_log_group(ctx)
    cluster = _create_cluster(ctx)

    # Roles first: the key policy must name the control role, and KMS validates principals.
    iam = ctx.client("iam")
    bad_role = _iam_role(ctx, "exec-notinkp", [_logs_stmt()])
    ok_role = _iam_role(ctx, "exec-inkp", [_logs_stmt()])

    admin = _caller_principal_arn(ctx)
    # No account-root statement: KMS then honours only principals the key policy names itself.
    key_arn = _create_cmk_with_policy(ctx, {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "KeyAdminIsTheCallerOnly", "Effect": "Allow", "Principal": {"AWS": admin},
             "Action": "kms:*", "Resource": "*"},
            {"Sid": "ControlExecutionRoleMayDecrypt", "Effect": "Allow",
             "Principal": {"AWS": ok_role}, "Action": "kms:Decrypt", "Resource": "*"},
        ],
    })
    secret_value = "s3cr3t:" + ctx.unique_name("") + "/+=v"
    _param_name, param_arn = _put_secure_parameter(ctx, secret_value, key_arn)
    container = _container(ctx, param_arn, log_group, ctx.region)

    # IDENTICAL identity grants on both roles, including kms:Decrypt on the key.
    grants = [_logs_stmt(), _ssm_stmt(param_arn), _kms_stmt(key_arn)]
    for role_arn in (bad_role, ok_role):
        name = role_arn.rsplit("/", 1)[-1]
        iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": grants}))
    for role_arn in (bad_role, ok_role):
        name = role_arn.rsplit("/", 1)[-1]
        doc = _poll_until(
            lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")["PolicyDocument"],
            lambda d: len(d.get("Statement", [])) == 3, timeout_s=60, interval_s=2,
            description=f"role {name} inline policy carries the three grants")
        assert doc["Statement"] == grants, f"role {name} policy read back as {doc!r}"
    bad_td = _register_task_def(ctx, [container], execution_role_arn=bad_role)
    ok_td = _register_task_def(ctx, [container], execution_role_arn=ok_role)
    # The fresh roles' grants reach the ECS agent a few seconds after IAM returns them, and that
    # window has no pollable condition. The control leg is the proof: while it still fails to
    # start, both legs are relaunched (bounded), never preceded by a fixed sleep.
    for attempt in range(4):
        bad_arn = _run_task(ctx, cluster, bad_td["taskDefinitionArn"], net)
        ok_arn = _run_task(ctx, cluster, ok_td["taskDefinitionArn"], net)
        bad, ok = _await_tasks(ctx, cluster, [bad_arn, ok_arn], timeout_s=_budget_s(ctx, 600))
        if ok.get("stopCode") != "TaskFailedToStart" or attempt == 3:
            break
        time.sleep(2)

    print(f"[observed] bad stopCode={bad.get('stopCode')!r} reason={bad.get('stoppedReason')!r}")
    assert bad.get("stopCode") == "TaskFailedToStart", (
        f"a task whose execution role is absent from a non-delegating key policy was not failed "
        f"at start: stopCode={bad.get('stopCode')!r} reason={bad.get('stoppedReason')!r}"
    )
    reason = bad.get("stoppedReason", "")
    assert "ResourceInitializationError" in reason, f"stoppedReason={reason!r}"
    assert _KP_DENIED.format(key_arn=key_arn) in reason, (
        f"expected {_KP_DENIED.format(key_arn=key_arn)!r} in stoppedReason={reason!r}"
    )
    bad_role_name = bad_role.rsplit("/", 1)[-1]
    assert f"assumed-role/{bad_role_name}/" in reason, (
        f"the denial does not name the execution role {bad_role_name!r}: {reason!r}"
    )
    assert bad["containers"][0].get("exitCode") is None, (
        f"the container ran despite the failed secret fetch: {bad['containers'][0]!r}"
    )
    assert secret_value not in json.dumps(bad, default=str), "plaintext leaked into DescribeTasks"

    assert ok["containers"][0].get("exitCode") == 0, (
        f"control task (role named in the key policy) failed: stopCode={ok.get('stopCode')!r} "
        f"reason={ok.get('stoppedReason')!r}"
    )
    ok_stream = f"ecs/app/{ok_arn.rsplit('/', 1)[-1]}"
    msgs = _await_log_line(ctx, log_group, ok_stream, f"injected={secret_value}",
                           timeout_s=_budget_s(ctx, 300))
    assert f"injected={secret_value}" in msgs, msgs

    bad_stream = f"ecs/app/{bad_arn.rsplit('/', 1)[-1]}"
    assert _stream_names(ctx, log_group, bad_stream) == [], (
        f"log stream exists for a task that never started: {bad_stream!r}"
    )

    _teardown_network(ctx, net, eni_wait_s=_budget_s(ctx, 300))


_XSVC_PREFIX = "sim2real-xsvc-"



def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}]


def _ecs_tags_kv():
    return [{"key": "sim2real", "value": CHECK}]


def _swallow(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - best-effort teardown
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "") if hasattr(
            exc, "response") else ""
        if "NotFound" not in code and "NoSuchEntity" not in code:
            print(f"[LEAK?] teardown step failed: {type(exc).__name__}: {exc}")


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition", ctx=None):
    """Poll probe() until predicate(result) holds; RAISE on timeout, never return the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
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
    ctx.on_cleanup(lambda: _teardown_network(ctx, net, eni_wait_s=40, raise_on_leak=True))
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


def _teardown_network(ctx, net, eni_wait_s=300, *, raise_on_leak=False):
    """Idempotent: wait for task ENIs to be released, then delete the VPC estate child-first.

    Called in-body on the success path (under the check's budget) and registered as the cleanup
    net for the failure path, where the 60 s cleanup budget bounds the ENI wait. As the cleanup
    (``raise_on_leak=True``) a VPC left behind raises; the in-body call only reports it."""
    if net.get("done") or not net.get("vpc"):
        return
    ec2 = ctx.client("ec2")
    eni_leak = None
    deadline = time.monotonic() + eni_wait_s
    while time.monotonic() < deadline:
        enis = _safe(lambda: ec2.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [net["vpc"]]}])["NetworkInterfaces"])
        if enis == []:
            break
        time.sleep(2)
    else:
        eni_leak = f"ENIs still present in {net['vpc']} after {eni_wait_s}s"
        if not raise_on_leak:
            print(eni_leak)
    if net.get("assoc"):
        _swallow(lambda: ec2.disassociate_route_table(AssociationId=net["assoc"]))
    if net.get("subnet"):
        _swallow(lambda: ec2.delete_subnet(SubnetId=net["subnet"]))
    if net.get("rt"):
        _swallow(lambda: ec2.delete_route_table(RouteTableId=net["rt"]))
    if net.get("igw"):
        _swallow(lambda: ec2.detach_internet_gateway(InternetGatewayId=net["igw"], VpcId=net["vpc"]))
        _swallow(lambda: ec2.delete_internet_gateway(InternetGatewayId=net["igw"]))
    try:
        ec2.delete_vpc(VpcId=net["vpc"])
        net["done"] = True
    except Exception as exc:  # noqa: BLE001 - teardown must not mask the verdict
        code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code")
        if code == "InvalidVpcID.NotFound":
            net["done"] = True
        elif raise_on_leak:
            prefix = f"{eni_leak}; " if eni_leak else ""
            raise RuntimeError(f"{prefix}vpc {net['vpc']}: {exc}") from exc
        else:
            print(f"vpc {net['vpc']}: {exc}")


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
    """The execution role's log writes and its pull of the seeded image from the target's ECR."""
    return {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents",
                                          "ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability",
                                          "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"],
            "Resource": "*"}


def _ssm_stmt(param_arn):
    return {"Effect": "Allow", "Action": "ssm:GetParameters", "Resource": param_arn}


def _kms_stmt(key_arn):
    return {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key_arn}


def _iam_role(ctx, kind, statements):
    """A role trusting ecs-tasks.amazonaws.com with ONE inline policy; returns its ARN.

    The policy is polled back readable; IAM exposes no condition for propagation to ECS."""
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
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.delete_cluster(cluster=name)))
    return name


def _create_log_group(ctx):
    logs = ctx.client("logs")
    name = ctx.unique_name(_XSVC_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _swallow(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _container(ctx, param_arn, log_group, region):
    return {
        "name": "app",
        "image": _target_image(ctx, "busybox"),
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


def _run_task(ctx, cluster, td_arn, net):
    # RunTask on Fargate needs AWSServiceRoleForECS; already-exists is success.
    _safe(lambda: ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com"))
    ecs = ctx.client("ecs")
    resp = ecs.run_task(
        cluster=cluster, taskDefinition=td_arn, launchType="FARGATE", count=1,
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": [net["subnet"]], "assignPublicIp": "ENABLED"}},
        tags=_ecs_tags_kv(),
    )
    assert not resp.get("failures"), f"RunTask failures: {resp.get('failures')!r}"
    arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.stop_task(cluster=cluster, task=arn)))
    return arn


def _await_tasks(ctx, cluster, task_arns, timeout_s=600):
    """Poll every task in one DescribeTasks until all are STOPPED; returns them in input order."""
    ecs = ctx.client("ecs")

    def probe():
        found = {t["taskArn"]: t for t in
                 ecs.describe_tasks(cluster=cluster, tasks=task_arns).get("tasks", [])}
        return [found.get(a, {}) for a in task_arns]

    return _poll_until(probe, lambda ts: all(t.get("lastStatus") == "STOPPED" for t in ts),
                       timeout_s=timeout_s, interval_s=1, ctx=ctx,
                       description=f"tasks {task_arns} STOPPED")


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
                       timeout_s=timeout_s, interval_s=1, ctx=ctx,
                       description=f"exact line {line!r} in {group}/{stream}")


#: The stoppedReason fragment for this break.
#: RESOURCE-based, not identity-based: the identity grant was present and KMS still refused.
_KP_DENIED = ("is not authorized to perform: kms:Decrypt on resource: {key_arn} "
              "because no resource-based policy allows the kms:Decrypt action")


def _caller_principal_arn(ctx):
    """The calling principal as a key-policy Principal: an IAM user ARN as-is, an assumed-role
    session resolved to its role's ARN (path included). Never the account root -- naming root
    would delegate to IAM and erase the very boundary this check exists to test."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    kind = arn.split(":", 5)[5].split("/", 1)[0]
    if kind == "user":
        return arn
    if kind == "assumed-role":
        return ctx.client("iam").get_role(RoleName=arn.split("/")[1])["Role"]["Arn"]
    raise AssertionError(f"caller {arn!r} cannot be named as a non-root key administrator")


def _create_cmk_with_policy(ctx, policy):
    """Like _create_cmk, but with an explicit key policy. Freshly created role principals can be
    briefly unknown to KMS, so CreateKey is retried on that one validation error only."""
    kms = ctx.client("kms")
    deadline = time.monotonic() + 90
    while True:
        try:
            meta = kms.create_key(
                Description=ctx.unique_name(_XSVC_PREFIX + "cmk-"), Policy=json.dumps(policy),
                KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
                Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
            )["KeyMetadata"]
            break
        except Exception as exc:  # noqa: BLE001 - retry only principal-propagation rejections
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code != "MalformedPolicyDocumentException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    key_id = meta["KeyId"]
    ctx.on_cleanup(lambda: _swallow(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)))
    alias = "alias/" + ctx.unique_name(_XSVC_PREFIX + "cmk-")
    kms.create_alias(AliasName=alias, TargetKeyId=key_id)
    ctx.on_cleanup(lambda: _swallow(lambda: kms.delete_alias(AliasName=alias)))
    return meta["Arn"]


# ===== target-sourced container image (self-contained) =====
#: Images the tasks run: the reference, its linux/amd64 image ID (the config digest), and the
#: archive it is pre-seeded as with `docker save`. The check never pulls from a registry.
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

    A missing or mismatched archive raises ``tool_missing``, never a finding about the target.
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
