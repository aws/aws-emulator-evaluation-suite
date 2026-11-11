"""xsvc-ecs-3-secret-injection-positive."""

from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import tarfile
import time

from behavioral_harness import tags

CHECK = "xsvc-ecs-3-secret-injection-positive"

GROUP = "container-secret-injection"

SERVICES = ["ecs", "kms", "logs", "ssm"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An SSM SecureString under a customer-managed KMS key, named in `secrets[].valueFrom`, reaches
    the container's environment as the exact plaintext via the execution role, while
    DescribeTaskDefinition, DescribeTasks and a non-decrypting GetParameter never expose it.
    """
    net = _network(ctx)
    log_group = _create_log_group(ctx)
    cluster = _create_cluster(ctx)
    key_arn = _create_cmk(ctx)
    secret_value = "s3cr3t:" + ctx.unique_name("") + "/+=v"
    param_name, param_arn = _put_secure_parameter(ctx, secret_value, key_arn)

    # The parameter really is encrypted under OUR key: a read without decryption is not the value.
    ssm = ctx.client("ssm")
    raw = ssm.get_parameter(Name=param_name, WithDecryption=False)["Parameter"]
    assert raw["Type"] == "SecureString", f"parameter type is {raw['Type']!r}"
    assert raw["Value"] != secret_value, "a non-decrypting read returned the plaintext"
    meta = ssm.describe_parameters(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [param_name]}]
    )["Parameters"]
    assert len(meta) == 1 and meta[0].get("KeyId") == key_arn, (
        f"parameter metadata does not name the CMK {key_arn!r}: {meta!r}"
    )

    exec_role = _iam_role(
        ctx, "exec-ok", [_logs_stmt(), _ssm_stmt(param_arn), _kms_stmt(key_arn)]
    )
    td = _register_task_def(
        ctx, [_container(ctx, param_arn, log_group, ctx.region)], execution_role_arn=exec_role
    )
    # The control plane holds the reference, never the plaintext.
    described = ctx.client("ecs").describe_task_definition(
        taskDefinition=td["taskDefinitionArn"]
    )["taskDefinition"]
    assert described["containerDefinitions"][0]["secrets"] == [
        {"name": "SIM2REAL_SECRET", "valueFrom": param_arn}
    ], f"task definition secrets round-tripped as {described['containerDefinitions'][0].get('secrets')!r}"
    assert secret_value not in json.dumps(described, default=str), (
        "the plaintext secret appears in DescribeTaskDefinition"
    )

    deadline = _deadline(ctx, _IAM_PROPAGATION_S)
    while True:
        try:
            task_arn = _run_task(ctx, cluster, td["taskDefinitionArn"], net)
        except Exception as exc:  # noqa: BLE001 - retried only while role propagation is in play
            if _role_not_yet_usable_message(str(exc)) and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
        task = _await_task(ctx, cluster, task_arn, timeout_s=600)
        if not _role_not_yet_usable(task) or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert task.get("stopCode") == "EssentialContainerExited", (
        f"task did not run to completion: stopCode={task.get('stopCode')!r} "
        f"reason={task.get('stoppedReason')!r}"
    )
    assert task["containers"][0].get("exitCode") == 0, (
        f"container exitCode={task['containers'][0].get('exitCode')!r} "
        f"reason={task['containers'][0].get('reason')!r}"
    )
    assert secret_value not in json.dumps(task, default=str), (
        "the plaintext secret appears in DescribeTasks"
    )

    stream = f"ecs/app/{task_arn.rsplit('/', 1)[-1]}"
    msgs = _await_log_line(ctx, log_group, stream, f"injected={secret_value}", timeout_s=300)
    assert f"injected={secret_value}" in msgs, f"exact line absent from {msgs!r}"
    assert f"len={len(secret_value)}" in msgs, (
        f"the injected value's length is not {len(secret_value)}: {msgs!r}"
    )

    _teardown_network(ctx, net)


# ===== helpers (self-contained) =====
_XSVC_PREFIX = "sim2real-xsvc-"



def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}]


def _ecs_tags_kv():
    return [{"key": "sim2real", "value": CHECK}]


def _swallow(fn):
    """Run a teardown step; absorb only its resource's own not-found code, raise the rest."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - classified below, not blanket-absorbed
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "") if hasattr(
            exc, "response") else ""
        if "NotFound" not in code and "NoSuchEntity" not in code:
            raise


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


def _undo_step(fn, raise_on_leak):
    """Run one network-teardown step; absorb its not-found code, raise the rest only as cleanup."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - classified below
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "") if hasattr(
            exc, "response") else ""
        if "NotFound" in code:
            return
        if raise_on_leak:
            raise
        print(f"[LEAK?] teardown step failed: {type(exc).__name__}: {exc}")


def _teardown_network(ctx, net, eni_wait_s=300, *, raise_on_leak=False):
    """Idempotent: wait for task ENIs to be released, then delete the VPC estate child-first.

    Called in-body on the success path (under the check's budget) and registered as the cleanup
    net for the failure path, where the 60 s cleanup budget bounds the ENI wait. As the cleanup
    (``raise_on_leak=True``) a leftover of any kind raises; the in-body call only reports it."""
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
        time.sleep(10)
    else:
        eni_leak = f"ENIs still present in {net['vpc']} after {eni_wait_s}s"
        if not raise_on_leak:
            print(eni_leak)
    if net.get("assoc"):
        _undo_step(lambda: ec2.disassociate_route_table(AssociationId=net["assoc"]), raise_on_leak)
    if net.get("subnet"):
        _undo_step(lambda: ec2.delete_subnet(SubnetId=net["subnet"]), raise_on_leak)
    if net.get("rt"):
        _undo_step(lambda: ec2.delete_route_table(RouteTableId=net["rt"]), raise_on_leak)
    if net.get("igw"):
        _undo_step(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=net["igw"], VpcId=net["vpc"]),
            raise_on_leak)
        _undo_step(lambda: ec2.delete_internet_gateway(InternetGatewayId=net["igw"]), raise_on_leak)
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

    IAM exposes no condition saying a policy is effective at ECS, so callers rerun the task
    launch while it fails on the fresh role's grants (_role_not_yet_usable)."""
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


#: Bound for a fresh execution role's grants to become effective at ECS.
_IAM_PROPAGATION_S = 180.0


def _deadline(ctx, budget_s):
    """A monotonic deadline `budget_s` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (budget_s if left is None else min(budget_s, max(0.0, left - 5)))


def _role_not_yet_usable_message(reason):
    """Whether `reason` names the execution role as not yet usable: unassumable or grant-denied.

    ECS reports this either as a `TaskFailedToStart` task, or as RunTask itself raising
    synchronously with the identical wording; both are IAM propagation, not a real rejection."""
    reason = reason or ""
    return "unable to assume" in reason.lower() or "is not authorized to perform" in reason


def _role_not_yet_usable(task):
    return task.get("stopCode") == "TaskFailedToStart" and _role_not_yet_usable_message(
        task.get("stoppedReason"))


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


def _await_task(ctx, cluster, task_arn, timeout_s=600):
    ecs = ctx.client("ecs")

    def probe():
        found = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        return found[0] if found else {}

    return _poll_until(probe, lambda t: t.get("lastStatus") == "STOPPED", timeout_s=timeout_s,
                       interval_s=2, description=f"task {task_arn} STOPPED")


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
                       timeout_s=timeout_s, interval_s=2,
                       description=f"exact line {line!r} in {group}/{stream}")


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
