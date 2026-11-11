"""ecs-efs-volume-shared-across-two-fargate-tasks-and-readonly-mount-write-denied."""

from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-efs-volume-shared-across-two-fargate-tasks-and-readonly-mount-write-denied"

GROUP = "task-storage"

SERVICES = ["ecs", "efs", "logs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:native",
      "plane:data")
def run(ctx) -> None:
    """An EFS volume is shared across Fargate tasks: B reads what an already-stopped A wrote, and a
    readOnly mount C is refused the write ("Read-only file system") yet reads, leaving no trace.
    """
    ecs = ctx.client("ecs")
    efs = ctx.client("efs")
    td = _Teardown(ctx)
    ok = False
    try:
        account = ctx.client("sts").get_caller_identity()["Account"]
        subnets, sg = _fargate_network(ctx)
        cluster = ctx.unique_name(_PREFIX + "cluster-")
        ecs.create_cluster(clusterName=cluster, tags=_ecs_tags())
        td.add(f"ecs cluster {cluster}", lambda: _drop_cluster(ecs, cluster))
        _ensure_ecs_slr(ctx)
        log_group = _create_log_group(ctx, td)

        fs_id = _create_filesystem(ctx, efs, td)
        _create_mount_target(ctx, efs, td, fs_id, subnets[0], sg)
        ap_id, ap_arn = _create_access_point(ctx, efs, td, fs_id)
        fs_arn = f"arn:aws:elasticfilesystem:{ctx.region}:{account}:file-system/{fs_id}"

        _n, task_role = _iam_role(ctx, td, "taskrole", [
            {"Effect": "Allow",
             "Action": ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"],
             "Resource": fs_arn,
             "Condition": {"StringEquals": {"elasticfilesystem:AccessPointArn": ap_arn}}},
        ])
        _e, exec_role = _iam_role(ctx, td, "exec", _EXEC_STATEMENTS)

        marker = ctx.unique_name("efs-payload-")
        rw_td = _register_td(ctx, ecs, td, fs_id, ap_id, log_group, exec_role, task_role,
                             read_only=False)
        ro_td = _register_td(ctx, ecs, td, fs_id, ap_id, log_group, exec_role, task_role,
                             read_only=True)
        net = {"awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg],
                                       "assignPublicIp": "ENABLED"}}

        # ---- A writes; B, in a different task started after A stopped, reads A's bytes ----
        a_task = _run_and_wait(ctx, ecs, td, cluster, rw_td, net, log_group, "A", [
            "sh", "-c",
            'set -e; echo "$MARKER" > /mnt/shared/payload; sync; '
            'echo "A-SIZE=$(wc -c < /mnt/shared/payload)"; '
            'echo "A-MODE=$(ls -l /mnt/shared/payload | cut -c1-10)"; echo A-DONE'],
            env=[{"name": "MARKER", "value": marker}], retry_s=_LAUNCH_RETRY_S)
        a_log = _stream_lines(ctx, log_group, a_task, "A-DONE")
        assert _container(a_task)["exitCode"] == 0, (
            f"the writing task must exit 0, got {_container(a_task)!r} "
            f"stoppedReason={a_task.get('stoppedReason')!r} log={a_log!r}")
        assert f"A-SIZE={len(marker) + 1}" in a_log, (
            f"the file A wrote must be exactly the {len(marker) + 1} bytes of the marker plus its "
            f"newline, as the container's own wc reports it; log={a_log!r}")
        assert any(line.startswith("A-MODE=-rw") for line in a_log), (
            f"the payload must be a regular writable file on the mounted filesystem; log={a_log!r}")

        b_task = _run_and_wait(ctx, ecs, td, cluster, rw_td, net, log_group, "B", [
            "sh", "-c",
            'set -e; echo "B-SAW=$(cat /mnt/shared/payload)"; '
            'echo B-APPEND >> /mnt/shared/payload; echo B-DONE'])
        b_log = _stream_lines(ctx, log_group, b_task, "B-DONE")
        assert _container(b_task)["exitCode"] == 0, (
            f"the reading task must exit 0, got {_container(b_task)!r} log={b_log!r}")
        assert f"B-SAW={marker}" in b_log, (
            f"task B must read back task A's EXACT bytes from the shared filesystem -- this is the "
            f"whole claim, and a per-task local mount fails here; expected B-SAW={marker!r}, "
            f"log={b_log!r}")
        assert a_task["taskArn"] != b_task["taskArn"], "A and B must be two distinct tasks"
        assert a_task["stoppedAt"] < b_task["startedAt"], (
            f"B must have started only after A had STOPPED, so the bytes crossed a task boundary "
            f"and not a shared runtime; A stoppedAt={a_task['stoppedAt']!r} "
            f"B startedAt={b_task['startedAt']!r}")
        assert _eni(a_task) != _eni(b_task) and _eni(a_task) and _eni(b_task), (
            f"each task gets its OWN awsvpc ENI, so the mount is per-task; got "
            f"{_eni(a_task)!r} and {_eni(b_task)!r}")

        # ---- C: readOnly mountPoint refuses the write and still reads (negative + control) ----
        c_task = _run_and_wait(ctx, ecs, td, cluster, ro_td, net, log_group, "C", [
            "sh", "-c",
            # `2>/tmp/err` comes before the append: the shell applies redirections left to right
            # and reports a failed one on whatever stderr is current at that moment.
            'echo "C-READ=$(tr "\\n" "|" < /mnt/shared/payload)"; '
            'if echo x 2>/tmp/err >> /mnt/shared/payload; then echo C-WROTE; '
            'else echo "C-DENIED-ERR=$(tr "\\n" " " < /tmp/err)"; fi; echo C-DONE'])
        c_log = _stream_lines(ctx, log_group, c_task, "C-DONE")
        read_line = next((line for line in c_log if line.startswith("C-READ=")), None)
        assert read_line == f"C-READ={marker}|B-APPEND|", (
            f"the read-only mount must still READ the current content -- that is the control that "
            f"makes the refusal below a statement about the mount and not about the mount having "
            f"failed; got {read_line!r}, log={c_log!r}")
        denied = next((line for line in c_log if line.startswith("C-DENIED-ERR=")), None)
        assert denied is not None, (
            f"the append through a readOnly:true mount must FAIL, so the else branch must have run; "
            f"log={c_log!r}")
        assert any(_EROFS in line for line in c_log), (
            f"the refusal must be the kernel's own {_EROFS!r} (EROFS), not some other errno; "
            f"log={c_log!r}")
        assert not any("C-WROTE" in line for line in c_log), (
            f"C-WROTE means the runtime ACCEPTED a write through a read-only mount, which is the "
            f"over-permissive divergence this arm exists to catch; log={c_log!r}")
        assert _container(c_task)["exitCode"] == 0, (
            f"the read-only task itself must run to completion, got {_container(c_task)!r}")

        # ---- D: the refused write left NO trace on the filesystem (effect absent) ----
        d_task = _run_and_wait(ctx, ecs, td, cluster, rw_td, net, log_group, "D", [
            "sh", "-c",
            'echo "D-CONTENT=$(tr "\\n" "|" < /mnt/shared/payload)"; echo D-DONE'])
        d_log = _stream_lines(ctx, log_group, d_task, "D-DONE")
        content = next((line for line in d_log if line.startswith("D-CONTENT=")), None)
        assert content == f"D-CONTENT={marker}|B-APPEND|", (
            f"after the refused write the filesystem must hold exactly A's line and B's appended "
            f"line -- an extra 'x' means C's write landed anyway; got {content!r}, log={d_log!r}")

        # ---- EFS's own metering saw real bytes, and the access point is the one we made ----
        described = _poll_until(
            lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0],
            lambda fs: (fs.get("SizeInBytes") or {}).get("Value", 0) > 0,
            timeout_s=_METER_TIMEOUT_S, interval_s=15,
            description=f"EFS {fs_id} SizeInBytes reflects the written bytes")
        assert described["SizeInBytes"]["Value"] > 0, described
        aps = _paginate(efs, "describe_access_points", "AccessPoints", FileSystemId=fs_id)
        assert [a["AccessPointId"] for a in aps] == [ap_id], (
            f"exactly the one access point this check created must exist on {fs_id}, got "
            f"{[a['AccessPointId'] for a in aps]!r}")
        vol = ecs.describe_task_definition(taskDefinition=ro_td)["taskDefinition"]["volumes"][0]
        assert vol["efsVolumeConfiguration"]["authorizationConfig"]["accessPointId"] == ap_id, vol
        assert vol["efsVolumeConfiguration"]["transitEncryption"] == "ENABLED", vol
        ok = True
    finally:
        # Verified inline teardown: ctx cleanups run under a short timeout that cannot fail the
        # verdict, so an EFS stack (access point, mount target, file system) would otherwise leak.
        leaks = td.run()
        if ok:
            assert not leaks, f"verified teardown did not remove everything: {leaks!r}"
        elif leaks:
            print(f"teardown after a failing body: {leaks!r}", file=sys.stderr)


_PREFIX = "sim2real-xsvc-efs-"
_MANAGED_TAGS = {
    "sim2real:managed": "true",
    "sim2real:prefix": "sim2real-xsvc",
    "sim2real": "ecs-efs-shared-volume",
}

# The exact errno text the kernel gives a write to a read-only mount, as busybox sh reports it.
_EROFS = "Read-only file system"

# The failure classes the first task's launch retries on (see _run_and_wait). EFS mount setup: a
# mount target that reports `available` may not yet resolve; EFS documents up to 90 s of DNS
# propagation with no API to poll. Task-role IAM propagation surfaces through the same message.
# Execution-role IAM propagation: ECS cannot yet assume the fresh role.
_MOUNT_DNS_LAG = "failed to invoke EFS utils commands to set up EFS volumes"
_ROLE_LAG = "unable to assume the role"
_LAUNCH_RETRY_S = 240.0

# Bounded deadlines, each with its reason.
_TASK_TIMEOUT_S = 900       # Fargate placement + public-ECR pull + EFS mount + run, per task
_MT_TIMEOUT_S = 600         # a mount target reaches `available` in 1-3 min
_METER_TIMEOUT_S = 600      # EFS SizeInBytes is metered asynchronously
_LOG_TIMEOUT_S = 420        # awslogs stream creation, then event delivery
_TEARDOWN_TIMEOUT_S = 420   # deleted -> polled actually gone, per resource

# busybox, pinned by digest rather than the moving `latest` tag.
_BUSYBOX = ("public.ecr.aws/docker/library/busybox"
            "@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662")

_ECS_TASKS_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
_EXEC_STATEMENTS = [
    {"Effect": "Allow",
     "Action": ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage",
                "logs:CreateLogStream", "logs:PutLogEvents"],
     "Resource": "*"}
]


class _Teardown:
    """Every undo, registered twice: inline (run in reverse order in the body's `finally`) and on
    `ctx.on_cleanup` as the failure-path net, since ctx cleanups are time-bounded and cannot fail."""

    def __init__(self, ctx):
        self._ctx = ctx
        self._steps = []

    def add(self, label, fn):
        self._steps.append((label, fn))
        self._ctx.on_cleanup(fn)

    def run(self):
        leaks = []
        for label, fn in reversed(self._steps):
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - collected, not swallowed
                leaks.append(f"{label}: {exc!r}")
        return leaks


def _ecs_tags():
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _kv_tags():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown step
        pass


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result); return the final result. Raises on a deadline miss."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _paginate(client, op, key, **kwargs):
    """Every page of a List*/Describe*, flattened."""
    out = []
    try:
        pages = client.get_paginator(op).paginate(**kwargs)
    except Exception:  # noqa: BLE001 - no paginator modelled for this op
        return getattr(client, op)(**kwargs).get(key, [])
    for page in pages:
        out.extend(page.get(key, []))
    return out


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


def _ensure_ecs_slr(ctx):
    """AWSServiceRoleForECS -- the role ECS assumes to attach an awsvpc task's ENI.

    CreateService creates it implicitly; RunTask does NOT, so in an account that has never used ECS
    every Fargate RunTask fails with InvalidParameterException "Unable to assume the service linked
    role". No teardown is registered deliberately: it is account-level, free, shared by every ECS
    check, and DeleteServiceLinkedRole is asynchronous and fails while anything references it.
    """
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        if code not in ("InvalidInput", "InvalidInputException") or message != (
            "Service role name AWSServiceRoleForECS has been taken in this account, please try a different suffix."
        ):
            raise AssertionError(f"cannot create the ECS service-linked role: {exc}") from exc


_SLR_LAG = "Unable to assume the service linked role"


def _launch_past_slr_lag(call, *, timeout_s=120.0, interval_s=10.0):
    """Run an ECS launch call, retrying (bounded) only while ECS cannot yet assume a just-created
    service-linked role; any other error or failure is returned or raised unchanged."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = call()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "InvalidParameterException" or _SLR_LAG not in str(err.get("Message", "")):
                raise
            last = exc
        else:
            lag = [f for f in resp.get("failures") or [] if _SLR_LAG in str(f.get("reason", ""))]
            if not lag:
                return resp
            last = lag
        if time.monotonic() >= deadline:
            raise AssertionError(f"ECS could not assume its service-linked role within {timeout_s}s: {last!r}")
        time.sleep(interval_s)


def _iam_role(ctx, td, kind, statements):
    """A role trusting ecs-tasks with one inline policy; returns (name, arn).

    Fresh per check so another check's teardown cannot delete it mid-pull; IAM trust propagation
    is retried at first use (_run_and_wait)."""
    iam = ctx.client("iam")
    name = ctx.unique_name(_PREFIX + kind + "-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_ECS_TASKS_TRUST), Path="/sim2real/",
        Description="SimParity behavioral: ECS+EFS " + kind,
        Tags=_kv_tags())["Role"]["Arn"]

    def _drop():
        _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        _swallow(lambda: iam.delete_role(RoleName=name))
        if _safe(lambda: iam.get_role(RoleName=name)) is not None:
            raise AssertionError(f"IAM role {name} still exists after DeleteRole")

    td.add(f"iam role {name}", _drop)
    iam.put_role_policy(RoleName=name, PolicyName="inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                   "Statement": statements}))
    _poll_until(lambda: _safe(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
                lambda r: r is not None, timeout_s=60, interval_s=2,
                description=f"role {name} inline policy readable")
    return name, arn


def _create_log_group(ctx, td):
    """A log group this check owns outright, so teardown is one call that takes the streams too."""
    logs = ctx.client("logs")
    name = ctx.unique_name(_PREFIX + "lg-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))

    def _drop():
        _swallow(lambda: logs.delete_log_group(logGroupName=name))
        left = _safe(lambda: logs.describe_log_groups(logGroupNamePrefix=name))
        if left and left.get("logGroups"):
            raise AssertionError(f"log group {name} still present after DeleteLogGroup")

    td.add(f"log group {name}", _drop)
    return name


def _create_filesystem(ctx, efs, td):
    """An encrypted general-purpose EFS file system, polled `available`.

    EFS refuses DeleteFileSystem while a mount target exists, and the mount target's ENI blocks the
    subnet delete, so the access point and mount target are registered later and run first (LIFO).
    """
    token = ctx.unique_name("efs-tok-")
    fs_id = efs.create_file_system(
        CreationToken=token, PerformanceMode="generalPurpose", ThroughputMode="bursting",
        Encrypted=True, Tags=_kv_tags() + [{"Key": "Name", "Value": token}])["FileSystemId"]

    def _drop():
        _swallow(lambda: efs.delete_file_system(FileSystemId=fs_id))
        _poll_until(
            lambda: _safe(lambda: efs.describe_file_systems(FileSystemId=fs_id)),
            lambda r: r is None,
            timeout_s=_TEARDOWN_TIMEOUT_S, interval_s=10,
            description=f"EFS file system {fs_id} gone (DescribeFileSystems raises)")

    td.add(f"efs file system {fs_id}", _drop)
    _poll_until(lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0],
                lambda fs: fs.get("LifeCycleState") == "available",
                timeout_s=_MT_TIMEOUT_S, interval_s=5,
                description=f"EFS file system {fs_id} available")
    return fs_id


def _create_mount_target(ctx, efs, td, fs_id, subnet_id, sg_id):
    """The mount target in the task's own subnet, polled `available`."""
    mt_id = efs.create_mount_target(FileSystemId=fs_id, SubnetId=subnet_id,
                                    SecurityGroups=[sg_id])["MountTargetId"]

    def _drop():
        _swallow(lambda: efs.delete_mount_target(MountTargetId=mt_id))
        _poll_until(
            lambda: _safe(lambda: efs.describe_mount_targets(FileSystemId=fs_id)) or {},
            lambda r: not (r or {}).get("MountTargets"),
            timeout_s=_TEARDOWN_TIMEOUT_S, interval_s=10,
            description=f"every mount target of {fs_id} gone before the file system delete")

    td.add(f"efs mount target {mt_id}", _drop)
    _poll_until(
        lambda: efs.describe_mount_targets(MountTargetId=mt_id)["MountTargets"][0],
        lambda mt: mt.get("LifeCycleState") == "available",
        timeout_s=_MT_TIMEOUT_S, interval_s=10,
        description=f"mount target {mt_id} available in {subnet_id}")
    return mt_id


def _create_access_point(ctx, efs, td, fs_id):
    """An access point pinning POSIX identity 1000:1000 and rooting the mount at /data."""
    ap = efs.create_access_point(
        ClientToken=ctx.unique_name("efs-ap-"), FileSystemId=fs_id, Tags=_kv_tags(),
        PosixUser={"Uid": 1000, "Gid": 1000},
        RootDirectory={"Path": "/data",
                       "CreationInfo": {"OwnerUid": 1000, "OwnerGid": 1000,
                                        "Permissions": "0755"}})
    ap_id, ap_arn = ap["AccessPointId"], ap["AccessPointArn"]

    def _drop():
        _swallow(lambda: efs.delete_access_point(AccessPointId=ap_id))
        _poll_until(
            lambda: _safe(lambda: efs.describe_access_points(AccessPointId=ap_id)),
            lambda r: r is None,
            timeout_s=_TEARDOWN_TIMEOUT_S, interval_s=10,
            description=f"access point {ap_id} gone")

    td.add(f"efs access point {ap_id}", _drop)
    _poll_until(lambda: efs.describe_access_points(AccessPointId=ap_id)["AccessPoints"][0],
                lambda a: a.get("LifeCycleState") == "available",
                timeout_s=_MT_TIMEOUT_S, interval_s=5,
                description=f"access point {ap_id} available")
    return ap_id, ap_arn


def _register_td(ctx, ecs, td, fs_id, ap_id, log_group, exec_role, task_role, *, read_only):
    """One task definition mounting the access point at /mnt/shared; only `read_only` differs."""
    family = ctx.unique_name(_PREFIX + ("td-ro-" if read_only else "td-rw-"))
    arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role,
        taskRoleArn=task_role,
        volumes=[{"name": "shared",
                  "efsVolumeConfiguration": {
                      "fileSystemId": fs_id,
                      "transitEncryption": "ENABLED",
                      "authorizationConfig": {"accessPointId": ap_id, "iam": "ENABLED"}}}],
        containerDefinitions=[{
            "name": "app",
            "image": _BUSYBOX,
            "essential": True,
            "mountPoints": [{"sourceVolume": "shared", "containerPath": "/mnt/shared",
                             "readOnly": read_only}],
            "logConfiguration": {"logDriver": "awslogs",
                                 "options": {"awslogs-group": log_group,
                                             "awslogs-region": ctx.region,
                                             "awslogs-stream-prefix": _STREAM_PREFIX}},
        }],
        tags=_ecs_tags())["taskDefinition"]["taskDefinitionArn"]
    td.add(f"ecs task definition {arn}",
           lambda: (_swallow(lambda: ecs.deregister_task_definition(taskDefinition=arn)),
                    _swallow(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))))
    return arn


_STREAM_PREFIX = "efs"


def _run_and_wait(ctx, ecs, td, cluster, task_def, net, log_group, label, command, env=None,
                  retry_s=0.0):
    """RunTask with the command overridden, then poll to STOPPED. Returns the task record.

    `retry_s` > 0 relaunches, until that deadline, only on an EFS mount-setup stoppedReason (the
    mount target's DNS name resolves only inside the VPC, so it cannot be polled) or a role ECS
    cannot yet assume.
    """
    overrides = {"containerOverrides": [{"name": "app", "command": command}]}
    if env:
        overrides["containerOverrides"][0]["environment"] = env
    left = ctx.time_left()
    deadline = time.monotonic() + (retry_s if left is None else min(retry_s, max(0.0, left - 10.0)))
    task = None
    while True:
        try:
            resp = _launch_past_slr_lag(lambda: ecs.run_task(
                cluster=cluster, taskDefinition=task_def, launchType="FARGATE", count=1,
                networkConfiguration=net, overrides=overrides, tags=_ecs_tags()))
        except ClientError as exc:
            message = str(exc.response.get("Error", {}).get("Message", ""))
            if _ROLE_LAG not in message.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(2)
            continue
        assert not resp.get("failures"), (
            f"RunTask for arm {label} reported failures: {resp.get('failures')!r}")
        arn = resp["tasks"][0]["taskArn"]
        td.add(f"ecs task {arn}",
               lambda a=arn: _swallow(lambda: ecs.stop_task(cluster=cluster, task=a,
                                                            reason="behavioral-cleanup")))
        task = _poll_until(
            lambda a=arn: _describe_task(ecs, cluster, a),
            lambda t: t["lastStatus"] == "STOPPED",
            timeout_s=_TASK_TIMEOUT_S, interval_s=10,
            description=f"task {label} ({arn}) reaches STOPPED")
        reason = task.get("stoppedReason") or ""
        if task.get("stopCode") == "TaskFailedToStart" \
                and (_MOUNT_DNS_LAG in reason or _ROLE_LAG in reason.lower()) \
                and time.monotonic() < deadline:
            time.sleep(2)
            continue
        break
    assert task.get("stopCode") != "TaskFailedToStart", (
        f"task {label} never started: stopCode={task.get('stopCode')!r} "
        f"stoppedReason={task.get('stoppedReason')!r} containers={task.get('containers')!r}")
    return task


def _container(task):
    return task["containers"][0]


def _eni(task):
    for att in task.get("attachments") or []:
        for kv in att.get("details") or []:
            if kv.get("name") == "networkInterfaceId":
                return kv.get("value")
    return None


def _stream_lines(ctx, group, task, sentinel):
    """Every line the task's container wrote, waited on until `sentinel` has been DELIVERED.

    Two waits, not one: the awslogs driver opens the stream when the task is INITIALISED,
    measurably before the container writes anything, so the stream existing is no evidence that
    output arrived -- only its events are.
    """
    logs = ctx.client("logs")
    stream = f"{_STREAM_PREFIX}/app/{task['taskArn'].rsplit('/', 1)[-1]}"

    def _read():
        out, token, seen = [], None, set()
        while True:
            kwargs = dict(logGroupName=group, logStreamName=stream, startFromHead=True)
            if token:
                kwargs["nextToken"] = token
            resp = _safe(lambda kw=dict(kwargs): logs.get_log_events(**kw))
            if resp is None:
                return out
            out.extend(e.get("message", "") for e in resp.get("events", []))
            token = resp.get("nextForwardToken")
            if not token or token in seen:
                return out
            seen.add(token)

    return _poll_until(_read, lambda msgs: any(sentinel in m for m in msgs),
                       timeout_s=_LOG_TIMEOUT_S, interval_s=5,
                       description=f"{sentinel!r} delivered to {group}/{stream}")


def _drop_cluster(ecs, cluster):
    _swallow(lambda: _drain_and_delete_ecs_cluster(ecs, cluster))
    left = _safe(lambda: ecs.describe_clusters(clusters=[cluster]))
    for c in (left or {}).get("clusters", []):
        if c.get("status") not in ("INACTIVE", None):
            raise AssertionError(f"ECS cluster {cluster} still {c.get('status')!r} after "
                                 f"DeleteCluster")


def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services, tasks or container instances remain, and a task's
    ENI stays in the shared network until the task has stopped, which keeps the network from
    being deleted.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s

    def arns(op, key, **kw):
        return [a for page in ecs.get_paginator(op).paginate(cluster=cluster, **kw) for a in page.get(key, [])]

    try:
        services = arns("list_services", "serviceArns")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ClusterNotFoundException":
            return
        raise
    for service in services:
        for call in (
            lambda s=service: ecs.update_service(cluster=cluster, service=s, desiredCount=0),
            lambda s=service: ecs.delete_service(cluster=cluster, service=s, force=True),
        ):
            try:
                call()
            except ClientError:
                pass
    while True:
        for task in arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            try:
                ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
            except ClientError:
                pass
        stopping = arns("list_tasks", "taskArns", desiredStatus="STOPPED")
        live = []
        for i in range(0, len(stopping), 100):
            live += [t for t in ecs.describe_tasks(cluster=cluster, tasks=stopping[i:i + 100])["tasks"]
                     if t.get("lastStatus") != "STOPPED"]
        if not live and not arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{len(live)} task(s) in {cluster} still not STOPPED after {timeout_s:.0f}s")
        time.sleep(interval_s)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code == "ClusterContainsContainerInstancesException":
                for instance in arns("list_container_instances", "containerInstanceArns"):
                    try:
                        ecs.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
                    except ClientError:
                        pass
            elif code not in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "UpdateInProgressException",
                "ResourceInUseException",
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _describe_task(ecs, cluster, task_arn, timeout_s=60.0):
    """DescribeTasks for one task, retrying while ECS does not list it yet.

    Right after RunTask, DescribeTasks can briefly answer with the task under `failures`
    (reason MISSING) instead of `tasks`.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        tasks = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"]
        if tasks:
            return tasks[0]
        if time.monotonic() >= deadline:
            raise AssertionError(f"DescribeTasks never listed task {task_arn} within {timeout_s}s")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
